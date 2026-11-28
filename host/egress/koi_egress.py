"""koi egress policy for preview containers (mitmproxy addon).

Previews have no route to the internet. Their HTTP(S)_PROXY points here, and
this addon decides what they may reach: allowlisted hostnames only, on 443
(CONNECT) or 80 (plain HTTP).

The CONNECT hostname alone proves little: sites behind one CDN answer for each
other, so a tunnel opened to pypi.org could carry TLS and HTTP for any other
site on that CDN. So the proxy intercepts TLS in every tunnel (previews trust
koi's CA through SSL_CERT_FILE and friends) and holds three names to the one
the CONNECT gave: the TLS server name (SNI), which must match or the handshake
fails, and the Host header and :authority of every request inside, which must
match or the connection is killed. The upstream connection is opened only for
a request that passed, and only with the CONNECT host as its server name.

Some code ignores a proxy setting on purpose. RocketRide's web nodes resolve
a URL's host themselves, refuse private addresses and connect to the address
they checked. For them the box gives each preview a default route to its
bridge, and the box's firewall sends a preview's new connections to ports 443
and 80 to this proxy's transparent listener (install.sh, host/cloud-init.sh);
Docker drops everything else. The address the preview connected to proves
nothing, so the policy never uses it. Over TLS, the server name is the one
name such a connection is for, held to the requests inside as a CONNECT host
is; in plain HTTP, each request's Host header is. The upstream connection
opens to that name, under the same checks as a proxied request.

Previews resolve names through this policy's own DNS server (koi_dns, UDP):
allowed names only,
IPv4 addresses only (previews have no IPv6 route, and the firewall redirects
IPv4), and public ones only. A name the policy would refuse is not looked up
at all, so the listener looks up no name the proxy would not look up itself
for a CONNECT.

koi_fixtures names a host this proxy answers itself with test pages
(redirects, status codes, delays, large bodies; see fixture_response), so a
preview can check how its code fetches the web. Nothing for it goes upstream.

Bodies stream through: the proxy never holds a whole upload or download, and
a refused request with a body is cut off at its headers, so the body is never
read. WebSockets and other upgraded connections stream through as bytes. The service's own memory ceiling (install.sh) bounds what is left.

The proxy forwards nothing unless this addon is loaded and set up. The service
starts mitmproxy with its server off (server=false), and only this addon turns
it on, once it has read its allowlist. When the addon goes away, because
mitmproxy reloads this file after it changed, it turns the server off and
closes every open connection first. So a file that fails to load leaves the
proxy down, never open.

On requests to LLM provider APIs, a koi token in the request is swapped for
the reviewer's real key on the way out. The preview's code only ever holds the
token; the real key exists in the reviewer's browser and in this process's
memory, nowhere else. Keys are registered by koid over a unix socket (the keys
page talks to koid, koid talks to this socket), and for each key this proxy
derives a token that stands for that key, its provider and one preview: an
HMAC of the three under a secret kept on the box (see derive_token), so the
same key registered again for the same preview gets the same token, after a
reload, a restart or a sleep. koid also tells it which container address
runs which preview, and a token works only in requests from its own
preview's container. Nothing here writes a key, a token or the secret to
disk or to a log. Tokens, keys and the container map live in this addon's
instance: when the addon is unloaded, its control socket closes with it, and
a reload starts with none, until the keys page registers its keys again.

The secret is 32 bytes in a file only the proxy's user can read, mode 0400
in a directory only root can write (install.sh makes it once). Without it,
or with one of the wrong size, owner or mode, the policy does not start
and the proxy stays down. Deleting the file invalidates every token: the
next registration of each key gets a new one.

Log lines never carry text a preview chose, such as a hostname: it can hold a
key or a koi token.
"""

import asyncio
import base64
import concurrent.futures
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import socket
import stat
import struct
import time
import weakref
from urllib.parse import parse_qs, quote, quote_plus, urlsplit

from mitmproxy import connection, ctx, dns, http, tcp, tls
from mitmproxy.net.http import url
from mitmproxy.proxy import mode_specs
from OpenSSL import SSL

log = logging.getLogger("koi_egress")

ALLOWED_PORTS = {443, 80}

# mitmproxy settings the checks below rely on. The addon sets them itself, so
# a different command line cannot loosen them.
OPTIONS = {
    # Connect upstream only for a request that passed the checks, never for a
    # bare CONNECT or before the client's TLS handshake.
    "connection_strategy": "lazy",
    # Raw relay, which mitmproxy needs to pass an upgraded connection (a
    # WebSocket) on as bytes; see websocket below. tcp_start refuses every
    # other raw relay, such as a tunnel whose bytes look like neither TLS nor
    # HTTP (or a ClientHello split before its third byte), and server_connect
    # then gives it no upstream connection.
    "rawtcp": True,
    # The addon streams every body itself (requestheaders, responseheaders).
    # This catches any it leaves buffered: past 64 KiB, mitmproxy streams it
    # too, so no body held in memory grows beyond that. mitmproxy's
    # body_size_limit is not set: it also cuts off streamed bodies, such as
    # model weights of several GB.
    "stream_large_bodies": "64k",
    # mitmproxy would take WebSocket frames apart, put each message together
    # in memory and keep every one on the flow. Off, an upgraded connection
    # (101 Switching Protocols, after its request passed the checks) is
    # relayed as bytes over the upstream connection already open to the
    # checked host, as they arrive; tcp_message keeps nothing of them.
    "websocket": False,
    # Hosts mitmproxy would relay without any of the hooks below. None.
    "ignore_hosts": [],
    "allow_hosts": [],
}


def same(value):
    """An option's value in a form that compares equal however it is stored."""
    return tuple(value) if isinstance(value, (list, tuple)) else value


# host -> provider id. Every provider here is also allowlisted.
PROVIDERS = {
    "api.openai.com": "openai",
    "api.anthropic.com": "anthropic",
    "generativelanguage.googleapis.com": "gemini",
    "api.mistral.ai": "mistral",
    "api.groq.com": "groq",
    "api.together.xyz": "together",
    "api.cohere.com": "cohere",
    "api.deepseek.com": "deepseek",
    "api.x.ai": "xai",
    "openrouter.ai": "openrouter",
    "api.perplexity.ai": "perplexity",
}

# Where each provider's API takes its key, as its documentation says: the
# headers that carry it (Authorization as "Bearer <key>", any other header as
# the key alone) and, for a provider whose API also reads it from the URL, the
# query parameter and the API paths that read it. A token is swapped in these
# places only, and only when it is the whole credential there.
BEARER = ("authorization",)
AUTH = {
    "openai": {"headers": BEARER},
    "anthropic": {"headers": ("x-api-key",)},
    "gemini": {
        "headers": ("x-goog-api-key",),
        "query": "key",
        "paths": ("/v1/", "/v1beta/", "/v1alpha/", "/upload/v1/", "/upload/v1beta/"),
    },
    "mistral": {"headers": BEARER},
    "groq": {"headers": BEARER},
    "together": {"headers": BEARER},
    "cohere": {"headers": BEARER},
    "deepseek": {"headers": BEARER},
    "xai": {"headers": BEARER},
    "openrouter": {"headers": BEARER},
    "perplexity": {"headers": BEARER},
}

TOKEN_RE = re.compile(r"koi_[a-z0-9]{32}")
# Some apps check a key's prefix before they send anything, and refuse one
# that does not begin the way the provider's keys do: "sk-ant" for
# Anthropic, "sk-" for DeepSeek, "xai-" for xAI. So the keys page shows each
# token after its provider's prefix, and a token here may come with any of
# them; key_for still checks that it is the provider's own. Matches
# TOKEN_PREFIXES in packages/shared/src/providers.ts.
TOKEN_PREFIXES = {"openai": "sk-", "anthropic": "sk-ant-", "deepseek": "sk-", "xai": "xai-"}
_PREFIX = "|".join(re.escape(p) for p in sorted(set(TOKEN_PREFIXES.values()), key=len, reverse=True))
PASTED_RE = re.compile(rf"(?:{_PREFIX})?(koi_[a-z0-9]{{32}})")
BEARER_RE = re.compile(rf"Bearer +(?:{_PREFIX})?(koi_[a-z0-9]{{32}})", re.IGNORECASE)
# The token secret: this many random bytes in a file (koi_secret). A token
# is the first TOKEN_BYTES of an HMAC-SHA256 under it, in lowercase base32
# (a-z and 2-7): 20 bytes, 160 bits, are 32 characters with no padding, so
# a token matches TOKEN_RE like the random ones before it did. The domain
# string starts the HMAC's message, so no other use of the secret can make
# a token.
SECRET_BYTES = 32
SECRET_PATH = "/etc/koi/egress/private/token-secret"
TOKEN_BYTES = 20
TOKEN_DOMAIN = b"koi token v1"
# A preview's label, as packages/shared checks it (PreviewLabelSchema).
LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
REQUESTS_PER_HOUR = 600
REGISTRATION_TTL_SECONDS = 24 * 3600
# Tokens held at once, in all and from one source (the address koid saw the
# registration come from), and how often expired ones are removed. One
# registration makes a token per provider key in it.
MAX_TOKENS = 5000
MAX_TOKENS_PER_SOURCE = 200
SWEEP_SECONDS = 600
# Container addresses koid may map to previews at once.
MAX_PREVIEWS = 1000
# DNS lookups in flight at once, in all and for one preview, and how long a
# client may keep an answer.
MAX_LOOKUPS = 64
MAX_LOOKUPS_PER_SOURCE = 8
DNS_TTL = 60
# The threads previews' lookups run on, apart from the ones mitmproxy
# resolves upstream hosts on, so slow lookups cannot hold up the proxy. The
# largest query taken (a plain one with EDNS is under 100 bytes) and the
# header's length.
DNS_WORKERS = 4
MAX_DNS_QUERY = 512
DNS_HEADER = 12
# What the fixtures host serves at most: a delay of this many seconds, a
# chain of this many redirects, a Location this long. Every page is small:
# mitmproxy holds a response this addon makes whole until the client reads
# it, so no page offers a large body.
FIXTURE_MAX_DELAY = 10
FIXTURE_MAX_REDIRECTS = 20
FIXTURE_MAX_LOCATION = 2048
FIXTURE_MAX_ECHO = 8 * 1024
REDIRECT_CODES = (301, 302, 303, 307, 308)
HOSTNAME_RE = re.compile(r"(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+")
FIXTURE_HTML = b"""<!doctype html>
<html><head><title>koi fixtures</title></head>
<body>
<h1>koi fixtures</h1>
<p>Test pages for previews. Nothing here reaches the internet.</p>
<ul>
<li><a href="/status/404">/status/CODE</a>: that status</li>
<li><a href="/redirect/3">/redirect/N</a>: N redirects, then a page</li>
<li><a href="/redirect-to?url=http://example.com:99999/">/redirect-to?url=URL&amp;status_code=3XX</a>: one redirect to URL, whatever it is</li>
<li><a href="/delay/2">/delay/SECONDS</a>: a page after up to 10 seconds</li>
<li><a href="/json">/json</a>, <a href="/headers">/headers</a>: JSON, and the request's own headers, up to 8 KiB</li>
</ul>
</body></html>
"""


def load_allowlist(path):
    exact, suffixes = set(), set()
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.split("#", 1)[0].strip().lower()
            if not line:
                continue
            if line.startswith("*."):
                suffixes.add(line[1:])  # ".example.com"
            else:
                exact.add(line)
    return exact, suffixes


def clean(host):
    return (host or "").lower().rstrip(".")


def peer(client):
    """The client's IP address: the preview container's, set by Docker."""
    return client.peername[0] if client.peername else "unknown"


def authorities(request):
    """Every name a request gives for its host: Host headers, and the :authority or absolute-form target."""
    names = list(request.headers.get_all("host"))
    if request.authority:
        names.append(request.authority)
    return names


def has_body(request):
    """True if the request's headers say a body follows them (HTTP/1 rules)."""
    length = request.headers.get("content-length", "0").strip()
    return "transfer-encoding" in request.headers or length != "0"


def cut(flow):
    """Kill a flow and close its client's connection now, leaving the rest unread.

    flow.kill() alone does not close the socket in mitmproxy 12.2.3: it
    cancels the connection's reader task, and if that task is waiting for
    mitmproxy's event lock, as it is while a client keeps sending a body, the
    task ends without closing the socket. The client then hangs on a socket
    nobody reads. So this also closes the socket, through mitmproxy's proxy
    server; if that ever changes shape, the kill still refuses the request.
    """
    flow.kill()
    close(flow.client_conn)


def close(client):
    """Close a client's socket now, through mitmproxy's proxy server (see cut)."""
    server = ctx.master.addons.get("proxyserver")
    handler = server.connections.get(client.id) if server else None
    io = getattr(handler, "transports", {}).get(client)
    if getattr(io, "writer", None) is not None:
        io.writer.close()


def names_only(names, host, port):
    """True if there is at least one name and each is host or host:port."""
    if not names:
        return False
    for name in names:
        try:
            h, p = url.parse_authority(name, check=True)
        except ValueError:
            return False
        if clean(h) != host or p not in (None, port):
            return False
    return True


def field(value):
    """A string as HMAC input: its UTF-8 bytes behind their length, so fields cannot run into each other."""
    data = value.encode()
    return struct.pack(">I", len(data)) + data


def derive_token(secret, provider, label, key):
    """The koi token for key, registered for provider in the preview label.

    HMAC-SHA256 under the secret of TOKEN_DOMAIN and the three fields, each
    length-prefixed, cut to TOKEN_BYTES and written in lowercase base32. The
    same inputs give the same token; a change in any one, or in the secret,
    gives an unrelated one; and a token gives away nothing about the key
    without the secret.
    """
    if not isinstance(secret, bytes) or len(secret) != SECRET_BYTES:
        raise ValueError("the key proxy has no token secret")
    message = TOKEN_DOMAIN + field(provider) + field(label) + field(key)
    digest = hmac.new(secret, message, hashlib.sha256).digest()
    return "koi_" + base64.b32encode(digest[:TOKEN_BYTES]).decode().lower()


def load_secret(path):
    """The SECRET_BYTES bytes of the token secret at path.

    ValueError (or OSError) unless the file is a regular file, not a
    symlink, owned by this process's user, of mode 0400 (install.sh keeps
    it in a directory only root can write, so not even this process can
    replace or change it), and exactly SECRET_BYTES long. The open never
    follows a symlink and never waits (a FIFO would hang it): what was
    opened is checked before anything is read. The message names the path
    and the problem, never the contents.
    """
    if not path:
        raise ValueError("no token secret file is set (koi_secret)")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"the token secret {path} is not a regular file")
        if st.st_uid != os.geteuid():
            raise ValueError(f"the token secret {path} is not owned by the proxy's user")
        mode = stat.S_IMODE(st.st_mode)
        if mode != 0o400:
            raise ValueError(f"the token secret {path} is mode {mode:04o}, not 0400")
        data = os.read(fd, SECRET_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) != SECRET_BYTES:
        raise ValueError(f"the token secret {path} is not {SECRET_BYTES} bytes")
    return data


def address(text):
    """An IP address in one spelling: an IPv4 address written as IPv6 becomes the IPv4 one. ValueError if not one."""
    ip = ipaddress.ip_address(text)
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return str(ip)


def transparent(client):
    """True if the box's firewall redirected this connection here, rather than the preview asking the proxy."""
    return isinstance(client.proxy_mode, mode_specs.TransparentMode)


def public(packed):
    """True if an A record's address is one on the internet: global and not multicast."""
    if len(packed) != 4:
        return False
    ip = ipaddress.IPv4Address(packed)
    return ip.is_global and not ip.is_multicast


def plain_query(data):
    """True if data is a small DNS query and nothing more, checked before anything parses it.

    One question, its name in plain labels (no compression pointer), and at
    most one more record, which must be EDNS's OPT: the root name, type 41,
    and data that ends the message.
    """
    if not DNS_HEADER <= len(data) <= MAX_DNS_QUERY:
        return False
    _, flags, questions, answers, authorities, additionals = struct.unpack(">HHHHHH", data[:DNS_HEADER])
    if flags & 0xF800 or questions != 1 or answers or authorities or additionals > 1:
        return False
    i = DNS_HEADER
    while True:
        if i >= len(data) or data[i] > 63:
            return False
        if data[i] == 0:
            i += 1
            break
        i += 1 + data[i]
    i += 4  # the question's type and class
    if not additionals:
        return i == len(data)
    if len(data) < i + 11 or data[i] != 0 or data[i + 1 : i + 3] != b"\x00\x29":
        return False
    return i + 11 + int.from_bytes(data[i + 9 : i + 11], "big") == len(data)


def page(status, body, content_type="text/plain", **headers):
    return http.Response.make(status, body, {"content-type": content_type, "cache-control": "no-store", **headers})


async def fixture_response(request):
    """The fixtures host's answer to a GET or HEAD request (see FIXTURE_HTML for what it serves), a few KiB at most.

    It answers from what the path asks for only, within the FIXTURE_MAX
    limits, and quotes the request back to the one preview that sent it on
    /headers alone.
    """
    parts = urlsplit(request.path)
    words = [w for w in parts.path.split("/") if w]
    head, arg = (words + ["", ""])[:2]
    number = arg if len(words) == 2 and arg.isdigit() and len(arg) <= 9 else None
    if not words:
        return page(200, FIXTURE_HTML, "text/html; charset=utf-8")
    if head == "status" and number is not None and 200 <= int(number) <= 599:
        code = int(number)
        if code in (204, 304):
            # No body and no Content-Length: a client reads none.
            response = page(code, b"")
            del response.headers["content-length"]
            return response
        extra = {"location": "/"} if 300 <= code < 400 else {}
        return page(code, f"status {code}\n".encode(), **extra)
    if head == "redirect" and number is not None and int(number) <= FIXTURE_MAX_REDIRECTS:
        n = int(number)
        if n == 0:
            return page(200, b"redirects done\n")
        return page(302, b"", location=f"/redirect/{n - 1}")
    if head == "redirect-to" and len(words) == 1:
        query = parse_qs(parts.query, keep_blank_values=True)
        target = (query.get("url") or [""])[0]
        code = (query.get("status_code") or ["302"])[0]
        if not target or len(target) > FIXTURE_MAX_LOCATION or any(not 0x21 <= ord(c) <= 0x7E for c in target):
            return page(400, b"redirect-to needs url=, printable ASCII without spaces, up to 2048 characters\n")
        if not code.isdigit() or int(code) not in REDIRECT_CODES:
            return page(400, b"status_code must be 301, 302, 303, 307 or 308\n")
        return page(int(code), b"", location=target)
    if head == "delay" and len(words) == 2:
        try:
            seconds = float(arg)
        except ValueError:
            seconds = -1.0
        if not 0 <= seconds <= FIXTURE_MAX_DELAY:
            return page(400, f"delay takes 0 to {FIXTURE_MAX_DELAY} seconds\n".encode())
        await asyncio.sleep(seconds)
        return page(200, f"delayed {seconds:g} seconds\n".encode())
    if head == "json" and len(words) == 1:
        return page(200, b'{"fixture": "koi", "ok": true}\n', "application/json")
    if head == "headers" and len(words) == 1:
        # Counted as they are taken, so a request with huge headers costs no
        # more than the budget to refuse; JSON escaping is checked at the end.
        sent, size = [], 0
        for name, value in request.headers.items(multi=True):
            size += len(name) + len(value)
            if size > FIXTURE_MAX_ECHO:
                return page(431, b"too many request headers to echo\n")
            sent.append([name, value])
        body = (json.dumps({"headers": sent}) + "\n").encode()
        if len(body) > FIXTURE_MAX_ECHO:
            return page(431, b"too many request headers to echo\n")
        return page(200, body, "application/json")
    return page(404, b"no such fixture; see /\n")


def token_in(header, value):
    """The koi token that is the whole credential in a provider auth header's value, prefix and all, or None."""
    if value is None:
        return None
    if header == "authorization":
        match = BEARER_RE.fullmatch(value)
        return match.group(1) if match else None
    match = PASTED_RE.fullmatch(value)
    return match.group(1) if match else None


def verified(flow, tunnel, host):
    """True if the request is HTTPS on port 443 to host and to nothing else.

    Every name for where it goes must be host: the CONNECT that opened the
    tunnel, the TLS server name, the URL, and each Host and :authority. A key
    is swapped into nothing less, so it never travels in plain text, or to
    an address another name could lead to.
    """
    request, client = flow.request, flow.client_conn
    return (
        tunnel == host
        and client.tls
        and clean(client.sni) == host
        and request.scheme == "https"
        and request.port == 443
        and names_only(authorities(request), host, 443)
    )


def carries_token(request):
    """True if a koi token appears in the request's URL or any header."""
    return TOKEN_RE.search(request.url) is not None or any(
        TOKEN_RE.search(value) for _, value in request.headers.items(multi=True)
    )


def secret_forms(swapped):
    """(secret, token) byte pairs to replace in responses: each key as it is and URL-encoded, longest first."""
    pairs = {}
    for key, token in swapped:
        for form in (key, quote(key, safe=""), quote_plus(key)):
            pairs[form.encode()] = token.encode()
    return sorted(pairs.items(), key=lambda pair: -len(pair[0]))


def scrub(data, pairs):
    for secret, token in pairs:
        data = data.replace(secret, token)
    return data


def held_back(data, secrets):
    """How many bytes at the end of data could be the start of a secret: the longest such tail, often 0."""
    longest = 0
    for secret in secrets:
        # Only a tail shorter than the secret: scrub replaced whole ones.
        start = max(0, len(data) - len(secret) + 1)
        i = data.find(secret[:1], start)
        while i != -1:
            if secret.startswith(data[i:]):
                # The leftmost match is the longest tail for this secret.
                longest = max(longest, len(data) - i)
                break
            i = data.find(secret[:1], i + 1)
    return longest


class Scrubber:
    """A response body stream that replaces each key with its token.

    A key may be split between two chunks, so the end of a chunk that could
    be the start of a key is held back until the next chunk, or the end of
    the body, shows whether it is one. Only that tail waits: a chunk that
    ends any other way, such as a server-sent event, goes on whole at once.
    mitmproxy calls this with b"" at the end. It returns lists, never an
    empty chunk, which HTTP/1 chunked encoding would take for the end.
    """

    def __init__(self, pairs):
        self.pairs = pairs
        self.secrets = [secret for secret, _ in pairs]
        self.held = b""

    def __call__(self, chunk):
        data = scrub(self.held + chunk, self.pairs)
        if not chunk:
            self.held = b""
            return [data] if data else []
        split = len(data) - held_back(data, self.secrets)
        self.held = data[split:]
        return [data[:split]] if split else []


class Registry:
    """Tokens and the keys behind them, in memory only.

    A token stands for one key, for one provider, for one preview (its
    label). The registry derives every token itself from those three and
    the secret (derive_token), and never takes one from a caller, so
    knowing a token lets nobody bind it to another key, provider or
    preview. Registering a key again for the same provider and preview
    gives the same token and renews its registration.

    The registry holds at most MAX_TOKENS tokens, and at most
    MAX_TOKENS_PER_SOURCE from one source, so registrations cannot grow the
    proxy's memory without bound. While it holds any, a timer on the event
    loop removes expired ones every sweep_seconds, so they go even if nobody
    uses them again.
    """

    def __init__(self, secret=None, clock=time.monotonic, sweep_seconds=SWEEP_SECONDS):
        self.secret = secret
        self.clock = clock
        self.sweep_seconds = sweep_seconds
        self.sweeper = None  # the next sweep's asyncio.TimerHandle, while one is due
        # token -> {"provider": p, "key": k, "label": l, "source": s, "expires": t, "window": t, "count": n}
        self.entries = {}

    def register(self, label, keys, source=""):
        """Register each key, bound to its provider and the preview; returns {provider: token}.

        A key already registered for that provider and preview keeps its
        token and its request count for the hour; its registration starts
        again from now, with this source.
        """
        if not isinstance(label, str) or not LABEL_RE.fullmatch(label):
            raise ValueError("bad preview label")
        if source is None:
            source = ""
        if not isinstance(source, str) or len(source) > 64:
            raise ValueError("bad source")
        if not isinstance(keys, dict) or not keys:
            raise ValueError("no keys")
        tokens = {}
        for provider, key in keys.items():
            if provider not in PROVIDERS.values():
                raise ValueError(f"unknown provider {provider}")
            if not isinstance(key, str) or not key or len(key) > 512 or any(c in key for c in "\r\n"):
                raise ValueError(f"bad key for {provider}")
            tokens[provider] = derive_token(self.secret, provider, label, key)
        self.sweep()
        new = [t for t in tokens.values() if t not in self.entries]
        if len(self.entries) + len(new) > MAX_TOKENS:
            raise ValueError("the key proxy holds as many koi tokens as it can; try again later")
        # A token registered again from another address moves to this one,
        # and counts here from now on; one registered again from the same
        # address is free.
        moving = [t for t in tokens.values() if t in self.entries and self.entries[t]["source"] != source]
        if self.held_by(source) + len(new) + len(moving) > MAX_TOKENS_PER_SOURCE:
            raise ValueError("too many koi tokens are registered from this address")
        now = self.clock()
        for provider, token in tokens.items():
            entry = self.entries.setdefault(token, {"window": now, "count": 0})
            entry.update(
                provider=provider,
                key=keys[provider],
                label=label,
                source=source,
                expires=now + REGISTRATION_TTL_SECONDS,
            )
        self.schedule_sweep()
        return tokens

    def held_by(self, source):
        return sum(1 for entry in self.entries.values() if entry["source"] == source)

    def sweep(self):
        """Removes expired tokens."""
        now = self.clock()
        for token in [t for t, entry in self.entries.items() if entry["expires"] < now]:
            del self.entries[token]

    def schedule_sweep(self):
        """Sets the timer for the next sweep, if tokens are held and none is due.

        Registrations arrive on mitmproxy's event loop. Without a running loop
        (a test calling register directly) there is no timer, and only
        register sweeps.
        """
        if self.sweeper is not None or not self.entries:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        self.sweeper = loop.call_later(self.sweep_seconds, self.timed_sweep)

    def timed_sweep(self):
        self.sweeper = None
        self.sweep()
        self.schedule_sweep()

    def forget(self, token):
        if isinstance(token, str):
            self.entries.pop(token, None)

    def clear(self):
        """Drops every key and the secret, and stops the sweep timer, which would keep this registry alive."""
        if self.sweeper is not None:
            self.sweeper.cancel()
            self.sweeper = None
        self.entries.clear()
        self.secret = None

    def key_for(self, token, provider, label):
        """(key, None) or (None, reason), for a request to provider from preview label (None: not a known preview)."""
        entry = self.entries.get(token)
        now = self.clock()
        if entry is None or entry["expires"] < now:
            self.entries.pop(token, None)
            return None, (
                "this koi token is not registered on the box; open the keys page from the pull request's "
                "preview comment, which registers your keys again with the same tokens"
            )
        if label is None or entry["label"] != label:
            return None, "this koi token is for another preview"
        if entry["provider"] != provider:
            return None, f"this koi token is for {entry['provider']}, not {provider}"
        if now - entry["window"] >= 3600:
            entry["window"], entry["count"] = now, 0
        if entry["count"] >= REQUESTS_PER_HOUR:
            return None, f"this koi token has made {REQUESTS_PER_HOUR} requests this hour; try again later"
        entry["count"] += 1
        return entry["key"], None


class DnsServer(asyncio.DatagramProtocol):
    """The previews' DNS server: one query in, one answer out, and nothing kept once it is sent."""

    def __init__(self, policy):
        self.policy = policy
        self.transport = None
        self.pending = set()  # the answers being worked out, so none is collected before it is sent

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        task = asyncio.get_running_loop().create_task(self.answer(data, addr))
        self.pending.add(task)
        task.add_done_callback(self.pending.discard)

    async def answer(self, data, addr):
        try:
            reply = await self.policy.dns_answer(data, addr[0])
        except (ValueError, struct.error, IndexError, OverflowError):
            # A question mitmproxy could read but not write back. Its text
            # stays out of the log.
            log.warning("koi egress could not answer a name lookup from %s", addr[0])
            return
        if reply is not None and self.transport is not None and not self.transport.is_closing():
            self.transport.sendto(reply, addr)


class KoiEgress:
    def __init__(self, registry=None):
        self.exact = set()
        self.suffixes = set()
        self.registry = registry or Registry()
        # Flow -> the (secret, token) pairs to scrub from its response, for
        # each flow a key was swapped into. Weak, so a flow that ends without
        # a response or error hook takes its pairs with it.
        self.substituted = weakref.WeakKeyDictionary()
        # The control socket's server (an asyncio task until it is serving)
        # and its listening socket, while the addon is loaded.
        self.server = None
        self.control_sock = None
        # Client connection id -> the host its CONNECT named. A connection
        # carries at most one tunnel; everything after the CONNECT is inside it.
        self.tunnels = {}
        # Client connection ids refused mid-way; nothing more passes on them.
        self.refused = set()
        # Container address -> the label of the preview it runs, as koid
        # last said (op "previews"). A token works only from its preview.
        self.previews = {}
        # Client connection ids whose checked request was upgraded (101): the
        # only connections relayed as raw bytes.
        self.upgraded = set()
        # Whether configure has read the allowlist; until then running()
        # leaves mitmproxy's server off.
        self.ready = False
        # The host this proxy answers itself with test pages (koi_fixtures),
        # or "" for none; and the flows for it whose answer is due.
        self.fixtures = ""
        self.fixture_flows = weakref.WeakSet()
        # The DNS server's task and UDP socket while it serves (koi_dns), and
        # its lookups in flight per preview address.
        self.dns_server = None
        self.dns_sock = None
        self.dns_pool = None
        self.lookups = {}

    def load(self, loader):
        loader.add_option("koi_allow", str, "/etc/koi/egress/allow.txt", "allowlist file")
        loader.add_option("koi_fixtures", str, "", "host this proxy answers itself with test pages (empty: none)")
        loader.add_option("koi_dns", str, "", "host:port the previews' DNS server listens on, over UDP (empty: none)")
        loader.add_option("koi_control", str, "", "unix socket for token registration (empty: off)")
        # The default is where install.sh puts it, so a running mitmdump that
        # loads this file again finds the secret before the service restarts
        # with the option set.
        loader.add_option("koi_secret", str, SECRET_PATH, "file holding the token secret (see load_secret)")

    def configure(self, updated):
        wrong = {
            k: v
            for k, v in OPTIONS.items()
            if k in updated and k in ctx.options and same(getattr(ctx.options, k)) != same(v)
        }
        if wrong:
            ctx.options.update(**wrong)
        if "koi_allow" in updated:
            self.exact, self.suffixes = load_allowlist(ctx.options.koi_allow)
            self.exact |= set(PROVIDERS)
            log.info("koi egress: %d hosts, %d suffixes", len(self.exact), len(self.suffixes))
            self.ready = True
        if "koi_fixtures" in updated:
            name = clean(ctx.options.koi_fixtures)
            self.fixtures = name if HOSTNAME_RE.fullmatch(name) else ""
            if name and not self.fixtures:
                log.error("koi egress: koi_fixtures is not a hostname; no fixtures host")
        if "koi_secret" in updated:
            # A secret that cannot be used leaves the registry without one,
            # and running() then keeps the proxy down. The log names the
            # file and what is wrong with it, never what is in it.
            self.registry.secret = None
            try:
                self.registry.secret = load_secret(ctx.options.koi_secret)
            except (OSError, ValueError) as e:
                log.error("koi egress: no usable token secret (%s); the proxy stays down", e)

    def running(self):
        # mitmproxy calls this once the file has loaded and configure has run,
        # at start and after each reload (synchronously, so this is not
        # async). Only now does the proxy listen, and only once the control
        # socket is bound, so a setup that fails leaves it down.
        if not self.ready or self.registry.secret is None:
            log.error("koi egress: policy not set up; the proxy stays down")
            return
        path = ctx.options.koi_control
        if path:
            self.listen_control(path)
        if ctx.options.koi_dns:
            self.listen_dns(ctx.options.koi_dns)
        ctx.options.update(server=True)
        log.info("koi egress: policy active, proxy listening")

    def listen_control(self, path):
        """Bind the control socket now, and serve it on the event loop."""
        if os.path.exists(path):
            os.unlink(path)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(path)
        os.chmod(path, 0o660)
        sock.listen()
        self.server = asyncio.get_running_loop().create_task(
            asyncio.start_unix_server(self.handle_control, sock=sock)
        )
        self.control_sock = sock
        log.info("koi egress control on %s", path)

    def close_control(self):
        """Stop taking registrations: the control socket goes with this addon."""
        task, self.server = self.server, None
        if task is None:
            return
        if task.done() and not task.cancelled() and task.exception() is None:
            task.result().close()
        else:
            task.cancel()
        self.control_sock.close()

    def done(self):
        # mitmproxy is unloading this addon: it is shutting down, or about to
        # load this file again after it changed. The control socket closes
        # with it, so no registration reaches an addon that no longer swaps,
        # and so does the DNS server. Then stop listening and close every open
        # connection, which would otherwise carry on with no policy. If the
        # new file fails to load, the proxy stays down.
        self.close_control()
        self.close_dns()
        # The keys and the secret go with it. A new load starts with an
        # empty registry, so a Forget could never reach these copies.
        self.registry.clear()
        if ctx.master.should_exit.is_set():
            return
        ctx.options.update(server=False)
        server = ctx.master.addons.get("proxyserver")
        for handler in list(getattr(server, "connections", {}).values()):
            close(handler.client)
        log.warning("koi egress: policy unloaded; the proxy is down until it loads again")

    async def handle_control(self, reader, writer):
        """One JSON request per line, one JSON reply.

        {"op": "register", "label": ..., "keys": {provider: key}, "source": ...}
            -> {"ok": true, "tokens": {provider: token}}, the token each key
            has in that preview (the same one each time it is registered)
        {"op": "forget", "token": ...} -> {"ok": true}
        {"op": "previews", "previews": {address: label}} -> {"ok": true}, every
            preview container's address, replacing what koid said before
        Anything refused -> {"ok": false, "error": ...}
        """
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=10)
            request = json.loads(line or b"{}")
            if not isinstance(request, dict):
                raise ValueError("expected a JSON object")
            op = request.get("op")
            if op == "register":
                tokens = self.registry.register(request.get("label"), request.get("keys"), request.get("source"))
                reply = {"ok": True, "tokens": tokens}
            elif op == "forget":
                self.registry.forget(request.get("token"))
                reply = {"ok": True}
            elif op == "previews":
                self.set_previews(request.get("previews"))
                reply = {"ok": True}
            else:
                reply = {"ok": False, "error": "unknown op"}
        except (ValueError, asyncio.TimeoutError) as e:
            reply = {"ok": False, "error": str(e)}
        writer.write((json.dumps(reply) + "\n").encode())
        await writer.drain()
        writer.close()

    def set_previews(self, previews):
        if not isinstance(previews, dict) or len(previews) > MAX_PREVIEWS:
            raise ValueError(f"expected at most {MAX_PREVIEWS} addresses and labels")
        mapping = {}
        for ip, label in previews.items():
            if not isinstance(ip, str) or not isinstance(label, str) or not LABEL_RE.fullmatch(label):
                raise ValueError("bad preview address or label")
            mapping[address(ip)] = label
        self.previews = mapping

    def allowed(self, host, port):
        """True if a request may go upstream to host on port. Never the fixtures host, which is answered here."""
        return port in ALLOWED_PORTS and self.allowed_name(host)

    def allowed_name(self, host):
        host = clean(host)
        # A hostname and nothing else: libc ends a name at a NUL, so
        # "evil.example\0.pypi.org" would be looked up as evil.example.
        if not HOSTNAME_RE.fullmatch(host):
            return False
        if self.fixtures and host == self.fixtures:
            return False
        return host in self.exact or any(host.endswith(s) for s in self.suffixes)

    def is_fixture(self, host, port):
        return bool(self.fixtures) and clean(host) == self.fixtures and port in ALLOWED_PORTS

    def reachable(self, host, port):
        """True if a preview may ask for host on port: upstream, or the fixtures host here."""
        return self.allowed(host, port) or self.is_fixture(host, port)

    def deny(self, flow, why):
        # The log names the preview by its address, never the host it asked
        # for: the preview chose that text, and it can carry a key or token.
        log.warning("koi egress denied a request from %s (%s)", peer(flow.client_conn), why)
        if has_body(flow.request):
            # mitmproxy sends a response only after reading the whole request,
            # and would hold the body until then. Cut it off at its headers.
            cut(flow)
            return
        # A fixed body, for the same reason: no preview-chosen text in it.
        flow.response = http.Response.make(
            403, b"koi: egress is not allowed\n", {"content-type": "text/plain"}
        )

    def refuse(self, client: connection.Client, why):
        """Refuse a client connection for good: nothing more on it reaches upstream."""
        log.warning("koi egress refused a connection from %s (%s)", peer(client), why)
        self.refused.add(client.id)

    def http_connect(self, flow: http.HTTPFlow):
        # mitmproxy itself refuses a CONNECT inside a tunnel (400), so this
        # sees only the one that opens a connection's tunnel.
        if flow.request.port != 443 or not self.reachable(flow.request.host, 443):
            self.deny(flow, "connect")
        else:
            self.tunnels[flow.client_conn.id] = clean(flow.request.host)

    def tls_clienthello(self, data: tls.ClientHelloData):
        # Every tunnel is intercepted (never data.ignore_connection), so the
        # requests inside it can be checked.
        client = data.context.client
        host = self.tunnels.get(client.id)
        sni = clean(data.client_hello.sni)
        if transparent(client):
            # No CONNECT named a host, so the server name is the one this
            # connection is for, held to every request in it as a CONNECT
            # host is. The port is the one the preview connected to.
            if not sni:
                self.refuse(client, "TLS without a server name")
            elif not self.reachable(sni, client.sockname[1]):
                self.refuse(client, "TLS server name not allowed")
            else:
                self.tunnels[client.id] = sni
            return
        if host is None:
            self.refuse(client, "TLS outside a CONNECT tunnel")
        elif not sni:
            self.refuse(client, "TLS without a server name")
        elif sni != host:
            self.refuse(client, "TLS server name is not the CONNECT host")

    def tls_start_client(self, data: tls.TlsData):
        # A refused client gets a TLS endpoint with no certificate, so its
        # handshake fails before it can send a request. mitmproxy's own TLS
        # setup runs after this addon and leaves ssl_conn alone once set.
        if data.context.client.id in self.refused:
            data.ssl_conn = SSL.Connection(SSL.Context(SSL.TLS_SERVER_METHOD))
            data.ssl_conn.set_accept_state()

    def requestheaders(self, flow: http.HTTPFlow):
        if flow.request.method == "CONNECT":
            return  # http_connect decides
        client = flow.client_conn
        tunnel = self.tunnels.get(client.id)
        why = (self.aim(flow, tunnel) if transparent(client) else None) or self.check(flow.request, client, tunnel)
        if why is None:
            if self.is_fixture(flow.request.host, flow.request.port):
                self.fixture(flow)
                return
            # The request's headers leave as soon as this hook returns, so the
            # token swap happens here, not in a request hook.
            if not self.swap_keys(flow, tunnel):
                return
            # Stream the body upstream as it arrives.
            flow.request.stream = True
            return
        if tunnel is None:
            self.deny(flow, why)
        else:
            self.refuse(client, why)
            cut(flow)

    def check(self, request: http.Request, client: connection.Client, tunnel):
        """Why a request may not go upstream, or None if it may."""
        host = clean(request.host)
        if client.id in self.refused:
            return "connection already refused"
        if tunnel is not None and not client.tls:
            return "plain text inside a tunnel"
        if tunnel is not None and host != tunnel:
            return "request host is not the CONNECT host"
        if not self.reachable(host, request.port):
            return "host not allowed"
        if not names_only(authorities(request), host, request.port):
            return "Host or :authority names another host"
        return None

    def aim(self, flow: http.HTTPFlow, tunnel):
        """Point a redirected request at the name it is for, or say why it has none.

        mitmproxy aims it at the address the preview connected to, which
        proves nothing, so the policy never connects there. Over TLS the
        name is the server name tls_clienthello took as the connection's
        tunnel; in plain HTTP, the request's Host header. check() then holds
        every name in the request to it, and mitmproxy connects upstream to
        that name. Only the target changes here, never a header.
        """
        request, client = flow.request, flow.client_conn
        if client.tls:
            if tunnel is None:
                return "TLS without a checked server name"
            name = tunnel
        else:
            names = authorities(request)
            if not names:
                return "no Host header"
            try:
                name, _ = url.parse_authority(names[0], check=True)
            except ValueError:
                return "Host is not a host"
        request.data.host = clean(name)
        return None

    def fixture(self, flow: http.HTTPFlow):
        """Answer a request for the fixtures host here, in the request hook, once it is whole; nothing goes upstream."""
        if flow.request.method not in ("GET", "HEAD") or has_body(flow.request):
            self.answer(flow, 405, "the fixtures host takes GET and HEAD without a body")
            return
        self.fixture_flows.add(flow)

    async def request(self, flow: http.HTTPFlow):
        if flow in self.fixture_flows:
            self.fixture_flows.discard(flow)
            response = await fixture_response(flow.request)
            if flow.request.method == "HEAD":
                # Not .content, which would set Content-Length to 0.
                response.raw_content = b""
            flow.response = response

    async def dns_answer(self, data, source):
        """The packed answer to one DNS query from a preview at address source, or None to send nothing.

        Only names a preview may reach are looked up: a name the policy would
        refuse gets NXDOMAIN at once, so the server looks up no name the
        proxy would not look up itself for a CONNECT. An allowed name gets
        an empty answer for any type but A: previews have no IPv6 route, so
        an IPv6 address would only send a client the wrong way first. Only
        public addresses are given. Lookups in flight are capped, overall
        and per preview; past either cap a query gets SERVFAIL, and its
        client asks again. The log names the preview, never the name.
        """
        if not plain_query(data):
            return None
        try:
            request = dns.DNSMessage.unpack(data)
        except (struct.error, ValueError, IndexError):
            return None
        question = request.question
        if (
            not request.query
            or request.op_code != dns.op_codes.QUERY
            or question is None
            or question.class_ != dns.classes.IN
        ):
            return request.fail(dns.response_codes.REFUSED).packed
        # mitmproxy decodes IDNA labels; the policy and the resolver both
        # take the ASCII form an allowlist names.
        try:
            name = clean(question.name).encode("idna").decode("ascii")
        except UnicodeError:
            log.warning("koi egress refused a name lookup from %s", source)
            return request.fail(dns.response_codes.NXDOMAIN).packed
        if not (self.allowed_name(name) or (self.fixtures and name == self.fixtures)):
            log.warning("koi egress refused a name lookup from %s", source)
            return request.fail(dns.response_codes.NXDOMAIN).packed
        if question.type != dns.types.A:
            return request.succeed([]).packed
        held = self.lookups.get(source, 0)
        if sum(self.lookups.values()) >= MAX_LOOKUPS or held >= MAX_LOOKUPS_PER_SOURCE:
            return request.fail(dns.response_codes.SERVFAIL).packed
        self.lookups[source] = held + 1
        try:
            addresses = await self.lookup(name)
        except socket.gaierror as e:
            if e.args[0] == socket.EAI_NONAME:
                return request.fail(dns.response_codes.NXDOMAIN).packed
            addresses = [] if e.args[0] == socket.EAI_NODATA else None
            if addresses is None:
                return request.fail(dns.response_codes.SERVFAIL).packed
        except OSError:
            return request.fail(dns.response_codes.SERVFAIL).packed
        finally:
            self.lookups[source] -= 1
            if not self.lookups[source]:
                del self.lookups[source]
        records = []
        for text in sorted(set(addresses)):
            ip = ipaddress.ip_address(text)
            if ip.version == 4 and public(ip.packed):
                records.append(dns.ResourceRecord.A(question.name, ip, ttl=DNS_TTL))
        return request.succeed(records).packed

    async def lookup(self, name):
        """The IPv4 addresses the box's resolver has for name, on the DNS server's own threads; socket.gaierror if none."""
        infos = await asyncio.get_running_loop().run_in_executor(
            self.dns_pool, socket.getaddrinfo, name, None, socket.AF_INET, socket.SOCK_STREAM
        )
        return [info[4][0] for info in infos]

    def listen_dns(self, where):
        """Bind the DNS server's UDP socket at host:port now, and serve it on the event loop."""
        host, _, port = where.rpartition(":")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((host, int(port)))
        sock.setblocking(False)
        self.dns_sock = sock
        self.dns_pool = concurrent.futures.ThreadPoolExecutor(max_workers=DNS_WORKERS, thread_name_prefix="koi-dns")
        loop = asyncio.get_running_loop()
        self.dns_server = loop.create_task(loop.create_datagram_endpoint(lambda: DnsServer(self), sock=sock))
        log.info("koi egress DNS on %s", where)

    def close_dns(self):
        task, self.dns_server = self.dns_server, None
        if task is None:
            return
        if task.done() and not task.cancelled() and task.exception() is None:
            task.result()[0].close()
        else:
            task.cancel()
        self.dns_sock.close()
        self.dns_pool.shutdown(wait=False, cancel_futures=True)

    def swap_keys(self, flow: http.HTTPFlow, tunnel):
        """Swap koi tokens for keys in the provider's own auth fields; False if the request was refused.

        A token anywhere else (another header, another query parameter, the
        body, or a field of another provider) is left as it is: it is not a
        key, and it never becomes one. A request to a provider that is not
        verified HTTPS to it (see verified) gets no key, and is refused if it
        carries a token.

        An upgrade (a WebSocket, such as a realtime API) that carries a token
        is refused too. After the 101 the proxy relays the connection as raw
        bytes, which it cannot scrub of a key the way it scrubs a response,
        so it never swaps one in.
        """
        host = clean(flow.request.host)
        provider = PROVIDERS.get(host)
        if provider is None:
            return True
        if "upgrade" in flow.request.headers:
            if carries_token(flow.request):
                self.answer(flow, 403, "koi tokens do not work for WebSocket APIs; use the provider's HTTP API")
                return False
            return True
        if not verified(flow, tunnel, host):
            if carries_token(flow.request):
                self.answer(flow, 403, "a koi token works only over HTTPS to its provider")
                return False
            return True
        auth = AUTH[provider]
        swapped = []
        for header in auth["headers"]:
            token = token_in(header, flow.request.headers.get(header))
            if token is None:
                continue
            key = self.key_for(flow, token, provider)
            if key is None:
                return False
            flow.request.headers[header] = f"Bearer {key}" if header == "authorization" else key
            swapped.append((key, token))
        query = auth.get("query")
        if query is not None and urlsplit(flow.request.path).path.startswith(auth["paths"]):
            token = flow.request.query.get(query)
            if token is not None and TOKEN_RE.fullmatch(token):
                key = self.key_for(flow, token, provider)
                if key is None:
                    return False
                flow.request.query[query] = key
                swapped.append((key, token))
        if swapped:
            # The response is scrubbed of the key on its way back, which a
            # compressed body would hide it from.
            flow.request.headers["accept-encoding"] = "identity"
            self.substituted[flow] = secret_forms(swapped)
        return True

    def key_for(self, flow, token, provider):
        """The key behind a token, or None after refusing the request.

        The token must have been registered for the preview whose container
        sent the request: the client address must be one koid mapped to the
        token's label. An address koid did not map is no preview's.
        """
        try:
            label = self.previews.get(address(peer(flow.client_conn)))
        except ValueError:
            label = None
        key, reason = self.registry.key_for(token, provider, label)
        if key is None:
            self.answer(flow, 401, reason)
        return key

    def answer(self, flow, status, message):
        """Refuse a request with a message, or cut it off if its body is too large to read first.

        mitmproxy sends a response only after reading the whole request. A
        body of known length up to 64 KiB (stream_large_bodies) is read and
        dropped; anything larger or of unknown length is cut off at its
        headers, as deny does.
        """
        log.warning("koi egress refused a request from %s (%d)", peer(flow.client_conn), status)
        length = flow.request.headers.get("content-length", "0").strip()
        small = "transfer-encoding" not in flow.request.headers and length.isdigit() and int(length) <= 64 * 1024
        if not small:
            cut(flow)
            return
        flow.response = http.Response.make(status, f"koi: {message}\n".encode(), {"content-type": "text/plain"})

    def responseheaders(self, flow: http.HTTPFlow):
        # Stream every response to the preview as it arrives, model weights
        # and server-sent events alike.
        pairs = self.substituted.get(flow)
        if pairs is None:
            if flow.response.status_code == 101:
                self.upgraded.add(flow.client_conn.id)
            flow.response.stream = True
            return
        if flow.response.status_code == 101:
            # A key went up in a request that was not an upgrade (see
            # swap_keys), and the provider switched protocols anyway. What
            # follows would be relayed as bytes nobody scrubs.
            log.warning("koi egress dropped an upgrade for %s", peer(flow.client_conn))
            flow.kill()
            return
        # A key went upstream in this request. Whatever comes back, a
        # redirect or an error that quotes the request, reaches the preview
        # with the key replaced by its token.
        response = flow.response
        encoding = response.headers.get("content-encoding", "identity").strip().lower()
        if encoding not in ("", "identity"):
            log.warning("koi egress dropped an encoded response for %s", peer(flow.client_conn))
            flow.kill()
            return
        response.headers.fields = tuple((scrub(n, pairs), scrub(v, pairs)) for n, v in response.headers.fields)
        response.data.reason = scrub(response.data.reason, pairs)
        if flow.request.method.upper() != "HEAD" and response.status_code >= 200 and response.status_code not in (204, 304):
            # A token is not as long as its key, so the body's length can
            # change: send it without a Content-Length, chunked to an HTTP/1
            # client.
            response.headers.pop("content-length", None)
            if flow.request.http_version.startswith("HTTP/1"):
                response.headers["transfer-encoding"] = "chunked"
        response.stream = Scrubber(pairs)

    def response(self, flow: http.HTTPFlow):
        # Trailers go to the preview after this hook.
        pairs = self.substituted.pop(flow, None)
        if pairs is not None and flow.response.trailers:
            trailers = flow.response.trailers
            trailers.fields = tuple((scrub(n, pairs), scrub(v, pairs)) for n, v in trailers.fields)

    def error(self, flow: http.HTTPFlow):
        self.substituted.pop(flow, None)

    def tcp_start(self, flow: tcp.TCPFlow):
        # mitmproxy relays raw bytes only after an upgrade (websocket is off).
        # Anything else should not happen, as rawtcp is off; if it does, the
        # relay gets no upstream connection.
        if flow.client_conn.id not in self.upgraded:
            self.refuse(flow.client_conn, "raw TCP")

    def tcp_message(self, flow: tcp.TCPFlow):
        # mitmproxy keeps every chunk it relays on the flow. Keep only the one
        # being relayed now.
        del flow.messages[:-1]

    def server_connect(self, data):
        # The last gate before any upstream connection, whatever led here.
        server, client = data.server, data.client
        host, port = server.address
        tunnel = self.tunnels.get(client.id)
        if (
            client.id in self.refused
            or not self.allowed(host, port)
            or (tunnel is not None and clean(host) != tunnel)
            or (server.sni is not None and clean(server.sni) != clean(host))
        ):
            log.warning("koi egress stopped an upstream connection for %s", peer(client))
            server.error = "koi: egress refused"

    def client_disconnected(self, client: connection.Client):
        self.tunnels.pop(client.id, None)
        self.refused.discard(client.id)
        self.upgraded.discard(client.id)


addons = [KoiEgress()]
