"""A real proxy for end-to-end tests of the egress policy.

The proxy is mitmproxy with koi_egress.py loaded as a script, as mitmdump
loads it on the box, so hooks run in the same order as there. One local
server stands in for every allowed host: a test addon added after the policy
sends each upstream connection to it, so tests can CONNECT to pypi.org
without a network. The server records the TLS server name and Host header of
everything that reaches it.
"""

import asyncio
import base64
import hashlib
import http.client
import logging
import os
import socket
import ssl
import struct
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from mitmproxy import addons, master, options
from mitmproxy.certs import CertStore

HERE = Path(__file__).parent
ADDON = HERE.parent / "koi_egress.py"
# What the upstream's certificate covers: every name a test connects to.
NAMES = ["pypi.org", "www.python.org", "files.pythonhosted.org"]
# LLM provider APIs, where the policy swaps koi tokens for keys.
NAMES += ["api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com", "api.groq.com", "openrouter.ai"]


def token_secret(workdir, data=None, name="token-secret"):
    """The token secret file in workdir, as install.sh makes it (32 random bytes, mode 0400); returns its path.

    One that is already there is kept, so proxies started from the same
    workdir, one after another, share a secret as restarts on the box do.
    """
    path = workdir / name
    if not path.exists():
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
        try:
            os.write(fd, os.urandom(32) if data is None else data)
        finally:
            os.close(fd)
    return path


class Upstream:
    """One HTTPS and one HTTP server on 127.0.0.1 that answer for every name."""

    def __init__(self, workdir):
        self.lock = threading.Lock()
        self.snis = []  # TLS server names, one per handshake
        self.requests = []  # (Host header, path, request body bytes read)
        # A test may answer instead: reply(handler) is called with each
        # request once its body is read, and writes the whole response.
        self.reply = None
        self.ws_bytes = 0  # WebSocket payload bytes received from clients
        store = CertStore.from_store(workdir / "upstream", "upstream", 2048)
        entry = store.get_cert(NAMES[0], [x509.DNSName(n) for n in NAMES])
        self.ca = workdir / "upstream" / "upstream-ca-cert.pem"
        cert, key = workdir / "upstream-cert.pem", workdir / "upstream-key.pem"
        cert.write_bytes(entry.cert.to_pem())
        key.write_bytes(
            entry.privatekey.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        tls.sni_callback = self.record_sni
        self.https = self.serve(tls)
        self.http = self.serve(None)

    def record_sni(self, sslobj, name, context):
        with self.lock:
            self.snis.append(name)

    def serve(self, tls):
        upstream = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def answer(self):
                if self.headers.get("upgrade", "").lower() == "websocket":
                    return self.websocket()
                length = int(self.headers.get("content-length") or 0)
                read = 0
                # The body's SHA-256, for a reply to check it arrived intact.
                self.body_digest = hashlib.sha256()
                while read < length:
                    chunk = self.rfile.read(min(1 << 20, length - read))
                    if not chunk:
                        break
                    read += len(chunk)
                    self.body_digest.update(chunk)
                with upstream.lock:
                    upstream.requests.append((self.headers.get("host"), self.path, read))
                if upstream.reply is not None:
                    upstream.reply(self)
                    return
                if self.path.startswith("/bytes/"):
                    size = int(self.path.rsplit("/", 1)[1])
                    self.send_response(200)
                    self.send_header("content-length", str(size))
                    self.end_headers()
                    block = b"x" * (1 << 20)
                    sent = 0
                    while sent < size:
                        n = min(len(block), size - sent)
                        self.wfile.write(block[:n])
                        sent += n
                    return
                body = f"upstream saw {self.headers.get('host')} and {read} bytes\n".encode()
                self.send_response(200)
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def websocket(self):
                """Accept a WebSocket and count the payload of every frame until it closes."""
                key = self.headers["sec-websocket-key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
                self.send_response(101)
                self.send_header("upgrade", "websocket")
                self.send_header("connection", "Upgrade")
                self.send_header("sec-websocket-accept", base64.b64encode(hashlib.sha1(key.encode()).digest()).decode())
                self.end_headers()
                self.wfile.flush()
                with upstream.lock:
                    upstream.requests.append((self.headers.get("host"), self.path, 0))
                while True:
                    head = self.rfile.read(2)
                    if len(head) < 2:
                        return
                    size = head[1] & 0x7F
                    if size == 126:
                        size = struct.unpack("!H", self.rfile.read(2))[0]
                    elif size == 127:
                        size = struct.unpack("!Q", self.rfile.read(8))[0]
                    if head[1] & 0x80:
                        self.rfile.read(4)  # the tests' mask is zeros
                    left = size
                    while left:
                        chunk = self.rfile.read(min(left, 1 << 20))
                        if not chunk:
                            return
                        left -= len(chunk)
                    if head[0] & 0x0F == 8:  # close
                        return
                    with upstream.lock:
                        upstream.ws_bytes += size

            do_GET = do_POST = do_PUT = answer

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        if tls is not None:
            server.socket = tls.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server

    def seen(self):
        with self.lock:
            return list(self.snis), list(self.requests)

    def clear(self):
        with self.lock:
            self.snis.clear()
            self.requests.clear()
            self.ws_bytes = 0
        self.reply = None

    def close(self):
        for server in (self.https, self.http):
            server.shutdown()
            server.server_close()


class ToUpstream:
    """Test addon, added after the policy: sends every upstream connection to the local server."""

    def __init__(self, upstream):
        self.upstream = upstream

    def server_connect(self, data):
        if data.server.error:
            return
        port = data.server.address[1]
        server = self.upstream.https if port == 443 else self.upstream.http
        data.server.address = server.server_address


class Flows:
    """Test addon: keeps every HTTP flow the proxy finished or killed, and every TCP flow."""

    def __init__(self):
        self.flows = []
        self.tcp = []

    def response(self, flow):
        self.flows.append(flow)

    def error(self, flow):
        self.flows.append(flow)

    def tcp_start(self, flow):
        self.tcp.append(flow)


class Logged(logging.Handler):
    """Keeps every log message, to wait for one."""

    def __init__(self):
        super().__init__()
        self.messages = []

    def emit(self, record):
        self.messages.append(record.getMessage())


class Proxy:
    """mitmproxy started as koi-egress.service starts it: server off, script given.

    script is the policy file to load (koi_egress.py unless a test passes a
    copy to break); port is where it listens once the policy turns the server
    on (0: any free port). wait: return only once the policy is active.
    policy_options are more of the policy's own options, such as koi_control;
    koi_secret is the workdir's token secret (token_secret) unless given.
    """

    def __init__(self, workdir, upstream, allow, script=ADDON, port=0, wait=True, **policy_options):
        self.workdir = workdir
        self.upstream = upstream
        policy_options.setdefault("koi_secret", str(token_secret(workdir)))
        self.flows = Flows()
        self.ca = workdir / "confdir" / "mitmproxy-ca-cert.pem"
        self.log = Logged()
        for name in ("mitmproxy.addons.script", "koi_egress"):
            logging.getLogger(name).addHandler(self.log)
        started = threading.Event()
        self.thread = threading.Thread(
            target=self.run, args=(allow, script, port, started, policy_options), daemon=True
        )
        self.thread.start()
        if not started.wait(30):
            raise RuntimeError("the proxy did not start")
        if wait:
            self.wait_listening()

    def run(self, allow, script, port, started, policy_options):
        async def main():
            opts = options.Options(listen_host="127.0.0.1", listen_port=port)
            self.master = master.Master(opts)
            self.master.addons.add(*addons.default_addons(), ToUpstream(self.upstream), self.flows)
            opts.update(
                confdir=str(self.workdir / "confdir"),
                ssl_verify_upstream_trusted_ca=str(self.upstream.ca),
                server=False,
                scripts=[str(script)],
            )
            opts.update_defer(koi_allow=str(allow), **policy_options)
            started.set()
            await self.master.run()

        asyncio.run(main())

    def wait_listening(self, timeout=30):
        deadline = time.monotonic() + timeout
        while self.policy() is None or not self.address():
            if time.monotonic() > deadline:
                raise RuntimeError("the proxy did not load koi_egress.py")
            time.sleep(0.05)

    def script(self):
        """mitmproxy's handle on the policy file; its ns is the loaded module, or None."""
        return self.master.addons.get("scriptloader").addons[0]

    def wait_loaded(self, before=None, since=0, timeout=10):
        """Wait until mitmproxy has (re)loaded the policy file, or failed to.

        before: the module loaded until now, if any; since: how many log
        messages there were before the file changed.
        """
        deadline = time.monotonic() + timeout
        while True:
            ns = self.script().ns
            if (ns is not None and ns is not before) or any(
                "error in script" in m for m in self.log.messages[since:]
            ):
                return
            if time.monotonic() > deadline:
                raise RuntimeError(f"the policy file did not load: {self.log.messages}")
            time.sleep(0.05)

    def wait_logged(self, text, timeout=10):
        """Wait for a log message containing text."""
        deadline = time.monotonic() + timeout
        while not any(text in m for m in self.log.messages):
            if time.monotonic() > deadline:
                raise RuntimeError(f"nothing logged {text!r}: {self.log.messages}")
            time.sleep(0.05)

    def finished(self, count=1):
        """Wait until the proxy has finished or killed count flows; returns them."""
        deadline = time.monotonic() + 10
        while len(self.flows.flows) < count and time.monotonic() < deadline:
            time.sleep(0.01)
        return list(self.flows.flows)

    def policy(self):
        return self.master.addons.get("koiegress")

    def address(self):
        addrs = self.master.addons.get("proxyserver").listen_addrs()
        return addrs[0][:2] if addrs else None

    def close(self):
        self.master.shutdown()
        self.thread.join(10)
        for name in ("mitmproxy.addons.script", "koi_egress"):
            logging.getLogger(name).removeHandler(self.log)

    # Clients

    def connect(self):
        return socket.create_connection(self.address(), timeout=10)

    def tunnel(self, target):
        """Open a CONNECT tunnel; returns (socket, status code)."""
        sock = self.connect()
        sock.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = sock.recv(4096)
            if not chunk:
                break
            head += chunk
        status = int(head.split(b" ", 2)[1]) if head else 0
        return sock, status

    def tls(self, sock, sni, alpn=("http/1.1",)):
        """TLS over a tunnel with the given server name (None sends none).

        The client trusts koi's CA and the upstream's, as a preview trusts
        koi's and the public ones.
        """
        context = ssl.create_default_context(cafile=str(self.ca))
        context.load_verify_locations(cafile=str(self.upstream.ca))
        context.set_alpn_protocols(list(alpn))
        if sni is None:
            context.check_hostname = False
        return context.wrap_socket(sock, server_hostname=sni)

    def https(self, sni, connect="pypi.org:443"):
        sock, status = self.tunnel(connect)
        assert status == 200, status
        return self.tls(sock, sni)


def request(sock, host, path="/", method="GET", body=None, target=None):
    """One HTTP/1.1 request on an open socket; returns (status, body) or raises if the proxy cut it off."""
    conn = http.client.HTTPConnection(host)
    conn.sock = sock
    conn.putrequest(method, target or path, skip_host=True, skip_accept_encoding=True)
    conn.putheader("Host", host)
    if body is not None:
        conn.putheader("Content-Length", str(len(body)))
    conn.endheaders(body)
    response = conn.getresponse()
    return response.status, response.read()


def refused(call):
    """True if the proxy closed the connection instead of answering."""
    try:
        call()
    except (ssl.SSLError, ConnectionError, http.client.HTTPException, OSError):
        return True
    return False


@pytest.fixture(scope="module")
def proxy():
    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        allow = workdir / "allow.txt"
        allow.write_text("pypi.org\nfiles.pythonhosted.org\n")
        upstream = Upstream(workdir)
        p = Proxy(workdir, upstream, allow)
        try:
            yield p
        finally:
            p.close()
            upstream.close()


@pytest.fixture
def upstream(proxy):
    proxy.upstream.clear()
    proxy.flows.flows.clear()
    proxy.flows.tcp.clear()
    return proxy.upstream
