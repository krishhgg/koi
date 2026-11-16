"""End-to-end: the key swap's state lives and dies with the loaded policy."""

import hashlib
import http.client
import json
import os
import socket
import threading
import time

import pytest
from conftest import ADDON, Proxy, Upstream, token_secret
from test_failclosed import BROKEN, free_port, write

TOKEN = "koi_" + "a" * 32
LABEL = "storefront-pr-7"


def control(path, request):
    """One request on the proxy's control socket; returns the reply."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        s.connect(str(path))
        s.sendall((json.dumps(request) + "\n").encode())
        return json.loads(s.makefile().readline())


@pytest.fixture
def box(tmp_path):
    allow = tmp_path / "allow.txt"
    allow.write_text("pypi.org\n")
    upstream = Upstream(tmp_path)
    script = tmp_path / "koi_egress.py"
    script.write_text(ADDON.read_text())
    sock = tmp_path / "control.sock"
    proxy = Proxy(tmp_path, upstream, allow, script=script, port=free_port(), koi_control=str(sock))
    yield proxy, script, sock
    proxy.close()
    upstream.close()


def register(sock):
    """Register an OpenAI key for LABEL; returns the token, or raises if the socket is closed."""
    reply = control(sock, {"op": "register", "label": LABEL, "keys": {"openai": "sk-real"}, "source": "x"})
    assert reply["ok"] is True, reply
    return reply["tokens"]["openai"]


def test_a_reload_starts_with_no_tokens_and_registering_again_gives_the_same_one(box):
    proxy, script, sock = box
    token = register(sock)
    assert token in proxy.policy().registry.entries
    write(script, ADDON.read_text() + "\n# changed\n", 5)
    proxy.wait_logged("policy unloaded")
    deadline = time.monotonic() + 10
    while (proxy.policy() is None or token in proxy.policy().registry.entries) and time.monotonic() < deadline:
        time.sleep(0.05)
    proxy.wait_listening()
    assert proxy.policy().registry.entries == {}
    assert proxy.policy().previews == {}
    assert register(sock) == token


def test_tokens_survive_a_proxy_restart_and_still_swap(tmp_path):
    # The box sleeps, or the service restarts: a new mitmdump with the same
    # secret file gives the same token for the same key and preview, and
    # swaps it as before. Another secret gives another token.
    allow = tmp_path / "allow.txt"
    allow.write_text("pypi.org\n")
    upstream = Upstream(tmp_path)
    sock = tmp_path / "control.sock"
    secret = token_secret(tmp_path)
    seen = []

    def reply(handler):
        seen.append(handler.headers.get("authorization"))
        handler.send_response(200)
        handler.send_header("content-length", "0")
        handler.end_headers()

    upstream.reply = reply

    def start(secret_path):
        proxy = Proxy(tmp_path, upstream, allow, port=free_port(), koi_control=str(sock), koi_secret=str(secret_path))
        proxy.control = sock
        assert control(sock, {"op": "previews", "previews": {"127.0.0.1": LABEL}}) == {"ok": True}
        return proxy

    try:
        first = start(secret)
        token = register_key(first, "openai", "sk-proj-real")
        assert call(first, "api.openai.com", "/v1/models", {"authorization": f"Bearer {token}"})[0] == 200
        first.close()

        second = start(secret)
        # Nothing is held after the restart, until the key is registered again.
        assert call(second, "api.openai.com", "/v1/models", {"authorization": f"Bearer {token}"})[0] == 401
        assert register_key(second, "openai", "sk-proj-real") == token
        assert call(second, "api.openai.com", "/v1/models", {"authorization": f"Bearer {token}"})[0] == 200
        assert register_key(second, "openai", "sk-proj-other") != token
        second.close()

        third = start(token_secret(tmp_path, name="another-secret"))
        assert register_key(third, "openai", "sk-proj-real") != token
        third.close()
    finally:
        upstream.close()
    assert seen == ["Bearer sk-proj-real", "Bearer sk-proj-real"]


@pytest.mark.parametrize("how", list(BROKEN))
def test_a_broken_reload_closes_the_control_socket(box, how):
    proxy, script, sock = box
    register(sock)
    loaded, since = proxy.script().ns, len(proxy.log.messages)
    write(script, BROKEN[how], 5)
    proxy.wait_loaded(before=loaded, since=since)
    time.sleep(0.5)
    with pytest.raises(OSError):
        register(sock)


# The key swap through a real proxy: requests from a preview through a CONNECT
# tunnel to a provider, an upstream that echoes the key back, and what the
# preview receives.

KEY = "sk-or-v1-0123456789abcdef0123456789abcdef"


@pytest.fixture(scope="module")
def keys_proxy(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("keys")
    allow = tmp / "allow.txt"
    allow.write_text("pypi.org\n")
    upstream = Upstream(tmp)
    sock = tmp / "control.sock"
    proxy = Proxy(tmp, upstream, allow, koi_control=str(sock))
    proxy.control = sock
    # The test client's address is LABEL's container; two more are other
    # previews' (see test_a_token_works_only_from_its_own_preview).
    assert control(sock, {"op": "previews", "previews": {"127.0.0.1": LABEL, "127.0.0.2": "evil-pr-8"}}) == {
        "ok": True
    }
    yield proxy
    proxy.close()
    upstream.close()


@pytest.fixture
def provider(keys_proxy):
    """The proxy, with what the upstream saw cleared; tests set upstream.reply."""
    keys_proxy.upstream.clear()
    return keys_proxy


def register_key(proxy, provider_id, key=KEY, label=LABEL):
    """Register key for provider and the preview label; returns the token the proxy made."""
    reply = control(proxy.control, {"op": "register", "label": label, "keys": {provider_id: key}, "source": "x"})
    assert reply["ok"] is True, reply
    return reply["tokens"][provider_id]


def call(proxy, host, target, headers, host_header=None, plain=False, body=None, source="127.0.0.1"):
    """GET target, or POST body to it, through a tunnel to host, or as plain HTTP through the proxy (target is then a
    URL), from the client address source.

    Returns (status, headers, body) as the preview sees them, or raises if
    the proxy closed the connection.
    """
    sock = socket.create_connection(proxy.address(), timeout=10, source_address=(source, 0))
    if not plain:
        sock.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = sock.recv(4096)
            if not chunk:
                raise ConnectionError("the proxy closed the tunnel")
            head += chunk
        assert head.split(b" ", 2)[1] == b"200", head
        sock = proxy.tls(sock, host)
    conn = http.client.HTTPConnection(host)
    conn.sock = sock
    conn.putrequest("GET" if body is None else "POST", target, skip_host=True, skip_accept_encoding=True)
    conn.putheader("Host", host_header or host)
    for name, value in headers.items():
        conn.putheader(name, value)
    if body is not None:
        conn.putheader("Content-Length", str(len(body)))
    conn.endheaders(body)
    response = conn.getresponse()
    return response.status, response.getheaders(), response.read()


def echo(seen):
    """An upstream reply that redirects to the URL it was asked for, quoting the Authorization header in a header and
    in a body sent in two writes that split the key."""

    def reply(handler):
        seen.append((handler.path, handler.headers.get("authorization")))
        auth = handler.headers.get("authorization") or ""
        body = f'{{"error": "Incorrect API key provided: {auth}"}}'.encode()
        middle = body.index(b"sk-or-v1-") + 10 if b"sk-or-v1-" in body else len(body) // 2
        handler.send_response(301)
        handler.send_header("location", f"https://{handler.headers['host']}{handler.path}")
        handler.send_header("x-echo", auth)
        handler.send_header("content-length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body[:middle])
        handler.wfile.flush()
        time.sleep(0.2)
        handler.wfile.write(body[middle:])
        handler.wfile.flush()

    return reply


@pytest.mark.parametrize("size", [1024, 300 * 1024])
def test_a_post_goes_up_with_the_key_in_its_header_and_its_body_intact(provider, size):
    # mitmproxy sends a request's headers upstream as soon as the
    # requestheaders hook returns, and its body streams after them, so the
    # swap must happen in that hook. A body past 64 KiB streams in pieces.
    token = register_key(provider, "openai", "sk-proj-real-openai-key")
    body = b'{"model": "gpt", "input": "' + os.urandom(size).hex().encode() + b'"}'
    seen = []

    def reply(handler):
        seen.append((handler.headers.get("authorization"), handler.body_digest.hexdigest()))
        handler.send_response(200)
        handler.send_header("content-length", "2")
        handler.end_headers()
        handler.wfile.write(b"ok")

    provider.upstream.reply = reply
    status, _, answer = call(
        provider, "api.openai.com", "/v1/responses", {"authorization": f"Bearer {token}"}, body=body
    )
    assert (status, answer) == (200, b"ok")
    assert seen == [("Bearer sk-proj-real-openai-key", hashlib.sha256(body).hexdigest())]
    assert provider.upstream.seen()[1] == [("api.openai.com", "/v1/responses", len(body))]


def test_an_openrouter_query_key_is_not_swapped(provider):
    # The reviewer's case: ?key= is not where OpenRouter takes its key, so the
    # token goes up as it is, and the redirect quotes only the token.
    token = register_key(provider, "openrouter")
    seen = []
    provider.upstream.reply = echo(seen)
    status, headers, body = call(provider, "openrouter.ai", f"/api/v1/models/?key={token}", {})
    assert status == 301
    assert seen == [(f"/api/v1/models/?key={token}", None)]
    assert dict(headers)["location"] == f"https://openrouter.ai/api/v1/models/?key={token}"
    assert KEY.encode() not in body and KEY not in str(headers)


def test_a_swapped_key_comes_back_as_the_token(provider):
    token = register_key(provider, "openrouter")
    seen = []
    provider.upstream.reply = echo(seen)
    status, headers, body = call(provider, "openrouter.ai", "/api/v1/models", {"authorization": f"Bearer {token}"})
    # Upstream got the key; the preview gets the token back, in the echoed
    # header and in the body whose two writes split the key.
    assert seen == [("/api/v1/models", f"Bearer {KEY}")]
    assert status == 301
    assert dict(headers)["x-echo"] == f"Bearer {token}"
    assert body == f'{{"error": "Incorrect API key provided: Bearer {token}"}}'.encode()
    assert KEY not in str(headers)


def test_a_gemini_query_key_is_swapped_on_api_paths_and_scrubbed_from_the_redirect(provider):
    token = register_key(provider, "gemini", "AIzaSy-real-gemini-key-0123456789")
    seen = []
    provider.upstream.reply = echo(seen)
    status, headers, body = call(
        provider, "generativelanguage.googleapis.com", f"/v1beta/models/?key={token}", {}
    )
    assert seen == [("/v1beta/models/?key=AIzaSy-real-gemini-key-0123456789", None)]
    assert status == 301
    location = dict(headers)["location"]
    assert location == f"https://generativelanguage.googleapis.com/v1beta/models/?key={token}"
    assert b"AIzaSy-real" not in body


# Where a key may go: HTTPS on 443, with the CONNECT host, the TLS server
# name, the URL and the Host header all the provider's own name.


@pytest.mark.parametrize("other", ["www.cloudflare.com", "example.com"])
def test_a_host_header_for_another_site_gets_no_key(provider, other):
    # The reviewer's cases: the URL names Groq, the Host header another site.
    token = register_key(provider, "groq")
    seen = []
    provider.upstream.reply = echo(seen)
    status, _, body = call(
        provider, "api.groq.com", f"http://api.groq.com/?key={token}", {}, host_header=other, plain=True
    )
    assert status == 403
    with pytest.raises(OSError):
        call(provider, "api.groq.com", "/openai/v1/models", {"authorization": f"Bearer {token}"}, host_header=other)
    assert seen == [] and provider.upstream.seen() == ([], [])


@pytest.mark.parametrize(
    "target,headers",
    [
        ("http://api.groq.com/openai/v1/models", {"authorization": f"Bearer {TOKEN}"}),
        (f"http://generativelanguage.googleapis.com/v1beta/models?key={TOKEN}", {}),
        ("http://api.groq.com/openai/v1/models", {"x-anything": TOKEN}),
    ],
)
def test_plain_http_with_a_token_is_refused(provider, target, headers):
    host = target.split("/")[2]
    # TOKEN stands for the provider's own, valid, token.
    token = register_key(provider, "groq" if "groq" in host else "gemini")
    target = target.replace(TOKEN, token)
    headers = {k: v.replace(TOKEN, token) for k, v in headers.items()}
    status, _, body = call(provider, host, target, headers, plain=True)
    assert status == 403
    assert b"only over HTTPS" in body
    assert provider.upstream.seen() == ([], [])


def test_plain_http_without_a_token_still_reaches_a_provider(provider):
    status, _, _ = call(provider, "api.groq.com", "http://api.groq.com/", {}, plain=True)
    assert status == 200
    assert [r[0] for r in provider.upstream.seen()[1]] == ["api.groq.com"]


# A token works only from the preview it was registered for: koid maps each
# preview container's address to its label, and the proxy checks the address
# a request comes from. On loopback, 127.0.0.2 and 127.0.0.3 stand for other
# containers.


def test_a_token_works_only_from_its_own_preview(provider):
    token = register_key(provider, "openai")
    seen = []

    def reply(handler):
        seen.append(handler.headers.get("authorization"))
        handler.send_response(200)
        handler.send_header("content-length", "0")
        handler.end_headers()

    provider.upstream.reply = reply
    auth = {"authorization": f"Bearer {token}"}
    assert call(provider, "api.openai.com", "/v1/models", auth)[0] == 200
    # Another preview's container, and an address no preview has.
    for source in ["127.0.0.2", "127.0.0.3"]:
        status, _, body = call(provider, "api.openai.com", "/v1/models", auth, source=source)
        assert status == 401, source
        assert b"another preview" in body
    assert seen == [f"Bearer {KEY}"]


def test_the_mapping_follows_a_container_restart(provider):
    token = register_key(provider, "openai")
    provider.upstream.reply = None
    auth = {"authorization": f"Bearer {token}"}
    try:
        # The preview's container came back at a new address.
        assert control(provider.control, {"op": "previews", "previews": {"127.0.0.3": LABEL}}) == {"ok": True}
        assert call(provider, "api.openai.com", "/v1/models", auth, source="127.0.0.1")[0] == 401
        assert call(provider, "api.openai.com", "/v1/models", auth, source="127.0.0.3")[0] == 200
    finally:
        control(provider.control, {"op": "previews", "previews": {"127.0.0.1": LABEL, "127.0.0.2": "evil-pr-8"}})


# Realtime APIs: a WebSocket upgrade with a token is refused before anything
# goes upstream; one without a token is relayed like any other upgrade.


def upgrade(proxy, host, target, headers):
    """Send a WebSocket upgrade through a tunnel to host; returns the response head."""
    sock = proxy.https(host, connect=f"{host}:443")
    lines = [
        f"GET {target} HTTP/1.1",
        f"Host: {host}",
        "Connection: Upgrade",
        "Upgrade: websocket",
        "Sec-WebSocket-Version: 13",
        "Sec-WebSocket-Key: MTIzNDU2Nzg5MGFiY2RlZg==",
        *(f"{name}: {value}" for name, value in headers.items()),
    ]
    sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = sock.recv(4096)
        if not chunk:
            break
        head += chunk
    sock.close()
    return head


def test_a_realtime_upgrade_with_a_token_is_refused(provider):
    token = register_key(provider, "openai")
    for target, headers in [
        ("/v1/realtime?model=gpt-realtime", {"Authorization": f"Bearer {token}"}),
        ("/v1/realtime", {"Sec-WebSocket-Protocol": f"realtime, openai-insecure-api-key.{token}"}),
    ]:
        head = upgrade(provider, "api.openai.com", target, headers)
        assert head.startswith(b"HTTP/1.1 403"), head
    assert provider.upstream.seen() == ([], [])


def test_an_upgrade_without_a_token_still_reaches_a_provider(provider):
    head = upgrade(provider, "api.openai.com", "/v1/realtime", {"Authorization": "Bearer sk-typed-by-hand"})
    assert head.startswith(b"HTTP/1.1 101"), head
    assert provider.upstream.seen()[1] == [("api.openai.com", "/v1/realtime", 0)]


def test_a_server_sent_event_reaches_the_preview_before_the_next_is_sent(provider):
    # A streamed completion: the upstream sends one event, then waits until
    # the preview has it before sending the next. Were the proxy holding the
    # end of each chunk back, the preview would wait for ever.
    token = register_key(provider, "openai")
    first_seen = threading.Event()

    def reply(handler):
        handler.send_response(200)
        handler.send_header("content-type", "text/event-stream")
        handler.send_header("connection", "close")
        handler.end_headers()
        handler.wfile.write(b'data: {"delta": "Hello"}\n\n')
        handler.wfile.flush()
        first_seen.wait(10)
        handler.wfile.write(b"data: [DONE]\n\n")
        handler.wfile.flush()
        handler.close_connection = True

    provider.upstream.reply = reply
    sock = provider.https("api.openai.com", connect="api.openai.com:443")
    conn = http.client.HTTPConnection("api.openai.com")
    conn.sock = sock
    conn.putrequest("POST", "/v1/chat/completions", skip_host=True, skip_accept_encoding=True)
    conn.putheader("Host", "api.openai.com")
    conn.putheader("Authorization", f"Bearer {token}")
    conn.putheader("Content-Length", "2")
    conn.endheaders(b"{}")
    response = conn.getresponse()
    sock.settimeout(5)
    got = b""
    started = time.monotonic()
    while b"\n\n" not in got:
        got += response.read1(65536)
    assert got == b'data: {"delta": "Hello"}\n\n'
    assert time.monotonic() - started < 5
    first_seen.set()
    assert response.read() == b"data: [DONE]\n\n"
