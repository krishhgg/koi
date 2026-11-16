"""End-to-end: the proxy never holds a whole body, allowed or refused.

Each test measures, with tracemalloc, the most memory Python held while a
64 MiB body went through or was refused. The proxy runs in this process, so
that covers every buffer mitmproxy and the addon keep.
"""

import ssl
import struct
import threading
import time
import tracemalloc

from conftest import request

BODY = 64 << 20
CHUNK = b"x" * (1 << 20)
# Far below the body: what a few chunks in flight cost, never the body.
CEILING = 16 << 20


def upload(sock, host, target):
    """Send a 64 MiB POST; returns how many body bytes went out and the error that stopped it, if any."""
    sock.sendall(f"POST {target} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {BODY}\r\n\r\n".encode())
    sent = 0
    try:
        while sent < BODY:
            sock.sendall(CHUNK)
            sent += len(CHUNK)
    except OSError as e:
        return sent, e
    return sent, None


def recv(sock):
    """One read; an empty one means the proxy closed the connection."""
    data = sock.recv(4096)
    if not data:
        raise ConnectionError("the proxy closed the connection")
    return data


def head_of(sock):
    """Read up to the end of a response's headers; returns (head, what followed)."""
    data = b""
    while b"\r\n\r\n" not in data:
        data += recv(sock)
    return data.split(b"\r\n\r\n", 1)


def answer(sock):
    """Read one response that has a Content-Length; returns its body."""
    head, body = head_of(sock)
    length = next(int(line.split(b":")[1]) for line in head.split(b"\r\n") if line.lower().startswith(b"content-length"))
    while len(body) < length:
        body += recv(sock)
    return body


def measure(run):
    """Run, and return its result and the most memory held above where it started."""
    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        base = tracemalloc.get_traced_memory()[0]
        result = run()
        return result, tracemalloc.get_traced_memory()[1] - base
    finally:
        tracemalloc.stop()


def test_a_large_denied_upload_is_cut_off_at_its_headers(proxy, upstream):
    sock = proxy.connect()
    (sent, error), used = measure(lambda: upload(sock, "denied.example", "http://denied.example/"))
    assert used < CEILING, f"the proxy held {used >> 20} MiB"
    # The proxy closed the connection; the client did not just stall.
    assert sent < BODY and isinstance(error, ConnectionError), error
    [flow] = proxy.finished()
    assert flow.error is not None and flow.response is None
    assert not flow.request.raw_content
    assert upstream.seen() == ([], [])


def test_a_large_upload_with_a_fronted_host_is_cut_off_in_a_tunnel(proxy, upstream):
    sock = proxy.https("pypi.org")
    (sent, error), used = measure(lambda: upload(sock, "www.python.org", "/upload"))
    assert used < CEILING, f"the proxy held {used >> 20} MiB"
    assert sent < BODY and isinstance(error, (ConnectionError, ssl.SSLError)), error
    assert upstream.seen()[1] == []


def test_a_denied_request_without_a_body_still_gets_a_403(proxy, upstream):
    assert request(proxy.connect(), "denied.example", target="http://denied.example/")[0] == 403


def test_a_denial_does_not_repeat_the_host_the_preview_asked_for(proxy, upstream):
    # The preview chose that text, and it can carry a key or a koi token.
    host = "koi-0123456789abcdefghij.example"
    status, body = request(proxy.connect(), host, target=f"http://{host}/")
    assert status == 403 and host.encode() not in body and b"0123456789" not in body


def test_a_large_upload_streams_through_a_tunnel(proxy, upstream):
    sock = proxy.https("pypi.org")

    def run():
        upload(sock, "pypi.org", "/upload")
        return answer(sock)

    body, used = measure(run)
    assert used < CEILING, f"the proxy held {used >> 20} MiB"
    assert body == f"upstream saw pypi.org and {BODY} bytes\n".encode()


def test_a_large_download_streams_through_a_tunnel(proxy, upstream):
    sock = proxy.https("pypi.org")

    def run():
        sock.sendall(f"GET /bytes/{BODY} HTTP/1.1\r\nHost: pypi.org\r\n\r\n".encode())
        got = 0
        while got < BODY:
            chunk = sock.recv(1 << 20)
            if not chunk:
                break
            got += len(chunk)
        return got

    got, used = measure(run)
    assert used < CEILING, f"the proxy held {used >> 20} MiB"
    assert got > BODY  # the body and the response head


def test_a_large_plain_http_upload_streams_through(proxy, upstream):
    sock = proxy.connect()

    def run():
        upload(sock, "pypi.org", "http://pypi.org/upload")
        return answer(sock)

    body, used = measure(run)
    assert used < CEILING, f"the proxy held {used >> 20} MiB"
    assert body == f"upstream saw pypi.org and {BODY} bytes\n".encode()


def websocket(proxy, host="pypi.org"):
    """Open a WebSocket to pypi.org through a tunnel, asking for host; returns the TLS socket."""
    sock = proxy.https("pypi.org")
    sock.sendall(
        f"GET /ws HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n".encode()
        + b"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: MTIzNDU2Nzg5MGFiY2RlZg==\r\n\r\n"
    )
    head, _ = head_of(sock)
    assert head.startswith(b"HTTP/1.1 101"), head
    return sock


def frame(size):
    """A binary WebSocket frame from a client, masked with zeros so the payload reads as sent."""
    return b"\x82\xff" + struct.pack("!Q", size) + bytes(4)


def wait_for(upstream, total):
    deadline = time.monotonic() + 30
    while upstream.ws_bytes < total and time.monotonic() < deadline:
        time.sleep(0.01)
    return upstream.ws_bytes


def held(proxy):
    """How many WebSocket messages or relayed chunks the proxy's flows still hold, and their bytes."""
    kept = []
    for flow in proxy.flows.flows:
        if flow.websocket is not None:
            kept += flow.websocket.messages
    for flow in proxy.flows.tcp:
        kept += flow.messages
    return len(kept), sum(len(m.content) for m in kept)


def test_a_long_websocket_stream_is_relayed_and_not_kept(proxy, upstream):
    sock = websocket(proxy)

    def run():
        for _ in range(96):
            sock.sendall(frame(len(CHUNK)) + CHUNK)
        return wait_for(upstream, 96 * len(CHUNK))

    got, used = measure(run)
    assert got == 96 * len(CHUNK)
    assert used < CEILING, f"the proxy held {used >> 20} MiB"
    count, size = held(proxy)
    assert count <= 1 and size < 1 << 20, (count, size)


def test_one_large_websocket_message_streams_through(proxy, upstream):
    sock = websocket(proxy)

    def run():
        sock.sendall(frame(BODY))
        for _ in range(BODY // len(CHUNK)):
            sock.sendall(CHUNK)
        return wait_for(upstream, BODY)

    got, used = measure(run)
    assert got == BODY
    assert used < CEILING, f"the proxy held {used >> 20} MiB"
    count, size = held(proxy)
    assert count <= 1 and size < 1 << 20, (count, size)


def test_the_helpers_stop_when_the_proxy_closes_the_connection(proxy, upstream):
    # The proxy refuses an upgrade for another host by closing the tunnel.
    # The helper must say so, not wait for more bytes forever.
    outcome = []

    def run():
        try:
            websocket(proxy, host="www.python.org")
            outcome.append("upgraded")
        except (ConnectionError, ssl.SSLError) as e:
            outcome.append(e)

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(10)
    assert not worker.is_alive(), "the helper is still waiting on a closed connection"
    assert outcome and isinstance(outcome[0], (ConnectionError, ssl.SSLError)), outcome
