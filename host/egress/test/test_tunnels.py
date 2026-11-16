"""End-to-end: what a preview can reach through a CONNECT tunnel."""

import ssl
import time

import h2.connection
import h2.events
from conftest import refused, request


def issuer(sock):
    return dict(x[0] for x in sock.getpeercert()["issuer"])["organizationName"]


def test_a_tunnel_reaches_the_host_it_named_through_koi_tls(proxy, upstream):
    sock = proxy.https("pypi.org")
    assert issuer(sock) == "mitmproxy"
    assert request(sock, "pypi.org", "/simple/") == (200, b"upstream saw pypi.org and 0 bytes\n")
    assert request(sock, "pypi.org:443", "/again") == (200, b"upstream saw pypi.org:443 and 0 bytes\n")
    snis, requests = upstream.seen()
    assert set(snis) == {"pypi.org"}
    assert [r[:2] for r in requests] == [("pypi.org", "/simple/"), ("pypi.org:443", "/again")]


def test_a_fronted_request_through_an_allowed_tunnel_is_refused(proxy, upstream):
    # The reviewer's case: CONNECT pypi.org, then TLS and HTTP for another
    # site on the same CDN.
    assert refused(lambda: request(proxy.https("www.python.org"), "www.python.org"))
    assert upstream.seen() == ([], [])


def test_a_server_name_for_another_allowed_host_is_refused(proxy, upstream):
    assert refused(lambda: request(proxy.https("files.pythonhosted.org"), "files.pythonhosted.org"))
    assert upstream.seen() == ([], [])


def test_tls_without_a_server_name_is_refused(proxy, upstream):
    assert refused(lambda: request(proxy.https(None), "pypi.org"))
    assert upstream.seen() == ([], [])


def test_a_host_header_for_another_site_is_refused(proxy, upstream):
    assert refused(lambda: request(proxy.https("pypi.org"), "www.python.org"))
    assert upstream.seen() == ([], [])


def test_an_absolute_target_for_another_site_is_refused(proxy, upstream):
    sock = proxy.https("pypi.org")
    assert refused(lambda: request(sock, "pypi.org", target="https://www.python.org/"))
    assert upstream.seen() == ([], [])


def test_every_request_in_a_tunnel_is_checked(proxy, upstream):
    sock = proxy.https("pypi.org")
    assert request(sock, "pypi.org")[0] == 200
    assert refused(lambda: request(sock, "www.python.org"))
    assert [r[0] for r in upstream.seen()[1]] == ["pypi.org"]


def test_http2_authority_is_checked(proxy, upstream):
    def h2_get(authority):
        sock = proxy.tls(proxy.tunnel("pypi.org:443")[0], "pypi.org", alpn=("h2",))
        assert sock.selected_alpn_protocol() == "h2"
        conn = h2.connection.H2Connection()
        conn.initiate_connection()
        conn.send_headers(
            1, [(":method", "GET"), (":path", "/"), (":scheme", "https"), (":authority", authority)], end_stream=True
        )
        sock.sendall(conn.data_to_send())
        while True:
            try:
                data = sock.recv(65536)
            except ConnectionError:
                return "closed"
            if not data:
                return "closed"
            for event in conn.receive_data(data):
                if isinstance(event, h2.events.ResponseReceived):
                    return dict(event.headers)[b":status"].decode()
                if isinstance(event, (h2.events.StreamReset, h2.events.ConnectionTerminated)):
                    return "reset"
            sock.sendall(conn.data_to_send())

    assert h2_get("www.python.org") in ("reset", "closed")
    assert upstream.seen()[1] == []
    assert h2_get("pypi.org") == "200"
    assert [r[0] for r in upstream.seen()[1]] == ["pypi.org"]


def test_plain_text_inside_a_tunnel_is_refused(proxy, upstream):
    sock, status = proxy.tunnel("pypi.org:443")
    assert status == 200
    assert refused(lambda: request(sock, "pypi.org"))
    assert upstream.seen() == ([], [])


def test_a_client_hello_split_before_its_third_byte_never_reaches_upstream(proxy, upstream):
    # mitmproxy tells TLS from other traffic by the first three bytes. Two
    # bytes alone must not get the tunnel relayed as raw TCP.
    context = ssl.create_default_context(cafile=str(proxy.ca))
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    try:
        context.wrap_bio(incoming, outgoing, server_hostname="www.python.org").do_handshake()
    except ssl.SSLWantReadError:
        pass
    hello = outgoing.read()
    sock, status = proxy.tunnel("pypi.org:443")
    assert status == 200
    sock.sendall(hello[:2])
    time.sleep(0.2)
    sock.sendall(hello[2:])
    sock.settimeout(1)
    try:
        sock.recv(65536)
    except OSError:
        pass
    assert upstream.seen() == ([], [])


def test_a_connect_inside_a_tunnel_goes_nowhere(proxy, upstream):
    sock = proxy.https("pypi.org")
    target = "files.pythonhosted.org:443"
    status, _ = request(sock, target, method="CONNECT", target=target)
    assert status == 400
    assert upstream.seen() == ([], [])


def test_tls_straight_to_the_proxy_is_refused(proxy, upstream):
    assert refused(lambda: request(proxy.tls(proxy.connect(), "pypi.org"), "pypi.org", target="https://pypi.org/"))
    assert upstream.seen() == ([], [])


def test_plain_http_reaches_an_allowed_host(proxy, upstream):
    status, body = request(proxy.connect(), "pypi.org", target="http://pypi.org/simple/")
    assert (status, body) == (200, b"upstream saw pypi.org and 0 bytes\n")


def test_plain_http_with_a_host_header_for_another_site_is_refused(proxy, upstream):
    status, _ = request(proxy.connect(), "www.python.org", target="http://pypi.org/")
    assert status == 403
    assert upstream.seen() == ([], [])
