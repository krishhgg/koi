"""The direct path: previews whose code ignores the proxy setting, and their DNS.

Run with the other egress tests, in an environment that has mitmproxy
installed:  uv run --with mitmproxy==12.2.3 --with pytest pytest host/egress/test

On the box, the firewall redirects a preview's connections to ports 443 and
80 to the proxy's transparent listener, and mitmproxy asks the kernel where
each was going. Here that lookup returns the address a test says the preview
connected to, which is never one the proxy should use. mitmproxy's resolver
answers from a table, so no test touches the network.
"""

import http.client
import socket
import struct
import tempfile
from pathlib import Path

import pytest
from conftest import Proxy, Upstream, refused, request
from mitmproxy import dns, platform

FIXTURES = "fixtures.koi.preview.test"
# Where the preview's code connected: what an attacker would point at its own
# server, so the proxy must never connect there.
DIALED = "93.184.215.14"


class Resolver:
    """mitmproxy's resolver, answering from a table and recording every name it looks up."""

    def __init__(self, table):
        self.table = table
        self.looked_up = []

    async def lookup_ipv4(self, name):
        return self.lookup(name, 4)

    async def lookup_ipv6(self, name):
        return self.lookup(name, 6)

    def lookup(self, name, version):
        self.looked_up.append(name)
        if name not in self.table:
            raise socket.gaierror(socket.EAI_NONAME, "no such name")
        return [ip for ip in self.table[name] if (":" in ip) == (version == 6)]


def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def direct():
    dialed = {"address": (DIALED, 443)}
    saved = platform.original_addr
    platform.original_addr = lambda sock: dialed["address"]
    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        allow = workdir / "allow.txt"
        allow.write_text("pypi.org\nfiles.pythonhosted.org\n")
        upstream = Upstream(workdir)
        ports = {free_port(), free_port()}
        while len(ports) < 2:
            ports.add(free_port())
        regular, redirected = sorted(ports)
        modes = [f"regular@{regular}", f"transparent@{redirected}", f"dns@{free_port(socket.SOCK_DGRAM)}"]
        p = Proxy(workdir, upstream, allow, modes=modes, koi_fixtures=FIXTURES)
        p.dialed = dialed
        p.resolver = Resolver(
            {
                "pypi.org": ["151.101.0.223", "10.0.0.5", "2a04:4e42::223", "::ffff:10.0.0.1"],
                FIXTURES: ["198.41.0.4"],
                "files.pythonhosted.org": ["127.0.0.1", "169.254.169.254"],
            }
        )
        p.master.addons.get("dnsresolver").resolver = lambda: p.resolver
        try:
            yield p
        finally:
            p.close()
            upstream.close()
            platform.original_addr = saved


@pytest.fixture
def proxy(direct):
    direct.upstream.clear()
    direct.flows.flows.clear()
    direct.to_upstream.asked.clear()
    direct.resolver.looked_up.clear()
    direct.dialed["address"] = (DIALED, 443)
    return direct


def redirected(proxy, port=443):
    """A connection as the firewall hands one over: the preview dialed DIALED on port."""
    proxy.dialed["address"] = (DIALED, port)
    return socket.create_connection(proxy.listener("transparent"), timeout=10)


def get(sock, host, path):
    """GET on an open socket; returns the response with its body read."""
    conn = http.client.HTTPConnection(host)
    conn.sock = sock
    conn.request("GET", path, headers={"Host": host})
    response = conn.getresponse()
    response.body = response.read()
    return response


def lookup(proxy, name, qtype=dns.types.A):
    """One DNS query over UDP to the proxy's DNS listener; returns the answer."""
    labels = b"".join(bytes([len(part)]) + part.encode() for part in name.split("."))
    query = struct.pack(">HHHHHH", 0x4B1D, 0x0100, 1, 0, 0, 0) + labels + b"\0" + struct.pack(">HH", qtype, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(10)
        s.sendto(query, proxy.listener("dns"))
        return dns.DNSMessage.unpack(s.recv(4096))


def addresses(answer):
    return sorted(str(r.ipv4_address if r.type == dns.types.A else r.ipv6_address) for r in answer.answers)


# --- TLS redirected by the firewall ---------------------------------------------


def test_redirected_tls_goes_to_its_server_name_not_the_address(proxy):
    status, body = request(proxy.tls(redirected(proxy), "pypi.org"), "pypi.org")
    assert (status, body) == (200, b"upstream saw pypi.org and 0 bytes\n")
    assert proxy.to_upstream.asked == [("pypi.org", 443)]
    assert proxy.upstream.seen()[0] == ["pypi.org"]


def test_redirected_tls_to_a_name_not_allowed_is_refused(proxy):
    assert refused(lambda: request(proxy.tls(redirected(proxy), "example.com"), "example.com"))
    assert proxy.to_upstream.asked == []


def test_redirected_tls_without_a_server_name_is_refused(proxy):
    assert refused(lambda: request(proxy.tls(redirected(proxy), None), "pypi.org"))
    assert proxy.to_upstream.asked == []


def test_a_request_inside_redirected_tls_for_another_host_is_cut_off(proxy):
    sock = proxy.tls(redirected(proxy), "pypi.org")
    assert refused(lambda: request(sock, "files.pythonhosted.org"))
    assert proxy.to_upstream.asked == []


def test_redirected_tls_to_a_port_not_allowed_is_refused(proxy):
    assert refused(lambda: request(proxy.tls(redirected(proxy, 8443), "pypi.org"), "pypi.org"))
    assert proxy.to_upstream.asked == []


# --- plain HTTP redirected by the firewall --------------------------------------


def test_redirected_plain_http_goes_to_its_host_header(proxy):
    status, body = request(redirected(proxy, 80), "pypi.org")
    assert (status, body) == (200, b"upstream saw pypi.org and 0 bytes\n")
    assert proxy.to_upstream.asked == [("pypi.org", 80)]


def test_redirected_plain_http_to_a_host_not_allowed_is_denied(proxy):
    assert request(redirected(proxy, 80), "example.com") == (403, b"koi: egress is not allowed\n")
    assert proxy.to_upstream.asked == []


def test_redirected_plain_http_naming_another_port_is_denied(proxy):
    assert request(redirected(proxy, 80), "pypi.org:8080")[0] == 403
    assert proxy.to_upstream.asked == []


def test_redirected_plain_http_naming_an_address_is_denied(proxy):
    assert request(redirected(proxy, 80), DIALED)[0] == 403
    assert proxy.to_upstream.asked == []


# --- the fixtures host ----------------------------------------------------------


def test_the_fixtures_host_answers_a_redirect_to_any_url_itself(proxy):
    sock = proxy.tls(redirected(proxy), FIXTURES)
    response = get(sock, FIXTURES, "/redirect-to?url=http://example.com:99999/&status_code=301")
    assert response.status == 301
    assert response.getheader("location") == "http://example.com:99999/"
    assert proxy.to_upstream.asked == []
    assert proxy.upstream.seen() == ([], [])


def test_the_fixtures_host_answers_through_the_proxy_setting_too(proxy):
    sock = proxy.https(FIXTURES, connect=f"{FIXTURES}:443")
    assert request(sock, FIXTURES, "/status/418") == (418, b"status 418\n")
    assert proxy.to_upstream.asked == []


def test_the_fixtures_host_serves_its_pages(proxy):
    sock = proxy.tls(redirected(proxy), FIXTURES)
    assert get(sock, FIXTURES, "/").status == 200
    assert get(sock, FIXTURES, "/redirect/2").getheader("location") == "/redirect/1"
    assert get(sock, FIXTURES, "/redirect/0").body == b"redirects done\n"
    assert get(sock, FIXTURES, "/bytes/70000").body == b"x" * 70000
    assert get(sock, FIXTURES, "/delay/0.2").body == b"delayed 0.2 seconds\n"
    assert get(sock, FIXTURES, "/json").getheader("content-type") == "application/json"
    assert get(sock, FIXTURES, "/delay/11").status == 400
    assert get(sock, FIXTURES, "/bytes/99999999").status == 404
    assert get(sock, FIXTURES, "/redirect-to?url=http://a%20b/").status == 400
    assert get(sock, FIXTURES, "/nothing").status == 404
    assert proxy.to_upstream.asked == []


def test_the_fixtures_host_over_plain_http(proxy):
    assert request(redirected(proxy, 80), FIXTURES, "/status/204")[0] == 204
    assert proxy.to_upstream.asked == []


def test_the_fixtures_host_takes_no_body(proxy):
    sock = proxy.tls(redirected(proxy), FIXTURES)
    assert request(sock, FIXTURES, "/", method="POST", body=b"x")[0] == 405
    assert proxy.to_upstream.asked == []


# --- DNS ------------------------------------------------------------------------


def test_an_allowed_name_resolves_to_its_public_addresses_only(proxy):
    answer = lookup(proxy, "pypi.org")
    assert answer.response_code == dns.response_codes.NOERROR
    assert addresses(answer) == ["151.101.0.223"]


def test_an_allowed_name_has_no_ipv6_addresses_for_a_preview(proxy):
    # Previews have no IPv6 route, and the firewall redirects IPv4 only.
    answer = lookup(proxy, "pypi.org", dns.types.AAAA)
    assert answer.response_code == dns.response_codes.NOERROR
    assert answer.answers == []
    assert proxy.resolver.looked_up == []


def test_an_allowed_name_with_only_private_addresses_resolves_to_none(proxy):
    answer = lookup(proxy, "files.pythonhosted.org")
    assert answer.response_code == dns.response_codes.NOERROR
    assert answer.answers == []


def test_a_name_not_allowed_is_never_looked_up(proxy):
    answer = lookup(proxy, "secret-data.attacker.example")
    assert answer.response_code == dns.response_codes.NXDOMAIN
    assert proxy.resolver.looked_up == []


def test_an_allowed_name_gets_no_other_record_types(proxy):
    answer = lookup(proxy, "pypi.org", dns.types.TXT)
    assert answer.response_code == dns.response_codes.NOERROR
    assert answer.answers == []
    assert proxy.resolver.looked_up == []


def test_the_fixtures_host_resolves(proxy):
    assert addresses(lookup(proxy, FIXTURES)) == ["198.41.0.4"]
