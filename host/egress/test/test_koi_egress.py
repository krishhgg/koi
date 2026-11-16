"""Unit tests for the egress policy, run with mitmproxy's own test helpers:

    /usr/local/bin/mitmdump is a frozen binary, so these run under a Python
    that has mitmproxy installed:  uv run --with mitmproxy==12.2.3 --with pytest pytest host/egress/test
"""

import logging
import os
import sys

from mitmproxy.test import taddons, tflow

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import koi_egress  # noqa: E402

ALLOW = os.path.join(os.path.dirname(__file__), "..", "allow.txt")


def addon():
    a = koi_egress.KoiEgress()
    return a


def plain_flow(host, port=80):
    """A plain HTTP request through the proxy, with no body, as pip sends one."""
    f = tflow.tflow()
    f.request.host, f.request.port = host, port
    f.request.headers.pop("content-length", None)
    f.request.headers["host"] = host
    return f


def connect_flow(host, port=443):
    f = plain_flow(host, port)
    f.request.method = "CONNECT"
    return f


def test_allows_listed_hosts_and_suffixes():
    a = addon()
    with taddons.context(a) as tctx:
        tctx.configure(a, koi_allow=ALLOW)
        for host in ["pypi.org", "files.pythonhosted.org", "cdn-lfs.huggingface.co", "x.hf.co"]:
            f = connect_flow(host)
            a.http_connect(f)
            assert f.response is None, host


def test_denies_everything_else():
    a = addon()
    with taddons.context(a) as tctx:
        tctx.configure(a, koi_allow=ALLOW)
        for host in ["example.com", "169.254.169.254", "pypi.org.evil.com", "hf.co", "evilpypi.org", "localhost"]:
            f = connect_flow(host)
            a.http_connect(f)
            assert f.response is not None and f.response.status_code == 403, host


def test_denies_other_ports_even_for_allowed_hosts():
    a = addon()
    with taddons.context(a) as tctx:
        tctx.configure(a, koi_allow=ALLOW)
        f = connect_flow("pypi.org", 22)
        a.http_connect(f)
        assert f.response.status_code == 403


def test_plain_http_follows_the_same_list():
    a = addon()
    with taddons.context(a) as tctx:
        tctx.configure(a, koi_allow=ALLOW)
        ok = plain_flow("pypi.org")
        a.requestheaders(ok)
        assert ok.response is None
        bad = plain_flow("169.254.169.254")
        a.requestheaders(bad)
        assert bad.response.status_code == 403


def test_denials_never_log_the_requested_host(caplog):
    a = addon()
    secret = "sk-ant-api03-abcdef0123456789"
    with taddons.context(a) as tctx, caplog.at_level(logging.DEBUG):
        tctx.configure(a, koi_allow=ALLOW)
        f = connect_flow(f"{secret}.example.com")
        a.http_connect(f)
        plain = plain_flow(f"{secret}.example.net")
        a.requestheaders(plain)
    assert f.response.status_code == 403 and plain.response.status_code == 403
    assert "denied" in caplog.text
    assert secret not in caplog.text


def test_a_denied_request_with_a_body_is_killed_at_its_headers():
    a = addon()
    with taddons.context(a) as tctx:
        tctx.configure(a, koi_allow=ALLOW)
        for header, value in [("content-length", "67108864"), ("transfer-encoding", "chunked")]:
            f = plain_flow("169.254.169.254")
            f.request.headers[header] = value
            a.requestheaders(f)
            assert f.response is None and f.error is not None, header


def test_allowed_requests_and_all_responses_stream():
    a = addon()
    with taddons.context(a) as tctx:
        tctx.configure(a, koi_allow=ALLOW)
        f = plain_flow("pypi.org")
        a.requestheaders(f)
        assert f.request.stream is True
        f = tflow.tflow(resp=True)
        a.responseheaders(f)
        assert f.response.stream is True


def test_the_addon_sets_the_mitmproxy_options_it_relies_on():
    a = addon()
    with taddons.context(a) as tctx:
        tctx.configure(a, koi_allow=ALLOW, websocket=True, ignore_hosts=["pypi.org"], allow_hosts=["x"])
        assert tctx.options.websocket is False
        assert list(tctx.options.ignore_hosts) == [] and list(tctx.options.allow_hosts) == []
