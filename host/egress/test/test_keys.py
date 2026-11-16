"""Tests for the key swap: tokens, the registry and its control socket. Run with mitmproxy's helpers:

    uv run --with mitmproxy==12.2.3 --with pytest pytest host/egress/test
"""

import asyncio
import hashlib
import hmac
import json
import os
import pathlib
import re
import sys
import tempfile
import threading

from urllib.parse import quote

import pytest
from conftest import token_secret
from mitmproxy.http import Headers
from mitmproxy.test import taddons, tflow

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import koi_egress  # noqa: E402

ALLOW = os.path.join(os.path.dirname(__file__), "..", "allow.txt")
# Shaped like a token, but no registry made it.
TOKEN = "koi_" + "a" * 32
OTHER = "koi_" + "b" * 32
LABEL = "storefront-pr-7"
# The address of LABEL's container, as koid maps it.
PREVIEW_IP = "172.19.0.5"
# A token secret for registries made directly, as the box's is 32 bytes.
SECRET = bytes(range(32))


@pytest.fixture
def egress(tmp_path):
    a = koi_egress.KoiEgress()
    with taddons.context(a) as tctx:
        tctx.configure(a, koi_allow=ALLOW, koi_secret=str(token_secret(tmp_path)))
        a.set_previews({PREVIEW_IP: LABEL})
        yield a


def register(egress, provider, key, label=LABEL):
    """Register one key; returns the token the registry made for it."""
    return egress.registry.register(label, {provider: key}, "198.51.100.1")[provider]


def provider_flow(egress, host, headers=None, query=None, path="/v1/x", ip=PREVIEW_IP):
    """A bodiless HTTPS request from the container at ip, inside a tunnel the proxy accepted for host."""
    f = tflow.tflow()
    f.client_conn.peername = (ip, 40000)
    f.client_conn.tls = True
    f.client_conn.sni = host
    egress.tunnels[f.client_conn.id] = host
    f.request.host = host
    f.request.port = 443
    f.request.scheme = "https"
    f.request.path = path
    f.request.headers.pop("content-length", None)
    f.request.headers["host"] = host
    for k, v in (headers or {}).items():
        f.request.headers[k] = v
    for k, v in (query or {}).items():
        f.request.query[k] = v
    return f


def test_providers_are_always_allowed(egress):
    for host in koi_egress.PROVIDERS:
        f = tflow.tflow()
        f.request.method = "CONNECT"
        f.request.host, f.request.port = host, 443
        egress.http_connect(f)
        assert f.response is None, host


class TestSwap:
    def test_swaps_a_bearer_token_for_the_registered_key(self, egress):
        token = register(egress, "openai", "sk-real-openai")
        f = provider_flow(egress, "api.openai.com", {"authorization": f"Bearer {token}"})
        egress.requestheaders(f)
        assert f.response is None
        assert f.request.headers["authorization"] == "Bearer sk-real-openai"

    def test_swaps_x_api_key_and_gemini_header_and_query(self, egress):
        tokens = egress.registry.register(LABEL, {"anthropic": "sk-ant-real", "gemini": "AIza-real"}, "x")
        a = provider_flow(egress, "api.anthropic.com", {"x-api-key": tokens["anthropic"]})
        egress.requestheaders(a)
        assert a.request.headers["x-api-key"] == "sk-ant-real"
        g = provider_flow(egress, "generativelanguage.googleapis.com", {"x-goog-api-key": tokens["gemini"]})
        egress.requestheaders(g)
        assert g.request.headers["x-goog-api-key"] == "AIza-real"
        for path in ["/v1beta/models/gemini-pro:generateContent", "/upload/v1beta/files"]:
            q = provider_flow(egress, "generativelanguage.googleapis.com", query={"key": tokens["gemini"]}, path=path)
            egress.requestheaders(q)
            assert q.request.query["key"] == "AIza-real", path

    def test_swaps_a_token_given_after_its_providers_key_prefix(self, egress):
        # Some apps refuse a key that does not begin like the provider's
        # own, so the keys page shows tokens after that prefix.
        tokens = egress.registry.register(
            LABEL, {"openai": "sk-real-openai", "anthropic": "sk-ant-real", "xai": "xai-real"}, "x"
        )
        a = provider_flow(egress, "api.anthropic.com", {"x-api-key": f"sk-ant-{tokens['anthropic']}"})
        egress.requestheaders(a)
        assert a.response is None and a.request.headers["x-api-key"] == "sk-ant-real"
        o = provider_flow(egress, "api.openai.com", {"authorization": f"Bearer sk-{tokens['openai']}"})
        egress.requestheaders(o)
        assert o.response is None and o.request.headers["authorization"] == "Bearer sk-real-openai"
        x = provider_flow(egress, "api.x.ai", {"authorization": f"Bearer xai-{tokens['xai']}"})
        egress.requestheaders(x)
        assert x.response is None and x.request.headers["authorization"] == "Bearer xai-real"

    def test_a_prefix_does_not_make_a_token_good_for_another_provider(self, egress):
        tokens = egress.registry.register(LABEL, {"openai": "sk-real-openai"}, "x")
        f = provider_flow(egress, "api.anthropic.com", {"x-api-key": f"sk-ant-{tokens['openai']}"})
        egress.requestheaders(f)
        assert f.response.status_code == 401
        assert b"for openai, not anthropic" in f.response.content
        assert b"sk-real-openai" not in f.response.content

    def test_a_token_works_only_for_its_provider(self, egress):
        tokens = egress.registry.register(LABEL, {"openai": "sk-real-openai", "anthropic": "sk-ant-real"}, "x")
        f = provider_flow(egress, "api.openai.com", {"authorization": f"bearer {tokens['openai']}"})
        egress.requestheaders(f)
        assert f.request.headers["authorization"] == "Bearer sk-real-openai"
        f = provider_flow(egress, "api.anthropic.com", {"x-api-key": tokens["openai"]})
        egress.requestheaders(f)
        assert f.response.status_code == 401
        assert b"for openai, not anthropic" in f.response.content
        assert f.request.headers["x-api-key"] == tokens["openai"]

    @pytest.mark.parametrize(
        "host,headers,query,path",
        [
            # The reviewer's case: OpenRouter takes its key in Authorization only.
            ("openrouter.ai", {}, {"key": TOKEN}, "/api/v1/models/"),
            ("api.openai.com", {"x-api-key": TOKEN}, {}, "/v1/models"),
            ("api.openai.com", {}, {"key": TOKEN}, "/v1/models"),
            ("api.anthropic.com", {"authorization": f"Bearer {TOKEN}"}, {}, "/v1/messages"),
            ("generativelanguage.googleapis.com", {"authorization": f"Bearer {TOKEN}"}, {}, "/v1beta/models"),
            # Gemini reads ?key= on its API paths only.
            ("generativelanguage.googleapis.com", {}, {"key": TOKEN}, "/"),
            ("generativelanguage.googleapis.com", {}, {"key": TOKEN}, "/v1betax/models"),
            # Only a token that is the whole credential.
            ("api.openai.com", {"authorization": f"Bearer {TOKEN} extra"}, {}, "/v1/models"),
            ("api.openai.com", {"authorization": f"Basic {TOKEN}"}, {}, "/v1/models"),
            ("api.openai.com", {"authorization": TOKEN}, {}, "/v1/models"),
            ("api.anthropic.com", {"x-api-key": f"x{TOKEN}"}, {}, "/v1/messages"),
            ("api.anthropic.com", {"x-api-key": f"sk-ant-x{TOKEN}"}, {}, "/v1/messages"),
            ("api.openai.com", {"authorization": f"Bearer pk-{TOKEN}"}, {}, "/v1/models"),
            ("api.openai.com", {"x-custom": TOKEN}, {}, "/v1/models"),
        ],
    )
    def test_swaps_nowhere_but_the_providers_documented_field(self, egress, host, headers, query, path):
        # TOKEN stands for the host's own, valid, token.
        provider = koi_egress.PROVIDERS[host]
        token = register(egress, provider, f"real-{provider}-key")
        headers = {k: v.replace(TOKEN, token) for k, v in headers.items()}
        query = {k: v.replace(TOKEN, token) for k, v in query.items()}
        f = provider_flow(egress, host, headers, query, path)
        before = (f.request.url, list(f.request.headers.fields))
        egress.requestheaders(f)
        assert f.response is None
        assert (f.request.url, list(f.request.headers.fields)) == before
        assert egress.substituted.get(f) is None

    def test_every_provider_says_where_its_key_goes(self):
        assert set(koi_egress.AUTH) == set(koi_egress.PROVIDERS.values())

    def test_asks_for_an_unencoded_response_when_a_key_went_up(self, egress):
        token = register(egress, "openai", "sk-real-openai")
        f = provider_flow(egress, "api.openai.com", {"authorization": f"Bearer {token}", "accept-encoding": "gzip, br"})
        egress.requestheaders(f)
        assert f.request.headers["accept-encoding"] == "identity"

    def test_refuses_an_unknown_token_with_instructions(self, egress):
        f = provider_flow(egress, "api.openai.com", {"authorization": f"Bearer {OTHER}"})
        egress.requestheaders(f)
        assert f.response.status_code == 401
        assert b"registers your keys again with the same tokens" in f.response.content
        assert OTHER.encode() not in f.response.content

    def test_leaves_requests_without_a_token_alone(self, egress):
        f = provider_flow(egress, "api.openai.com", {"authorization": "Bearer sk-reviewer-typed-this"})
        egress.requestheaders(f)
        assert f.response is None
        assert f.request.headers["authorization"] == "Bearer sk-reviewer-typed-this"

    def test_never_swaps_for_hosts_that_are_not_providers(self, egress):
        token = register(egress, "openai", "sk-real-openai")
        f = provider_flow(egress, "evil.example.com", {"authorization": f"Bearer {token}"})
        egress.requestheaders(f)
        assert f.request.headers["authorization"] == f"Bearer {token}"

    def test_caps_requests_per_hour(self):
        now = [0.0]
        registry = koi_egress.Registry(SECRET, clock=lambda: now[0])
        token = registry.register(LABEL, {"openai": "k"})["openai"]
        for _ in range(koi_egress.REQUESTS_PER_HOUR):
            assert registry.key_for(token, "openai", LABEL)[0] == "k"
        key, reason = registry.key_for(token, "openai", LABEL)
        assert key is None and "requests this hour" in reason
        now[0] += 3600
        assert registry.key_for(token, "openai", LABEL)[0] == "k"

    def test_registrations_expire(self):
        now = [0.0]
        registry = koi_egress.Registry(SECRET, clock=lambda: now[0])
        token = registry.register(LABEL, {"openai": "k"})["openai"]
        now[0] += koi_egress.REGISTRATION_TTL_SECONDS + 1
        assert registry.key_for(token, "openai", LABEL)[0] is None


class TestPreviewScope:
    """A token works only from the container of the preview it was registered for."""

    def test_works_from_its_own_preview(self, egress):
        token = register(egress, "openai", "sk-real-openai")
        f = provider_flow(egress, "api.openai.com", {"authorization": f"Bearer {token}"}, ip=PREVIEW_IP)
        egress.requestheaders(f)
        assert f.response is None
        assert f.request.headers["authorization"] == "Bearer sk-real-openai"

    def test_refused_from_another_preview(self, egress):
        egress.set_previews({PREVIEW_IP: LABEL, "172.19.0.9": "evil-pr-8"})
        token = register(egress, "openai", "sk-real-openai")
        f = provider_flow(egress, "api.openai.com", {"authorization": f"Bearer {token}"}, ip="172.19.0.9")
        egress.requestheaders(f)
        assert f.response.status_code == 401
        assert b"another preview" in f.response.content
        assert f.request.headers["authorization"] == f"Bearer {token}"

    def test_refused_from_an_address_no_preview_has(self, egress):
        token = register(egress, "openai", "sk-real-openai")
        for ip in ["172.19.0.77", "127.0.0.1"]:
            f = provider_flow(egress, "api.openai.com", {"authorization": f"Bearer {token}"}, ip=ip)
            egress.requestheaders(f)
            assert f.response.status_code == 401, ip
            assert f.request.headers["authorization"] == f"Bearer {token}"

    def test_the_mapping_follows_a_container_restart_to_a_new_address(self, egress):
        token = register(egress, "openai", "sk-real-openai")
        egress.set_previews({"172.19.0.6": LABEL})
        old = provider_flow(egress, "api.openai.com", {"authorization": f"Bearer {token}"}, ip=PREVIEW_IP)
        egress.requestheaders(old)
        assert old.response.status_code == 401
        new = provider_flow(egress, "api.openai.com", {"authorization": f"Bearer {token}"}, ip="172.19.0.6")
        egress.requestheaders(new)
        assert new.response is None
        assert new.request.headers["authorization"] == "Bearer sk-real-openai"

    def test_an_ipv4_address_written_as_ipv6_is_the_same_container(self, egress):
        token = register(egress, "openai", "sk-real-openai")
        f = provider_flow(egress, "api.openai.com", {"authorization": f"Bearer {token}"}, ip=f"::ffff:{PREVIEW_IP}")
        egress.requestheaders(f)
        assert f.response is None

    @pytest.mark.parametrize(
        "previews",
        [None, [], {"not-an-ip": LABEL}, {PREVIEW_IP: "Bad_Label"}, {PREVIEW_IP: 7}],
    )
    def test_refuses_a_bad_mapping_and_keeps_the_last(self, egress, previews):
        with pytest.raises(ValueError):
            egress.set_previews(previews)
        assert egress.previews == {PREVIEW_IP: LABEL}


class TestRegistration:
    @pytest.mark.parametrize(
        "label,keys",
        [
            ("Bad_Label", {"openai": "k"}),
            (None, {"openai": "k"}),
            ("x" * 64, {"openai": "k"}),
            (LABEL, {}),
            (LABEL, None),
            (LABEL, {"notaprovider": "k"}),
            (LABEL, {"openai": ""}),
            (LABEL, {"openai": "k\r\nX-Injected: 1"}),
            (LABEL, {"openai": "k" * 513}),
        ],
    )
    def test_rejects_bad_input(self, label, keys):
        with pytest.raises(ValueError):
            koi_egress.Registry(SECRET).register(label, keys)

    def test_one_token_per_key_and_the_same_one_again(self):
        registry = koi_egress.Registry(SECRET)
        first = registry.register(LABEL, {"openai": "k1", "anthropic": "k2"})
        again = registry.register(LABEL, {"openai": "k1"})
        other = registry.register(LABEL, {"openai": "k3"})
        tokens = [first["openai"], first["anthropic"], other["openai"]]
        assert all(koi_egress.TOKEN_RE.fullmatch(t) for t in tokens)
        assert len(set(tokens)) == 3
        assert again["openai"] == first["openai"]
        assert len(registry.entries) == 3
        assert registry.entries[first["anthropic"]]["provider"] == "anthropic"
        assert {e["label"] for e in registry.entries.values()} == {LABEL}

    def test_registering_again_renews_the_registration_and_keeps_the_count(self):
        now = [0.0]
        registry = koi_egress.Registry(SECRET, clock=lambda: now[0])
        token = registry.register(LABEL, {"openai": "k"}, "198.51.100.1")["openai"]
        for _ in range(3):
            registry.key_for(token, "openai", LABEL)
        now[0] += koi_egress.REGISTRATION_TTL_SECONDS - 1
        assert registry.register(LABEL, {"openai": "k"}, "198.51.100.2")["openai"] == token
        entry = registry.entries[token]
        assert entry["expires"] == now[0] + koi_egress.REGISTRATION_TTL_SECONDS
        assert entry["count"] == 3
        assert entry["source"] == "198.51.100.2"
        # Still the same token after it expired and went.
        now[0] += koi_egress.REGISTRATION_TTL_SECONDS + 1
        assert registry.key_for(token, "openai", LABEL)[0] is None
        assert registry.register(LABEL, {"openai": "k"})["openai"] == token
        assert registry.key_for(token, "openai", LABEL)[0] == "k"

    def test_a_registry_without_a_secret_makes_no_token(self):
        with pytest.raises(ValueError, match="no token secret"):
            koi_egress.Registry().register(LABEL, {"openai": "k"})
        for bad in [b"", b"x" * 31, b"x" * 33, "x" * 32]:
            with pytest.raises(ValueError, match="no token secret"):
                koi_egress.Registry(bad).register(LABEL, {"openai": "k"})

    def test_control_socket_registers_maps_and_forgets(self):
        async def scenario():
            a = koi_egress.KoiEgress()
            a.registry.secret = SECRET
            path = os.path.join(tempfile.mkdtemp(), "control.sock")
            server = await asyncio.start_unix_server(a.handle_control, path=path)

            async def send(obj):
                reader, writer = await asyncio.open_unix_connection(path)
                writer.write((json.dumps(obj) + "\n").encode())
                await writer.drain()
                reply = json.loads(await reader.readline())
                writer.close()
                return reply

            # A caller's token is not used: the registry makes its own.
            reply = await send({"op": "register", "token": TOKEN, "label": LABEL, "keys": {"openai": "k"}})
            assert reply["ok"] is True and set(reply["tokens"]) == {"openai"}
            token = reply["tokens"]["openai"]
            assert token != TOKEN and TOKEN not in a.registry.entries
            assert a.registry.key_for(token, "openai", LABEL)[0] == "k"
            bad = await send({"op": "register", "label": "nope_", "keys": {"openai": "k"}})
            assert bad["ok"] is False
            assert await send({"op": "previews", "previews": {PREVIEW_IP: LABEL}}) == {"ok": True}
            assert a.previews == {PREVIEW_IP: LABEL}
            assert (await send({"op": "previews", "previews": {"x": LABEL}}))["ok"] is False
            assert await send({"op": "previews", "previews": {}}) == {"ok": True}
            assert a.previews == {}
            assert await send({"op": "forget", "token": token}) == {"ok": True}
            assert a.registry.key_for(token, "openai", LABEL)[0] is None
            assert (await send([1]))["ok"] is False
            server.close()

        asyncio.run(scenario())


class TestRegistryLimits:
    def test_caps_tokens_in_all(self, monkeypatch):
        monkeypatch.setattr(koi_egress, "MAX_TOKENS", 3)
        registry = koi_egress.Registry(SECRET)
        # Each registration is a different key, so a different token.
        tokens = [registry.register(LABEL, {"openai": f"k{i}"}, f"198.51.100.{i}")["openai"] for i in range(2)]
        with pytest.raises(ValueError, match="as many koi tokens as it can"):
            registry.register(LABEL, {"openai": "k3", "anthropic": "k3"}, "198.51.100.3")
        registry.register(LABEL, {"openai": "k3"}, "198.51.100.3")
        with pytest.raises(ValueError, match="as many koi tokens as it can"):
            registry.register(LABEL, {"openai": "k4"}, "198.51.100.4")
        # A key already registered takes no room; a forgotten one makes room.
        registry.register(LABEL, {"openai": "k3"}, "198.51.100.4")
        registry.forget(tokens[0])
        registry.register(LABEL, {"openai": "k4"}, "198.51.100.4")
        assert len(registry.entries) == 3

    def test_caps_tokens_per_source(self, monkeypatch):
        monkeypatch.setattr(koi_egress, "MAX_TOKENS_PER_SOURCE", 2)
        registry = koi_egress.Registry(SECRET)
        registry.register(LABEL, {"openai": "k1"}, "198.51.100.1")
        with pytest.raises(ValueError, match="from this address"):
            registry.register(LABEL, {"openai": "k2", "anthropic": "k2"}, "198.51.100.1")
        registry.register(LABEL, {"openai": "k2"}, "198.51.100.1")
        with pytest.raises(ValueError, match="from this address"):
            registry.register(LABEL, {"openai": "k3"}, "198.51.100.1")
        # The same keys again take no room.
        registry.register(LABEL, {"openai": "k1"}, "198.51.100.1")
        registry.register(LABEL, {"openai": "k3"}, "2001:db8:1:2::/64")

    def test_a_token_registered_again_from_another_address_counts_there(self, monkeypatch):
        # The token moves to the new address, so the
        # check counts it there; registered again from its own address it
        # stays free, even at the cap.
        monkeypatch.setattr(koi_egress, "MAX_TOKENS_PER_SOURCE", 2)
        registry = koi_egress.Registry(SECRET)
        registry.register(LABEL, {"openai": "k1", "anthropic": "k1"}, "198.51.100.1")
        registry.register(LABEL, {"openai": "k2", "anthropic": "k2"}, "198.51.100.2")
        registry.register(LABEL, {"openai": "k2", "anthropic": "k2"}, "198.51.100.2")
        with pytest.raises(ValueError, match="from this address"):
            registry.register(LABEL, {"openai": "k1"}, "198.51.100.2")
        assert registry.held_by("198.51.100.2") == 2
        # With room, the token moves and counts at its new address.
        registry.forget(registry.register(LABEL, {"openai": "k2"}, "198.51.100.2")["openai"])
        registry.register(LABEL, {"openai": "k1"}, "198.51.100.2")
        assert registry.held_by("198.51.100.2") == 2
        assert registry.held_by("198.51.100.1") == 1
        with pytest.raises(ValueError, match="from this address"):
            registry.register(LABEL, {"anthropic": "k1"}, "198.51.100.2")
        registry.register(LABEL, {"openai": "k1", "anthropic": "k2"}, "198.51.100.2")

    def test_expired_tokens_make_room(self, monkeypatch):
        monkeypatch.setattr(koi_egress, "MAX_TOKENS", 1)
        now = [0.0]
        registry = koi_egress.Registry(SECRET, clock=lambda: now[0])
        registry.register(LABEL, {"openai": "k1"}, "198.51.100.1")
        now[0] += koi_egress.REGISTRATION_TTL_SECONDS + 1
        token = registry.register(LABEL, {"openai": "k2"}, "198.51.100.2")["openai"]
        assert list(registry.entries) == [token]

    @pytest.mark.parametrize("source", [5, ["x"], "x" * 65])
    def test_rejects_a_bad_source(self, source):
        with pytest.raises(ValueError, match="bad source"):
            koi_egress.Registry(SECRET).register(LABEL, {"openai": "k"}, source)

    def test_removes_expired_tokens_on_a_timer(self):
        async def scenario():
            now = [0.0]
            registry = koi_egress.Registry(SECRET, clock=lambda: now[0], sweep_seconds=0.01)
            registry.register(LABEL, {"openai": "k", "anthropic": "k"}, "198.51.100.1")
            await asyncio.sleep(0.05)
            assert len(registry.entries) == 2
            now[0] += koi_egress.REGISTRATION_TTL_SECONDS + 1
            await asyncio.sleep(0.05)
            # Gone without anyone using or registering a token, and the
            # timer stops once there is nothing left to expire.
            assert registry.entries == {}
            assert registry.sweeper is None

        asyncio.run(scenario())

    def test_clear_drops_every_key_and_the_secret_and_stops_the_timer(self):
        async def scenario():
            registry = koi_egress.Registry(SECRET, sweep_seconds=60)
            registry.register(LABEL, {"openai": "k"}, "198.51.100.1")
            timer = registry.sweeper
            assert timer is not None
            registry.clear()
            assert registry.entries == {}
            assert registry.secret is None
            assert registry.sweeper is None and timer.cancelled()

        asyncio.run(scenario())

    def test_control_socket_passes_the_source_and_refusals(self, monkeypatch):
        monkeypatch.setattr(koi_egress, "MAX_TOKENS_PER_SOURCE", 1)

        async def scenario():
            a = koi_egress.KoiEgress()
            a.registry.secret = SECRET
            path = os.path.join(tempfile.mkdtemp(), "control.sock")
            server = await asyncio.start_unix_server(a.handle_control, path=path)

            async def send(obj):
                reader, writer = await asyncio.open_unix_connection(path)
                writer.write((json.dumps(obj) + "\n").encode())
                await writer.drain()
                reply = json.loads(await reader.readline())
                writer.close()
                return reply

            first = {"op": "register", "label": LABEL, "keys": {"openai": "k"}, "source": "198.51.100.1"}
            token = (await send(first))["tokens"]["openai"]
            assert a.registry.entries[token]["source"] == "198.51.100.1"
            second = await send({**first, "keys": {"openai": "k2"}})
            assert second["ok"] is False and "from this address" in second["error"]
            server.close()

        asyncio.run(scenario())


class TestDerivation:
    """A token is an HMAC of the key, its provider and the preview under the box's secret."""

    ARGS = ("openai", LABEL, "sk-real-key")

    def test_the_same_inputs_give_the_same_token(self):
        token = koi_egress.derive_token(SECRET, *self.ARGS)
        assert koi_egress.derive_token(SECRET, *self.ARGS) == token
        assert koi_egress.Registry(SECRET).register(LABEL, {"openai": "sk-real-key"})["openai"] == token

    def test_a_token_is_koi_and_32_characters_of_lowercase_base32(self):
        token = koi_egress.derive_token(SECRET, *self.ARGS)
        assert len(token) == 36
        assert re.fullmatch(r"koi_[a-z2-7]{32}", token)
        assert koi_egress.TOKEN_RE.fullmatch(token)
        assert koi_egress.BEARER_RE.fullmatch(f"Bearer {token}")
        assert koi_egress.TOKEN_BYTES * 8 >= 128

    @pytest.mark.parametrize(
        "change",
        [
            {"provider": "anthropic"},
            {"label": "storefront-pr-8"},
            {"key": "sk-real-keY"},
            {"key": "sk-real-key "},
            {"secret": bytes(range(1, 33))},
            {"secret": bytes(range(31)) + b"\x00"},
        ],
    )
    def test_any_change_in_the_inputs_or_the_secret_gives_another_token(self, change):
        args = {"secret": SECRET, "provider": "openai", "label": LABEL, "key": "sk-real-key"}
        assert koi_egress.derive_token(**{**args, **change}) != koi_egress.derive_token(**args)

    def test_fields_cannot_run_into_each_other(self):
        # Each field goes in behind its length, so moving characters between
        # the label and the key, or the provider and the label, changes the
        # token: "ab" + "c" and "a" + "bc" are different registrations.
        assert koi_egress.derive_token(SECRET, "openai", "ab", "c") != koi_egress.derive_token(SECRET, "openai", "a", "bc")
        assert koi_egress.derive_token(SECRET, "openai", "a", "b") != koi_egress.derive_token(SECRET, "openaia", "", "b")
        assert koi_egress.derive_token(SECRET, "openai", "a", "") != koi_egress.derive_token(SECRET, "openai", "", "a")

    def test_the_format_is_pinned(self):
        # Written out in full: a change here invalidates every token on the
        # box, so it must be deliberate (and the secret's domain must stay
        # this proxy's own).
        message = (
            b"koi token v1"
            + b"\x00\x00\x00\x06openai"
            + b"\x00\x00\x00\x0fstorefront-pr-7"
            + b"\x00\x00\x00\x0bsk-real-key"
        )
        digest = hmac.new(SECRET, message, hashlib.sha256).digest()[:20]
        expected = "koi_" + "".join(
            "abcdefghijklmnopqrstuvwxyz234567"[int(bits, 2)]
            for bits in re.findall(".{5}", "".join(f"{b:08b}" for b in digest))
        )
        assert koi_egress.derive_token(SECRET, *self.ARGS) == expected

    def test_a_token_says_nothing_about_the_key_without_the_secret(self):
        # Two keys that differ in one character get tokens that share no
        # more than chance, and the secret is nowhere in the token.
        a = koi_egress.derive_token(SECRET, "openai", LABEL, "sk-real-key-1")
        b = koi_egress.derive_token(SECRET, "openai", LABEL, "sk-real-key-2")
        assert sum(x == y for x, y in zip(a[4:], b[4:])) < 10
        assert SECRET.hex() not in a and "sk-real" not in a


class TestSecretFile:
    """The proxy takes its secret only from a file that is its own, and the right size."""

    def test_reads_a_well_kept_file(self, tmp_path):
        path = token_secret(tmp_path, SECRET)
        assert koi_egress.load_secret(str(path)) == SECRET

    @pytest.mark.parametrize("size", [0, 31, 33, 64])
    def test_refuses_the_wrong_size(self, tmp_path, size):
        path = token_secret(tmp_path, b"x" * size)
        with pytest.raises(ValueError, match="not 32 bytes"):
            koi_egress.load_secret(str(path))

    @pytest.mark.parametrize("mode", [0o600, 0o700, 0o440, 0o640, 0o604, 0o660, 0o666, 0o644, 0o610, 0o601])
    def test_refuses_any_mode_but_0400(self, tmp_path, mode):
        # Not even its owner may write it: the proxy's own user, which a
        # compromised proxy would be, cannot change the secret under root.
        path = token_secret(tmp_path, SECRET)
        path.chmod(mode)
        with pytest.raises(ValueError, match="not 0400") as e:
            koi_egress.load_secret(str(path))
        assert f"{mode:04o}" in str(e.value)
        assert SECRET.hex() not in str(e.value)

    def test_refuses_a_missing_file_a_symlink_a_directory_and_no_path(self, tmp_path):
        with pytest.raises(OSError):
            koi_egress.load_secret(str(tmp_path / "missing"))
        link = tmp_path / "link"
        link.symlink_to(token_secret(tmp_path, SECRET))
        with pytest.raises(OSError):
            koi_egress.load_secret(str(link))
        with pytest.raises((OSError, ValueError)):
            koi_egress.load_secret(str(tmp_path))
        with pytest.raises(ValueError, match="no token secret file"):
            koi_egress.load_secret("")

    def test_refuses_a_fifo_without_waiting_on_it(self, tmp_path):
        # Opening a FIFO with no writer blocks until one comes; the proxy
        # would hang at load and never say what is wrong.
        fifo = tmp_path / "fifo"
        os.mkfifo(fifo, 0o400)
        outcome = []

        def attempt():
            try:
                koi_egress.load_secret(str(fifo))
            except Exception as e:  # noqa: BLE001
                outcome.append(e)

        worker = threading.Thread(target=attempt, daemon=True)
        worker.start()
        worker.join(5)
        assert not worker.is_alive(), "load_secret hung on the FIFO"
        assert isinstance(outcome[0], ValueError) and "not a regular file" in str(outcome[0])

    def test_the_default_path_is_where_install_sh_puts_it(self):
        text = (pathlib.Path(__file__).parent.parent / "install.sh").read_text()
        assert f"secret=$secret_dir/token-secret" in text
        assert "secret_dir=" + os.path.dirname(koi_egress.SECRET_PATH) + "\n" in text
        assert f"--set koi_secret={koi_egress.SECRET_PATH} " in text

    def test_a_bad_secret_leaves_the_policy_without_one(self, tmp_path):
        # configure logs what is wrong and leaves the registry without a
        # secret; running() then keeps the proxy down (test_failclosed.py).
        a = koi_egress.KoiEgress()
        with taddons.context(a) as tctx:
            tctx.configure(a, koi_allow=ALLOW, koi_secret=str(token_secret(tmp_path, b"short")))
            assert a.ready is True
            assert a.registry.secret is None
            with pytest.raises(ValueError, match="no token secret"):
                a.registry.register(LABEL, {"openai": "k"})
            tctx.configure(a, koi_secret=str(token_secret(tmp_path, SECRET, name="good")))
            assert a.registry.secret == SECRET


KEY = "sk-real-key/with+odd=chars"


def swapped_flow(egress):
    """A flow the proxy swapped KEY into for its token, with its response's headers in; returns (flow, token)."""
    token = register(egress, "openai", KEY)
    f = provider_flow(egress, "api.openai.com", {"authorization": f"Bearer {token}"})
    egress.requestheaders(f)
    assert f.request.headers["authorization"] == f"Bearer {KEY}"
    f.response = tflow.tresp()
    return f, token


def body_through(stream, body, cuts):
    """What a stream callable passes on for body cut at the given offsets."""
    out = []
    edges = [0, *cuts, len(body)]
    for start, end in zip(edges, edges[1:]):
        chunks = stream(body[start:end])
        assert b"" not in chunks
        out += chunks
    out += stream(b"")
    return b"".join(out)


class TestScrub:
    def test_a_redirect_gets_the_token_back_not_the_key(self, egress):
        f, token = swapped_flow(egress)
        f.response.status_code = 301
        f.response.headers["location"] = f"https://api.openai.com/v1/models/?key={KEY}"
        f.response.headers[f"x-echo-{KEY}"] = f"Bearer {KEY}"
        egress.responseheaders(f)
        assert f.response.headers["location"] == f"https://api.openai.com/v1/models/?key={token}"
        assert f.response.headers[f"x-echo-{token}"] == f"Bearer {token}"
        assert KEY.encode() not in b"".join(n + v for n, v in f.response.headers.fields)

    def test_a_url_encoded_key_is_replaced_too(self, egress):
        f, token = swapped_flow(egress)
        f.response.headers["location"] = "https://x/?key=" + quote(KEY, safe="")
        egress.responseheaders(f)
        assert f.response.headers["location"] == f"https://x/?key={token}"

    def test_a_body_is_scrubbed_wherever_chunks_split_the_key(self, egress):
        body = f'{{"error": "bad key {KEY}", "again": "{KEY}"}}'.encode()
        for cut in [*range(1, len(body)), None]:
            f, token = swapped_flow(egress)
            egress.responseheaders(f)
            cuts = list(range(1, len(body))) if cut is None else [cut]
            assert body_through(f.response.stream, body, cuts) == body.replace(KEY.encode(), token.encode()), cut

    def test_a_chunk_that_cannot_begin_the_key_goes_on_at_once(self, egress):
        # Server-sent events: each one reaches the preview when it arrives,
        # not when the next one does.
        f, token = swapped_flow(egress)
        egress.responseheaders(f)
        stream = f.response.stream
        for event in [b'data: {"delta": "Hel"}\n\n', b'data: {"delta": "lo"}\n\n', b"data: [DONE]\n\n"]:
            assert stream(event) == [event]
        assert stream(b"") == []

    def test_only_a_tail_that_could_begin_the_key_waits(self, egress):
        f, token = swapped_flow(egress)
        egress.responseheaders(f)
        stream = f.response.stream
        # "sk-re" could begin KEY, so it waits; the rest goes on.
        assert stream(b"error: sk-re") == [b"error: "]
        assert stream(b"al-key/with+odd=chars!") == [token.encode() + b"!"]
        # "sk-x" cannot: nothing waits.
        assert stream(b"error: sk-x") == [b"error: sk-x"]

    def test_a_scrubbed_body_goes_without_a_length(self, egress):
        f, token = swapped_flow(egress)
        f.response.headers["content-length"] = "7"
        egress.responseheaders(f)
        assert "content-length" not in f.response.headers
        assert f.response.headers["transfer-encoding"] == "chunked"

    def test_an_encoded_response_is_dropped(self, egress):
        f, token = swapped_flow(egress)
        f.response.headers["content-encoding"] = "gzip"
        egress.responseheaders(f)
        assert f.error is not None

    def test_trailers_are_scrubbed(self, egress):
        f, token = swapped_flow(egress)
        egress.responseheaders(f)
        f.response.trailers = Headers([(b"x-echo", KEY.encode())])
        egress.response(f)
        assert f.response.trailers["x-echo"] == token

    def test_responses_to_other_requests_pass_untouched(self, egress):
        f = provider_flow(egress, "api.openai.com", {"authorization": "Bearer sk-typed-by-hand"})
        egress.requestheaders(f)
        f.response = tflow.tresp()
        f.response.headers["location"] = "sk-typed-by-hand"
        egress.responseheaders(f)
        assert f.response.stream is True
        assert f.response.headers["location"] == "sk-typed-by-hand"
        assert f.response.headers["content-length"] == str(len(f.response.content))


class TestVerified:
    """A key goes only into HTTPS on 443 where every name is the provider's."""

    @pytest.mark.parametrize(
        "change",
        [
            "plain http",
            "server name",
            "port 80 in the tunnel",
        ],
    )
    def test_no_key_and_a_refusal_when_a_name_or_the_scheme_differs(self, egress, change):
        token = register(egress, "groq", "gsk-real")
        f = provider_flow(egress, "api.groq.com", {"authorization": f"Bearer {token}"})
        if change == "plain http":
            egress.tunnels.pop(f.client_conn.id)
            f.client_conn.tls = False
            f.client_conn.sni = None
            f.request.scheme, f.request.port = "http", 80
        elif change == "server name":
            f.client_conn.sni = "www.cloudflare.com"
        else:
            f.request.port = 80
        egress.requestheaders(f)
        assert f.response is not None and f.response.status_code == 403
        assert f.request.headers["authorization"] == f"Bearer {token}"

    def test_plain_http_with_no_token_passes(self, egress):
        f = provider_flow(egress, "api.groq.com", {"authorization": "Bearer gsk-typed-by-hand"})
        egress.tunnels.pop(f.client_conn.id)
        f.client_conn.tls, f.client_conn.sni = False, None
        f.request.scheme, f.request.port = "http", 80
        egress.requestheaders(f)
        assert f.response is None and f.request.stream is True


class TestUpgrades:
    """WebSockets are relayed as raw bytes after the 101, which nothing scrubs, so no key goes into one."""

    UPGRADE = {"connection": "Upgrade", "upgrade": "websocket", "sec-websocket-version": "13"}

    @pytest.mark.parametrize(
        "host,where,path",
        [
            # OpenAI's Realtime API authenticates the upgrade with a Bearer token...
            ("api.openai.com", "authorization", "/v1/realtime"),
            # ...or, from a browser, with a subprotocol that carries it.
            ("api.openai.com", "sec-websocket-protocol", "/v1/realtime"),
            # Gemini's Live API takes ?key= on its WebSocket path.
            (
                "generativelanguage.googleapis.com",
                "query",
                "/ws/google.ai.generativelanguage.v1beta.GenerativeService.BidiGenerateContent",
            ),
        ],
    )
    def test_an_upgrade_with_a_token_is_refused_and_gets_no_key(self, egress, host, where, path):
        token = register(egress, koi_egress.PROVIDERS[host], "real-key")
        headers, query = dict(self.UPGRADE), {}
        if where == "authorization":
            headers["authorization"] = f"Bearer {token}"
        elif where == "sec-websocket-protocol":
            headers["sec-websocket-protocol"] = f"realtime, openai-insecure-api-key.{token}"
        else:
            query["key"] = token
        f = provider_flow(egress, host, headers, query, path)
        before = (f.request.url, list(f.request.headers.fields))
        egress.requestheaders(f)
        assert f.response.status_code == 403
        assert b"WebSocket" in f.response.content
        assert (f.request.url, list(f.request.headers.fields)) == before

    def test_an_upgrade_without_a_token_passes(self, egress):
        f = provider_flow(egress, "api.openai.com", {**self.UPGRADE, "authorization": "Bearer sk-typed-by-hand"})
        egress.requestheaders(f)
        assert f.response is None and f.request.stream is True
        f.response = tflow.tresp(status_code=101)
        egress.responseheaders(f)
        assert f.client_conn.id in egress.upgraded

    def test_a_101_to_a_request_a_key_went_into_is_dropped(self, egress):
        f, _ = swapped_flow(egress)
        f.response.status_code = 101
        egress.responseheaders(f)
        assert f.error is not None
        assert f.client_conn.id not in egress.upgraded


def test_unloading_the_policy_drops_its_keys_and_secret(egress):
    # A reload starts a new registry, so a Forget could never reach the keys
    # the old one still held; they go when the policy unloads, and so does
    # the secret.
    register(egress, "openai", "sk-" + "k" * 40)
    assert egress.registry.entries and egress.registry.secret is not None
    egress.done()
    assert egress.registry.entries == {}
    assert egress.registry.secret is None
