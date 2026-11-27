"""koi-preview-route, run against stand-ins for docker and nsenter.

Run with the other egress tests:  uv run --with mitmproxy==12.2.3 --with pytest pytest host/egress/test
"""

import os
import subprocess
from pathlib import Path

import pytest

HELPER = Path(__file__).parent.parent / "koi-preview-route"
SANDBOX = "/var/run/docker/netns/1f2e3d4c5b6a"

DOCKER = """#!/bin/bash
case "$1 $2" in
	"network inspect") echo "$FAKE_GATEWAY" ;;
	"container inspect") echo "$FAKE_CONTAINER" ;;
	*) exit 9 ;;
esac
"""
NSENTER = """#!/bin/bash
echo "$*" >> "$FAKE_CALLS"
"""


@pytest.fixture
def box(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in (("docker", DOCKER), ("nsenter", NSENTER)):
        (bin_dir / name).write_text(body)
        (bin_dir / name).chmod(0o755)
    calls = tmp_path / "calls"
    calls.write_text("")

    def run(*args, gateway="172.18.0.1", container=f"true {SANDBOX} koi-previews,"):
        env = {
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "FAKE_GATEWAY": gateway,
            "FAKE_CONTAINER": container,
            "FAKE_CALLS": str(calls),
        }
        r = subprocess.run([str(HELPER), *args], env=env, capture_output=True, text=True, timeout=30, check=False)
        return r.returncode, r.stderr, calls.read_text().splitlines()

    return run


def test_gives_a_running_preview_a_default_route_to_its_bridge(box):
    code, err, calls = box("koi-hello-main-abc")
    assert (code, err) == (0, "")
    assert calls == [f"--net={SANDBOX} ip route replace default via 172.18.0.1"]


@pytest.mark.parametrize(
    "container, why",
    [
        (f"false {SANDBOX} koi-previews,", "not running"),
        (f"true {SANDBOX} koi-previews,koi-build,", "not koi-previews alone"),
        (f"true {SANDBOX} bridge,", "not koi-previews alone"),
        ("true /proc/1/ns/net koi-previews,", "no network namespace Docker made"),
        # An empty path shifts the fields, and the network check refuses it.
        ("true  koi-previews,", "not koi-previews alone"),
    ],
)
def test_changes_nothing_for_a_container_it_should_not_touch(box, container, why):
    code, err, calls = box("koi-hello-main-abc", container=container)
    assert code == 1
    assert why in err
    assert calls == []


@pytest.mark.parametrize("args", [(), ("-rf",), ("a b",), ("../x",), ("one", "two"), ("",)])
def test_takes_exactly_one_container_name(box, args):
    code, err, calls = box(*args)
    assert code == 2
    assert "usage" in err
    assert calls == []


def test_refuses_a_preview_network_without_an_ipv4_gateway(box):
    code, err, calls = box("koi-hello-main-abc", gateway="")
    assert code == 1
    assert "no IPv4 gateway" in err
    assert calls == []
