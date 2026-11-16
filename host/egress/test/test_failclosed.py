"""End-to-end: without a working policy, the proxy is down, never open.

The proxy starts with mitmproxy's server off, as koi-egress.service starts
it, and only a loaded, set-up koi_egress.py turns it on. These tests load a
copy of the policy and break it: at start, in its setup, and by changing the
file under a running proxy, which mitmproxy reloads.
"""

import os
import socket
import subprocess
import time

import pytest
from conftest import ADDON, Proxy, Upstream, refused, request, token_secret

BROKEN = {
    "a syntax error": "def broken(:\n",
    "an import that fails": "import koi_no_such_module\n",
    "a half-written file": ADDON.read_text()[: len(ADDON.read_text()) // 2],
}


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def write(path, text, mtime_step):
    """Replace path with text, renamed into place, with an mtime later than any before."""
    tmp = path.with_name(f".{path.name}.new")
    tmp.write_text(text)
    when = time.time() + mtime_step
    os.utime(tmp, (when, when))
    tmp.replace(path)


def through(port, target="http://pypi.org/"):
    """A plain HTTP request through the proxy on port, for an allowed host."""
    return request(socket.create_connection(("127.0.0.1", port), timeout=2), "pypi.org", target=target)


def answers(port):
    """True if anything accepts a connection on the port."""
    try:
        socket.create_connection(("127.0.0.1", port), timeout=2).close()
        return True
    except OSError:
        return False


@pytest.fixture
def box(tmp_path):
    """An upstream, an allowlist and a copy of the policy to break; yields a proxy factory."""
    allow = tmp_path / "allow.txt"
    allow.write_text("pypi.org\n")
    upstream = Upstream(tmp_path)
    started = []

    def start(script, allow_file=allow, wait=False, **policy_options):
        port = free_port()
        p = Proxy(tmp_path, upstream, allow_file, script=script, port=port, wait=wait, **policy_options)
        started.append(p)
        return p, port

    yield start
    for p in started:
        p.close()
    upstream.close()


@pytest.mark.parametrize("how", list(BROKEN))
def test_a_policy_that_fails_to_load_at_start_leaves_the_proxy_down(box, tmp_path, how):
    script = tmp_path / "koi_egress.py"
    script.write_text(BROKEN[how])
    proxy, port = box(script)
    # mitmproxy logs an error, or (a file cut where it still parses) loads a
    # module with no policy in it. Either way nothing listens.
    proxy.wait_loaded()
    time.sleep(0.5)
    assert not answers(port)
    assert refused(lambda: through(port))
    assert proxy.policy() is None


def test_a_policy_whose_setup_fails_leaves_the_proxy_down(box, tmp_path):
    script = tmp_path / "koi_egress.py"
    script.write_text(ADDON.read_text())
    proxy, port = box(script, allow_file=tmp_path / "missing-allow.txt")
    proxy.wait_logged("policy not set up")
    time.sleep(0.5)
    assert not answers(port)
    assert refused(lambda: through(port))


@pytest.mark.parametrize("how", list(BROKEN))
def test_a_broken_reload_takes_the_proxy_down_and_closes_open_connections(box, tmp_path, how):
    script = tmp_path / "koi_egress.py"
    script.write_text(ADDON.read_text())
    proxy, port = box(script, wait=True)
    tunnel = proxy.https("pypi.org")
    assert request(tunnel, "pypi.org")[0] == 200

    loaded, since = proxy.script().ns, len(proxy.log.messages)
    write(script, BROKEN[how], 5)
    proxy.wait_loaded(before=loaded, since=since)
    time.sleep(0.5)
    # New connections find nothing listening, and the tunnel opened under the
    # old policy is closed rather than left to run without one.
    assert not answers(port)
    assert refused(lambda: through(port))
    assert refused(lambda: request(tunnel, "pypi.org"))
    assert proxy.policy() is None

    # A working file brings it back.
    write(script, ADDON.read_text(), 10)
    proxy.wait_listening()
    assert request(proxy.https("pypi.org"), "pypi.org")[0] == 200


def test_a_good_reload_keeps_the_proxy_up(box, tmp_path):
    script = tmp_path / "koi_egress.py"
    script.write_text(ADDON.read_text())
    proxy, port = box(script, wait=True)
    write(script, ADDON.read_text() + "\n# changed\n", 5)
    proxy.wait_logged("policy unloaded")
    proxy.wait_listening()
    deadline = time.monotonic() + 10
    while not answers(port) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert request(proxy.https("pypi.org"), "pypi.org")[0] == 200


# The token secret: without a usable one the policy does not start, as with
# any other failure to load, and the proxy stays down.


def bad_secrets(tmp_path):
    """Each way the secret file can be wrong, by name: a path to pass as koi_secret."""
    good = token_secret(tmp_path, b"s" * 32, name="good")
    link = tmp_path / "link"
    link.symlink_to(good)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo, 0o400)
    loose = {}
    for mode in (0o600, 0o640, 0o644):
        loose[f"mode {mode:04o}"] = token_secret(tmp_path, b"s" * 32, name=f"mode-{mode:o}")
        loose[f"mode {mode:04o}"].chmod(mode)
    return {
        "no file": tmp_path / "missing",
        "no path": "",
        "empty": token_secret(tmp_path, b"", name="empty"),
        "31 bytes": token_secret(tmp_path, b"s" * 31, name="short"),
        "33 bytes": token_secret(tmp_path, b"s" * 33, name="long"),
        "a symlink": link,
        "a directory": tmp_path,
        "a fifo": fifo,
        **loose,
    }


SECRET_PROBLEMS = ["no file", "no path", "empty", "31 bytes", "33 bytes", "a symlink", "a directory", "a fifo"]
SECRET_PROBLEMS += ["mode 0600", "mode 0640", "mode 0644"]


@pytest.mark.parametrize("how", SECRET_PROBLEMS)
def test_a_bad_token_secret_leaves_the_proxy_down(box, tmp_path, how):
    sock = tmp_path / "control.sock"
    proxy, port = box(ADDON, koi_secret=str(bad_secrets(tmp_path)[how]), koi_control=str(sock))
    proxy.wait_logged("no usable token secret")
    proxy.wait_logged("policy not set up")
    time.sleep(0.5)
    assert not answers(port)
    assert refused(lambda: through(port))
    # No registration can reach it either, and the log never has the
    # secret's bytes, only the file and what is wrong with it.
    assert not sock.exists()
    assert not any("s" * 32 in m or (b"s" * 32).hex() in m for m in proxy.log.messages)


def test_a_secret_that_goes_bad_takes_the_proxy_down_on_reload(box, tmp_path):
    script = tmp_path / "koi_egress.py"
    script.write_text(ADDON.read_text())
    secret = token_secret(tmp_path)
    proxy, port = box(script, wait=True, koi_secret=str(secret))
    tunnel = proxy.https("pypi.org")
    assert request(tunnel, "pypi.org")[0] == 200

    # The file is now writable by its owner, and the policy loads again.
    secret.chmod(0o600)
    since = len(proxy.log.messages)
    write(script, ADDON.read_text() + "\n# changed\n", 5)
    proxy.wait_logged("policy unloaded")
    deadline = time.monotonic() + 10
    while not any("no usable token secret" in m for m in proxy.log.messages[since:]):
        assert time.monotonic() < deadline, proxy.log.messages[since:]
        time.sleep(0.05)
    time.sleep(0.5)
    assert not answers(port)
    assert refused(lambda: through(port))
    assert refused(lambda: request(tunnel, "pypi.org"))

    # Put right, the next load brings it back.
    secret.chmod(0o400)
    write(script, ADDON.read_text() + "\n# changed again\n", 10)
    proxy.wait_listening()
    assert request(proxy.https("pypi.org"), "pypi.org")[0] == 200


def ready(port, seconds):
    env = {**os.environ, "KOI_EGRESS_HOST": "127.0.0.1", "KOI_EGRESS_PORT": str(port), "KOI_EGRESS_READY_SECONDS": str(seconds)}
    script = ADDON.parent / "ready.sh"
    return subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True)


def test_the_service_counts_as_started_only_once_the_proxy_listens():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        s.listen()
        assert ready(s.getsockname()[1], 5).returncode == 0
    closed = ready(free_port(), 1)
    assert closed.returncode != 0
    assert "did not start the proxy" in closed.stderr
