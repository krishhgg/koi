"""install.sh's pieces that can run off the box.

Each is a shell function in install.sh, run here with the box's paths
pointed into a scratch directory and the commands that need root
(runuser, chown) replaced by stand-ins that record what they were asked.
"""

import re
import subprocess
from pathlib import Path

import pytest

INSTALL = Path(__file__).parent.parent / "install.sh"


def function(name):
    """The text of a shell function in install.sh, from its name to its closing brace."""
    match = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", INSTALL.read_text(), re.S | re.M)
    assert match, f"install.sh has no function {name}"
    return match.group(0)


def runuser_stub(where, before=""):
    """A shell runuser that notes the user asked for in where/runuser.log, runs before, then the command itself."""
    return f'runuser() {{ echo "$2" >> "{where / "runuser.log"}"; shift 3; {before} "$@"; }}'


def run(name, where, prelude=None):
    """Runs install.sh's function name with the box's paths under where; returns the completed process."""
    if prelude is None:
        prelude = runuser_stub(where)
    script = function(name).replace("/var/lib/koi-egress", str(where / "var")).replace("/etc/koi/egress", str(where / "etc"))
    return subprocess.run(
        ["bash", "-c", f"set -euo pipefail\n{prelude}\n{script}\n{name}\n"],
        capture_output=True,
        text=True,
        timeout=30,
    )


def asked_of_runuser(where):
    """The users runuser was asked to run as, in order."""
    log = where / "runuser.log"
    return log.read_text().split() if log.exists() else []


CERT = "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"


class TestPublishCa:
    """The CA certificate reaches ca.pem read as the proxy's user, and only if it is one."""

    @pytest.fixture
    def box(self, tmp_path):
        (tmp_path / "var").mkdir()
        (tmp_path / "etc").mkdir()
        return tmp_path, runuser_stub(tmp_path), tmp_path / "runuser.log"

    def test_copies_a_certificate_read_as_koi_egress(self, box):
        where, prelude, log = box
        (where / "var" / "mitmproxy-ca-cert.pem").write_text(CERT)
        done = run("publish_ca", where, prelude)
        assert done.returncode == 0, done.stderr
        assert (where / "etc" / "ca.pem").read_text() == CERT
        assert oct((where / "etc" / "ca.pem").stat().st_mode & 0o777) == "0o644"
        assert log.read_text() == "koi-egress\n"
        assert not list(where.glob("tmp.*"))

    @pytest.mark.parametrize(
        "content",
        [
            "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----\n",
            CERT + "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n",
            "root:x:0:0:root:/root:/bin/bash\n",
            "",
        ],
    )
    def test_publishes_nothing_that_is_not_a_certificate_alone(self, box, content):
        # Whatever the proxy's user put at the path, or pointed it at.
        where, prelude, log = box
        secret = where / "var" / "something-else"
        secret.write_text(content)
        (where / "var" / "mitmproxy-ca-cert.pem").symlink_to(secret)
        done = run("publish_ca", where, prelude)
        assert done.returncode == 1
        assert "refusing to publish" in done.stderr
        assert not (where / "etc" / "ca.pem").exists()

    def test_fails_when_the_file_cannot_be_read_as_koi_egress(self, box):
        where, prelude, log = box
        done = run("publish_ca", where, prelude)
        assert done.returncode == 1
        assert "could not read" in done.stderr
        assert not (where / "etc" / "ca.pem").exists()


class TestRemoveOldSecret:
    """The secret an earlier revision kept under /var/lib/koi-egress goes, without following a symlink."""

    def old(self, tmp_path):
        private = tmp_path / "var" / "private"
        private.mkdir(parents=True)
        return private

    def test_removes_the_file_and_then_the_empty_directory_as_koi_egress(self, tmp_path):
        private = self.old(tmp_path)
        (private / "token-secret").write_bytes(b"s" * 32)
        assert run("remove_old_secret", tmp_path).returncode == 0
        assert not private.exists()
        assert asked_of_runuser(tmp_path) == ["koi-egress", "koi-egress"]

    def test_a_directory_swapped_for_a_symlink_after_the_check_leads_nowhere_root_would_delete(self, tmp_path):
        # The proxy's user owns /var/lib/koi-egress, so
        # the proxy can replace private with a symlink to the live secret's
        # directory between the check and the removal. The removal runs as
        # that user, which cannot delete there. The stand-in runuser makes
        # the swap just before each command; the live directory is one its
        # caller cannot write, as root's is to koi-egress.
        private = self.old(tmp_path)
        (private / "token-secret").write_bytes(b"old")
        live = tmp_path / "live"
        live.mkdir()
        (live / "token-secret").write_bytes(b"s" * 32)
        live.chmod(0o555)
        swap = f'rm -rf "{private}"; ln -s "{live}" "{private}";'
        try:
            done = run("remove_old_secret", tmp_path, runuser_stub(tmp_path, before=swap))
            assert done.returncode == 0, done.stderr
            assert (live / "token-secret").read_bytes() == b"s" * 32
            assert asked_of_runuser(tmp_path) == ["koi-egress", "koi-egress"]
        finally:
            live.chmod(0o755)

    def test_removes_a_symlink_in_its_place_and_not_what_it_points_at(self, tmp_path):
        private = self.old(tmp_path)
        target = tmp_path / "elsewhere"
        target.write_text("keep")
        (private / "token-secret").symlink_to(target)
        assert run("remove_old_secret", tmp_path).returncode == 0
        assert not private.exists()
        assert target.read_text() == "keep"

    def test_leaves_a_directory_that_is_a_symlink_alone(self, tmp_path):
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / "token-secret").write_text("keep")
        (tmp_path / "var").mkdir()
        (tmp_path / "var" / "private").symlink_to(elsewhere)
        assert run("remove_old_secret", tmp_path).returncode == 0
        assert (tmp_path / "var" / "private").is_symlink()
        assert (elsewhere / "token-secret").read_text() == "keep"

    def test_keeps_a_directory_that_holds_anything_else(self, tmp_path):
        private = self.old(tmp_path)
        (private / "token-secret").write_bytes(b"s" * 32)
        (private / "other").write_text("x")
        assert run("remove_old_secret", tmp_path).returncode == 0
        assert not (private / "token-secret").exists()
        assert (private / "other").read_text() == "x"

    def test_does_nothing_on_a_box_that_never_had_it(self, tmp_path):
        (tmp_path / "var").mkdir()
        assert run("remove_old_secret", tmp_path).returncode == 0
        assert sorted(p.name for p in (tmp_path / "var").iterdir()) == []
