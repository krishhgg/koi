"""The supervisor without Docker: real child processes, pipes for stdin and stdout, and a clock of the test's own where time matters.

Each test writes a point.json, feeds the supervisor's stdin through a pipe
and reads what it printed: the children's lines in order, the supervisor's
step and exit lines on lines of their own, and the exit code.
"""

import hashlib
import hmac
import importlib.util
import json
import os
import shlex
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

SUPERVISOR = Path(__file__).parent.parent / "supervisor.py"
spec = importlib.util.spec_from_file_location("supervisor", SUPERVISOR)
sup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sup)

KEY = "ab" * 32
START = json.dumps({"version": 1, "type": "start", "key": KEY}, separators=(",", ":")).encode() + b"\n"


def point(tmp_path, steps, timeout=20, runner=None):
    path = tmp_path / "point.json"
    path.write_text(json.dumps({"version": 1, "runner": runner, "steps": steps, "timeoutSeconds": timeout}))
    return str(path)


def signed(line):
    """Whether a supervisor line's MAC is the one the key gives its text, as koid checks it."""
    head, _, tail = line.rpartition(',"mac":"')
    return hmac.new(KEY.encode(), head.encode(), hashlib.sha256).hexdigest() + '"}' == tail


def alive(pid):
    """Whether the process is there and not a zombie."""
    try:
        with open(f"/proc/{pid}/stat", encoding="ascii") as f:
            return f.read().rpartition(")")[2].split()[0] != "Z"
    except FileNotFoundError:
        return False


def read_pid(path, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.exists() and path.read_text().strip():
            return int(path.read_text())
        time.sleep(0.02)
    raise AssertionError(f"{path} never appeared")


class Run:
    """One supervisor run: stdin fed from the test, stdout collected as it arrives, in a thread.

    The test process stays dumpable: the command-line test below covers the
    real call. `hold_reading` is an event the collector waits on before its first
    read, as a koid busy elsewhere leaves the supervisor's stdout unread.
    """

    def __init__(self, point_path, cwd, env=None, clock=None, hold_reading=None):
        self.hold_reading = hold_reading
        self.in_r, self.in_w = os.pipe()
        self.out_r, self.out_w = os.pipe()
        self.stdin = os.fdopen(self.in_r, "rb", buffering=0)
        self.stdout = os.fdopen(self.out_w, "wb", buffering=0)
        self.code = None
        self.output = b""
        kwargs = {
            "stdin": self.stdin,
            "stdout": self.stdout,
            "cwd": cwd,
            "env": env if env is not None else {"PATH": os.environ["PATH"]},
            "harden": lambda: None,
        }
        if clock is not None:
            kwargs["clock"] = clock
        self.thread = threading.Thread(target=self._main, args=(point_path, kwargs), daemon=True)
        self.thread.start()
        self.reader = threading.Thread(target=self._collect, daemon=True)
        self.reader.start()

    def _main(self, point_path, kwargs):
        try:
            self.code = sup.main(["supervisor.py", point_path], **kwargs)
        finally:
            self.stdout.close()

    def _collect(self):
        if self.hold_reading is not None:
            self.hold_reading.wait()
        with os.fdopen(self.out_r, "rb", buffering=0) as f:
            while True:
                data = f.read(65536)
                if not data:
                    return
                self.output += data

    def wait_for(self, text, timeout=10):
        """Waits until `text` has been printed, so a test can act on what the step did."""
        deadline = time.time() + timeout
        while text not in self.output:
            assert time.time() < deadline, f"{text!r} was not printed: {self.output!r}"
            time.sleep(0.02)

    def send(self, data):
        os.write(self.in_w, data)

    def close_stdin(self):
        os.close(self.in_w)

    def wait(self, timeout=30):
        self.thread.join(timeout)
        assert not self.thread.is_alive(), "the supervisor did not finish"
        self.reader.join(timeout)
        try:
            os.close(self.in_w)
        except OSError:
            pass
        return self.code

    def lines(self):
        return self.output.decode("utf-8").split("\n")

    def supervisor_lines(self):
        out = []
        for line in self.lines():
            if line.startswith('{"version":1,"type":"supervisor"'):
                out.append(json.loads(line))
        return out

    def exit_line(self):
        exits = [l for l in self.supervisor_lines() if l["event"] == "exit"]
        assert len(exits) == 1
        return exits[0]


def test_runs_setup_run_and_cleanup_in_order_and_forwards_their_stdout(tmp_path):
    p = point(
        tmp_path,
        {
            "setup": ["sh", "-c", "echo one; pwd"],
            "run": ["sh", "-c", "echo two"],
            "cleanup": ["sh", "-c", "echo three"],
        },
    )
    r = Run(p, cwd=str(tmp_path))
    r.send(START)
    assert r.wait() == 0
    lines = r.lines()
    assert json.loads(lines[0])["event"] == "started"
    # The children's lines, in the order the steps ran, with the step lines
    # between them; the working directory is the point's.
    texts = [l for l in lines if l and not l.startswith("{")]
    assert texts == ["one", str(tmp_path.resolve()), "two", "three"]
    steps = [l for l in r.supervisor_lines() if l["event"] == "step"]
    assert [(s["step"], s["status"], s["code"]) for s in steps] == [
        ("setup", "exited", 0),
        ("run", "exited", 0),
        ("cleanup", "exited", 0),
    ]
    exit_line = r.exit_line()
    assert exit_line["step"] == "cleanup"
    assert exit_line["status"] == "exited"
    assert exit_line["code"] == 0
    assert [s["step"] for s in exit_line["steps"]] == ["setup", "run", "cleanup"]
    # The last line is the exit line.
    assert json.loads(lines[-2])["event"] == "exit"
    assert lines[-1] == ""


def test_runner_prefix_goes_before_each_step(tmp_path):
    p = point(tmp_path, {"run": ["-c", "echo $0 $1", "a", "b"]}, runner=["sh"])
    r = Run(p, cwd=str(tmp_path))
    r.send(START)
    assert r.wait() == 0
    assert "a b" in r.lines()


def test_never_runs_a_step_before_start_and_gives_up_when_stdin_closes(tmp_path):
    marker = tmp_path / "ran"
    p = point(tmp_path, {"run": ["sh", "-c", f"touch {marker}"]})
    r = Run(p, cwd=str(tmp_path))
    r.close_stdin()
    assert r.wait() == sup.EXIT_NOT_STARTED
    assert not marker.exists()
    assert r.exit_line() == {"version": 1, "type": "supervisor", "event": "exit", "status": "not-started", "steps": []}


def test_a_line_that_is_not_start_is_not_start(tmp_path):
    p = point(tmp_path, {"run": ["sh", "-c", "echo ran"]})
    r = Run(p, cwd=str(tmp_path))
    r.send(b'{"version":1,"type":"capture-result","label":"x","status":"ready","artifact":"recorder:screenshot:1"}\n')
    r.close_stdin()
    assert r.wait() == sup.EXIT_NOT_STARTED
    assert "ran" not in r.lines()


# Reads one line from stdin and prints it, or says it got nothing within a
# second. Python rather than sh, whose `read -t` is not in POSIX: under dash it
# fails at once and looks the same as nothing arriving.
READ_WITH_TIMEOUT = (
    "import select, sys\n"
    "ready, _, _ = select.select([sys.stdin], [], [], 1)\n"
    "line = sys.stdin.readline() if ready else ''\n"
    "print(f'{sys.argv[1]} got ' + line.strip() if line else f'{sys.argv[1]}-got-nothing', flush=True)\n"
)


def test_forwards_acknowledgments_to_the_running_step_only(tmp_path):
    # run reads one line from stdin and prints it; cleanup reads with a short
    # timeout and must get nothing, since the line sent while run ran was
    # consumed by run.
    ack = '{"version":1,"type":"capture-result","label":"x","status":"ready","artifact":"recorder:screenshot:7"}'
    p = point(
        tmp_path,
        {
            "run": ["python3", "-c", "import sys; print('ready', flush=True); print('run got ' + sys.stdin.readline().strip(), flush=True)"],
            "cleanup": ["python3", "-c", READ_WITH_TIMEOUT, "cleanup"],
        },
    )
    r = Run(p, cwd=str(tmp_path))
    r.send(START)
    r.wait_for(b"ready\n")
    r.send(ack.encode() + b"\n")
    assert r.wait() == 0
    lines = r.lines()
    assert f"run got {ack}" in lines
    assert "cleanup-got-nothing" in lines


def test_a_line_sent_between_steps_goes_to_nobody(tmp_path):
    p = point(
        tmp_path,
        {
            "setup": ["sh", "-c", "echo setup-done"],
            "run": ["python3", "-c", READ_WITH_TIMEOUT, "run"],
        },
    )
    r = Run(p, cwd=str(tmp_path))
    # Both lines arrive before setup ends; the second is delivered to setup,
    # which does not read it, and is gone by the time run starts.
    r.send(START + b"stray\n")
    assert r.wait() == 0
    assert "setup-done" in r.lines()
    assert "run-got-nothing" in r.lines()


def test_a_failed_setup_skips_run_but_still_runs_cleanup(tmp_path):
    p = point(
        tmp_path,
        {
            "setup": ["sh", "-c", "exit 7"],
            "run": ["sh", "-c", "echo must-not-run"],
            "cleanup": ["sh", "-c", "echo cleaned"],
        },
    )
    r = Run(p, cwd=str(tmp_path))
    r.send(START)
    assert r.wait() == sup.EXIT_STEP_FAILED
    assert "must-not-run" not in r.lines()
    assert "cleaned" in r.lines()
    steps = {s["step"]: s for s in r.exit_line()["steps"]}
    assert steps["setup"] == {"step": "setup", "status": "exited", "code": 7, "seconds": steps["setup"]["seconds"]}
    assert steps["run"] == {"step": "run", "status": "skipped", "reason": "setup did not exit 0"}
    assert steps["cleanup"]["code"] == 0
    assert r.exit_line()["step"] == "cleanup"


def test_a_failed_run_still_runs_cleanup_and_the_exit_code_says_a_step_failed(tmp_path):
    p = point(tmp_path, {"run": ["sh", "-c", "exit 1"], "cleanup": ["sh", "-c", "echo cleaned"]})
    r = Run(p, cwd=str(tmp_path))
    r.send(START)
    assert r.wait() == sup.EXIT_STEP_FAILED
    assert "cleaned" in r.lines()
    assert r.exit_line()["status"] == "exited"
    assert r.exit_line()["code"] == 0


def test_a_step_past_its_budget_is_killed_and_cleanup_keeps_its_reserve(tmp_path):
    # A budget of 8 seconds holds 2 back for cleanup (a quarter, under the 30
    # second cap); run gets 6 and sleeps longer. The clock is real here, so
    # the timeout is short.
    p = point(
        tmp_path,
        {
            "run": ["sh", "-c", "trap 'exit 9' TERM; echo running; sleep 30; echo late"],
            "cleanup": ["sh", "-c", "echo cleaned"],
        },
        timeout=8,
    )
    r = Run(p, cwd=str(tmp_path))
    r.send(START)
    started = time.time()
    assert r.wait() == sup.EXIT_TIMEOUT
    assert time.time() - started < 20
    steps = {s["step"]: s for s in r.exit_line()["steps"]}
    assert steps["run"]["status"] == "timeout"
    assert 5 <= steps["run"]["seconds"] <= 12
    assert steps["cleanup"]["status"] == "exited"
    assert "late" not in r.lines()
    assert "cleaned" in r.lines()


def test_a_point_with_no_cleanup_keeps_no_time_back_for_one(tmp_path):
    # A budget of 4 seconds would hold 1 back. Nothing could use it, so run gets all 4.
    p = point(tmp_path, {"run": ["sh", "-c", "sleep 3.3; echo finished"]}, timeout=4)
    r = Run(p, cwd=str(tmp_path))
    r.send(START)
    assert r.wait() == 0
    assert "finished" in r.lines()


def test_a_step_that_ignores_sigterm_gets_sigkill(tmp_path):
    p = point(tmp_path, {"run": ["sh", "-c", "trap '' TERM; sleep 60"]}, timeout=4)
    r = Run(p, cwd=str(tmp_path))
    r.send(START)
    started = time.time()
    assert r.wait() == sup.EXIT_TIMEOUT
    # 3 seconds of budget (4 less the reserve), then the 5 second grace.
    assert time.time() - started < 20
    assert r.exit_line()["status"] == "timeout"


def test_a_descendant_that_ignores_sigterm_and_holds_stdout_dies_with_the_group(tmp_path):
    # The leader dies at SIGTERM at once. Its child ignores SIGTERM and keeps
    # the step's stdout open, so waiting on the leader alone would never send
    # the SIGKILL, and the reader would never see the pipe end.
    pid_file = tmp_path / "grandchild.pid"
    grandchild = (
        "import os, signal, time\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        f"open({str(pid_file)!r}, 'w').write(str(os.getpid()))\n"
        "print('grandchild up', flush=True)\n"
        "time.sleep(120)\n"
    )
    p = point(
        tmp_path,
        {"run": ["sh", "-c", f"python3 -c {shlex.quote(grandchild)} & wait"], "cleanup": ["sh", "-c", "echo cleaned"]},
        timeout=4,
    )
    r = Run(p, cwd=str(tmp_path))
    r.send(START)
    pid = read_pid(pid_file)
    r.wait_for(b"grandchild up\n")
    assert alive(pid)
    started = time.time()
    try:
        assert r.wait() == sup.EXIT_TIMEOUT
        # 3 seconds of budget at most, then the 5 second grace, and the pipe
        # ends with the SIGKILL, with no wait on the reader.
        assert time.time() - started < 12
        steps = {s["step"]: s for s in r.exit_line()["steps"]}
        assert steps["run"]["status"] == "timeout"
        assert steps["run"]["seconds"] >= 2 + sup.TERM_GRACE_SECONDS - 1
        # The grace outlasted a small budget's reserve.
        assert steps["cleanup"] == {"step": "cleanup", "status": "timeout", "reason": "no time left in the point's budget"}
        deadline = time.time() + 5
        while alive(pid) and time.time() < deadline:
            time.sleep(0.05)
        assert not alive(pid)
    finally:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def escaped(pid_file):
    """A program that leaves the step's process group and session, ignores SIGTERM, keeps stdout open and says so."""
    return (
        "import os, signal, time\n"
        "os.setsid()\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        f"open({str(pid_file)!r}, 'w').write(str(os.getpid()))\n"
        "time.sleep(120)\n"
    )


def test_a_descendant_outside_the_group_cannot_hold_the_supervisor_past_a_timeout(tmp_path):
    # No signal to the group reaches it, and it holds the pipe the reader is
    # blocked on. A close that waited on that reader's lock would hang here.
    pid_file = tmp_path / "escaped.pid"
    p = point(
        tmp_path,
        {"run": ["sh", "-c", f"python3 -c {shlex.quote(escaped(pid_file))} & wait"], "cleanup": ["sh", "-c", "echo cleaned"]},
        timeout=4,
    )
    r = Run(p, cwd=str(tmp_path))
    r.send(START)
    pid = read_pid(pid_file)
    try:
        assert r.wait(timeout=25) == sup.EXIT_TIMEOUT
        assert [s["status"] for s in r.exit_line()["steps"]] == ["timeout", "timeout"]
        assert r.exit_line()["steps"][0]["output_incomplete"] is True
    finally:
        os.kill(pid, signal.SIGKILL)


def test_a_descendant_left_holding_stdout_after_a_clean_exit_does_not_hold_the_supervisor(tmp_path):
    pid_file = tmp_path / "escaped.pid"
    p = point(tmp_path, {"run": ["sh", "-c", f"python3 -c {shlex.quote(escaped(pid_file))} & echo done"]}, timeout=30)
    r = Run(p, cwd=str(tmp_path))
    r.send(START)
    pid = read_pid(pid_file)
    started = time.time()
    try:
        assert r.wait(timeout=25) == 0
        assert time.time() - started < 15
        assert "done" in r.lines()
        # What that process prints later is lost, so the signed lines say so.
        step = next(l for l in r.supervisor_lines() if l["event"] == "step")
        assert step["output_incomplete"] is True
        assert r.exit_line()["steps"] == [step_fields(step)]
        assert all(signed(l) for l in r.lines() if l.startswith('{"version":1,"type":"supervisor"'))
    finally:
        os.kill(pid, signal.SIGKILL)


def step_fields(line):
    """A step line as the exit line repeats it."""
    return {k: v for k, v in line.items() if k not in ("version", "type", "seq", "event", "mac")}


def test_a_step_that_ended_normally_says_nothing_of_incomplete_output(tmp_path):
    p = point(tmp_path, {"run": ["sh", "-c", "echo done"]})
    r = Run(p, cwd=str(tmp_path))
    r.send(START)
    assert r.wait() == 0
    assert "output_incomplete" not in r.exit_line()["steps"][0]


def test_a_stall_downstream_past_the_idle_limit_loses_nothing(tmp_path):
    # koid reads nothing for longer than the idle limit, while the step has
    # already exited with the end of its output still in its own pipe. A limit
    # on the wait for the reader would drop that end, with a clean exit code and
    # nothing to say so. The output is more than the pipe to koid holds, and little
    # enough for the two pipes together, so the step can exit during the stall.
    program = (
        "import sys\n"
        "print('first', flush=True)\n"
        "for i in range(2400):\n"
        "    print('log %06d ' % i + 'x' * 40, flush=True)\n"
        "print('the end', flush=True)\n"
    )
    p = point(tmp_path, {"run": [sys.executable, "-c", program]}, timeout=60)
    hold = threading.Event()
    r = Run(p, cwd=str(tmp_path), hold_reading=hold)
    r.send(START)
    time.sleep(sup.DRAIN_IDLE_SECONDS + 2)
    hold.set()
    assert r.wait(timeout=30) == 0
    lines = r.lines()
    assert "the end" in lines
    assert len([l for l in lines if l.startswith("log ")]) == 2400
    assert "output_incomplete" not in r.exit_line()["steps"][0]


def test_output_that_keeps_coming_after_the_step_ends_stops_at_the_budget_and_says_so(tmp_path):
    # Never idle, so only the point's budget ends the wait.
    pid_file = tmp_path / "writer.pid"
    program = (
        "import os, time\n"
        "os.setsid()\n"
        f"open({str(pid_file)!r}, 'w').write(str(os.getpid()))\n"
        "while True:\n"
        "    print('still here', flush=True)\n"
        "    time.sleep(0.1)\n"
    )
    p = point(tmp_path, {"run": ["sh", "-c", f"python3 -c {shlex.quote(program)} & echo done"]}, timeout=3)
    r = Run(p, cwd=str(tmp_path))
    r.send(START)
    pid = read_pid(pid_file)
    started = time.time()
    try:
        assert r.wait(timeout=25) == 0
        assert time.time() - started < sup.DRAIN_IDLE_SECONDS + 2
        step = r.exit_line()["steps"][0]
        assert step["status"] == "exited"
        assert step["output_incomplete"] is True
    finally:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def test_a_forward_that_fails_is_reported_as_incomplete_output(tmp_path):
    class BrokenOutput:
        def forward(self, data):
            raise OSError("the pipe to koid is gone")

    class NoStdin:
        def attach(self, pipe):
            pass

        def detach(self):
            pass

    result = sup.run_step(
        "run",
        ["sh", "-c", "echo lost"],
        10,
        {"PATH": os.environ["PATH"]},
        BrokenOutput(),
        NoStdin(),
        cwd=str(tmp_path),
    )
    assert result["status"] == "exited"
    assert result["output_incomplete"] is True


def test_a_step_with_no_time_left_is_a_timeout_not_a_skip(tmp_path):
    # koid reads "skipped" as a failed step and "timeout" as the budget. A
    # setup that used its whole share leaves run no time, which is the budget.
    p = point(tmp_path, {"setup": ["sh", "-c", "echo up"], "run": ["sh", "-c", "echo must-not-run"]}, timeout=8)
    clock = iter([0.0, 0.0, 0.0, 0.0, 100.0, 100.0, 100.0, 100.0, 100.0]).__next__
    r = Run(p, cwd=str(tmp_path), clock=clock)
    r.send(START)
    assert r.wait() == sup.EXIT_TIMEOUT
    steps = {s["step"]: s for s in r.exit_line()["steps"]}
    assert steps["run"] == {"step": "run", "status": "timeout", "reason": "no time left in the point's budget"}
    assert "must-not-run" not in r.lines()


def test_a_step_killed_by_a_signal_is_reported_as_signalled(tmp_path):
    p = point(tmp_path, {"run": ["sh", "-c", "kill -KILL $$"]})
    r = Run(p, cwd=str(tmp_path))
    r.send(START)
    assert r.wait() == sup.EXIT_STEP_FAILED
    step = r.exit_line()["steps"][0]
    assert step["status"] == "signalled"
    assert step["signal"] == 9


def test_a_program_that_cannot_start_fails_the_step_with_the_reason(tmp_path):
    p = point(tmp_path, {"run": ["/nonexistent/program"]})
    r = Run(p, cwd=str(tmp_path))
    r.send(START)
    assert r.wait() == sup.EXIT_START_FAILED
    step = r.exit_line()["steps"][0]
    assert step["status"] == "failed"
    assert step["reason"].startswith("/nonexistent/program: ")


def test_children_get_the_allowlisted_environment_and_nothing_else(tmp_path):
    p = point(tmp_path, {"run": ["sh", "-c", "env | sort"]})
    env = {
        "PATH": os.environ["PATH"],
        "HOME": "/tmp/home",
        "KOI_RUN_ID": "r1",
        "KOI_POINT_ID": "hello.home",
        "KOI_RECORDER_WS": "ws://10.213.0.3:4317/abc",
        "PYTHON_VERSION": "3.13.13",
        "HTTP_PROXY": "http://proxy:3128",
        "SECRET": "no",
    }
    r = Run(p, cwd=str(tmp_path), env=env)
    r.send(START)
    assert r.wait() == 0
    assert KEY not in r.output.decode()
    seen = {l.split("=", 1)[0]: l.split("=", 1)[1] for l in r.lines() if "=" in l and not l.startswith("{")}
    assert seen == {
        "PATH": os.environ["PATH"],
        "HOME": "/tmp/home",
        "KOI_RUN_ID": "r1",
        "KOI_POINT_ID": "hello.home",
        "KOI_RECORDER_WS": "ws://10.213.0.3:4317/abc",
        # The shell adds PWD itself.
        **({"PWD": seen["PWD"]} if "PWD" in seen else {}),
    }


def test_after_start_every_line_of_its_own_is_numbered_and_signed_with_the_key(tmp_path):
    p = point(tmp_path, {"setup": ["sh", "-c", "echo up"], "run": ["sh", "-c", "exit 3"], "cleanup": ["sh", "-c", "true"]})
    r = Run(p, cwd=str(tmp_path))
    r.send(START)
    assert r.wait() == sup.EXIT_STEP_FAILED
    own = [l for l in r.lines() if l.startswith('{"version":1,"type":"supervisor"')]
    assert [json.loads(l)["event"] for l in own] == ["started", "step", "step", "step", "exit"]
    assert [json.loads(l)["seq"] for l in own] == [1, 2, 3, 4, 5]
    assert all(signed(l) for l in own)
    # The MAC covers the text: change a byte and it no longer checks.
    tampered = own[2].replace('"code":3', '"code":0')
    assert tampered != own[2] and not signed(tampered)
    # The key itself is on no line.
    assert KEY not in r.output.decode()


def test_a_child_sees_no_key_on_its_stdin_or_in_its_environment(tmp_path):
    p = point(tmp_path, {"setup": ["sh", "-c", "env"], "run": ["python3", "-c", READ_WITH_TIMEOUT, "run"]})
    r = Run(p, cwd=str(tmp_path), env={"PATH": os.environ["PATH"], "HOME": "/tmp/home"})
    r.send(START)
    assert r.wait() == 0
    # The start line stopped at the supervisor, and nothing printed the key.
    assert "run-got-nothing" in r.lines()
    assert KEY not in r.output.decode()


def start_with(seconds):
    return json.dumps({"version": 1, "type": "start", "key": KEY, "timeoutSeconds": seconds}, separators=(",", ":")).encode() + b"\n"


def test_the_start_line_says_what_the_point_has_left_whatever_point_json_says(tmp_path):
    # point.json was written before the context opened and the inputs were staged.
    p = point(tmp_path, {"run": ["sh", "-c", "echo timeout=$KOI_TIMEOUT_SECONDS; sleep 30"]}, timeout=600)
    r = Run(p, cwd=str(tmp_path), env={"PATH": os.environ["PATH"], "KOI_TIMEOUT_SECONDS": "600"})
    started = time.monotonic()
    r.send(start_with(1.2))
    r.close_stdin()
    assert r.wait() == sup.EXIT_TIMEOUT
    # The run step's share of 1.2 seconds, and the 5 seconds SIGTERM may take at
    # most. Nowhere near 30, and the step's own view of it is rounded up.
    assert time.monotonic() - started < 10
    assert "timeout=2" in r.lines()
    assert r.exit_line()["steps"][0]["status"] == "timeout"


def test_a_start_line_with_a_time_that_is_no_time_is_not_start(tmp_path):
    p = point(tmp_path, {"run": ["sh", "-c", "echo ran"]})
    for seconds in (0, -1, "60", True):
        r = Run(p, cwd=str(tmp_path))
        r.send(start_with(seconds))
        r.close_stdin()
        assert r.wait() == sup.EXIT_NOT_STARTED
        assert "ran" not in r.lines()


def test_a_start_line_without_a_well_formed_key_is_not_start(tmp_path):
    p = point(tmp_path, {"run": ["sh", "-c", "echo ran"]})
    for line in (b'{"version":1,"type":"start"}\n', b'{"version":1,"type":"start","key":"short"}\n', b'{"version":1,"type":"start","key":7}\n'):
        r = Run(p, cwd=str(tmp_path))
        r.send(line)
        r.close_stdin()
        assert r.wait() == sup.EXIT_NOT_STARTED
        assert "ran" not in r.lines()
        assert r.exit_line()["status"] == "not-started"


def test_a_supervisor_that_cannot_make_itself_undumpable_runs_nothing(tmp_path):
    marker = tmp_path / "ran"
    p = point(tmp_path, {"run": ["sh", "-c", f"touch {marker}"]})
    in_r, in_w = os.pipe()
    out_r, out_w = os.pipe()

    def refuse():
        raise OSError(1, "prctl(PR_SET_DUMPABLE)")

    with os.fdopen(in_r, "rb", buffering=0) as stdin, os.fdopen(out_w, "wb", buffering=0) as stdout:
        os.write(in_w, START)
        code = sup.main(["supervisor.py", p], stdin=stdin, stdout=stdout, env={}, cwd=str(tmp_path), harden=refuse)
    os.close(in_w)
    with os.fdopen(out_r, "rb") as f:
        printed = f.read().decode()
    assert code == sup.EXIT_START_FAILED
    assert json.loads(printed)["status"] == "failed"
    assert not marker.exists()


@pytest.mark.skipif(not sys.platform.startswith("linux") or os.geteuid() == 0, reason="root reads any /proc entry")
def test_a_child_cannot_reach_the_supervisors_memory_or_descriptors(tmp_path):
    # The real call, in a process of its own. The same reads of a process that
    # did not make itself undumpable succeed, and the first check says so.
    script = (
        "import os, sys\n"
        "print('self', os.access('/proc/self/mem', os.R_OK), flush=True)\n"
        "parent = os.getppid()\n"
        "for path in (f'/proc/{parent}/fd/1', f'/proc/{parent}/mem', f'/proc/{parent}/environ'):\n"
        "    try:\n"
        "        open(path, 'rb').close()\n"
        "        print('opened', path, flush=True)\n"
        "    except PermissionError:\n"
        "        print('refused', path, flush=True)\n"
    )
    p = point(tmp_path, {"run": ["python3", "-c", script]})
    loader = (
        "import importlib.util, sys\n"
        "spec = importlib.util.spec_from_file_location('supervisor', sys.argv[1])\n"
        "m = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(m)\n"
        "sys.exit(m.main(['supervisor.py', sys.argv[2]], cwd=sys.argv[3]))\n"
    )
    proc = subprocess.run(
        [sys.executable, "-I", "-c", loader, str(SUPERVISOR), p, str(tmp_path)],
        input=START,
        capture_output=True,
        timeout=30,
        env={"PATH": os.environ["PATH"]},
    )
    assert proc.returncode == 0, proc.stderr.decode()
    lines = proc.stdout.decode().split("\n")
    assert "self True" in lines
    refused = [l for l in lines if l.startswith("refused ")]
    opened = [l for l in lines if l.startswith("opened ")]
    assert len(refused) == 3 and opened == []
    assert all(signed(l) for l in lines if l.startswith('{"version":1,"type":"supervisor"'))


def test_a_partial_line_from_a_child_does_not_join_the_supervisors_line(tmp_path):
    p = point(tmp_path, {"run": ["sh", "-c", "printf no-newline"]})
    r = Run(p, cwd=str(tmp_path))
    r.send(START)
    assert r.wait() == 0
    lines = r.lines()
    assert "no-newline" in lines
    assert all(l.startswith("{") for l in lines if "supervisor" in l)


def test_a_long_line_is_forwarded_whole(tmp_path):
    p = point(tmp_path, {"run": ["sh", "-c", "head -c 200000 /dev/zero | tr '\\0' x; echo"]})
    r = Run(p, cwd=str(tmp_path))
    r.send(START)
    assert r.wait() == 0
    assert "x" * 200000 in r.lines()


def test_load_point_refuses_what_koid_would_not_write():
    with pytest.raises(sup.PointFile):
        sup.load_point("not json")
    with pytest.raises(sup.PointFile):
        sup.load_point(json.dumps({"version": 2, "steps": {"run": ["x"]}, "timeoutSeconds": 1}))
    with pytest.raises(sup.PointFile):
        sup.load_point(json.dumps({"version": 1, "steps": {"setup": ["x"]}, "timeoutSeconds": 1}))
    with pytest.raises(sup.PointFile):
        sup.load_point(json.dumps({"version": 1, "steps": {"run": ["x", ""]}, "timeoutSeconds": 1}))
    with pytest.raises(sup.PointFile):
        sup.load_point(json.dumps({"version": 1, "steps": {"run": "x"}, "timeoutSeconds": 1}))
    with pytest.raises(sup.PointFile):
        sup.load_point(json.dumps({"version": 1, "steps": {"run": ["x"]}, "timeoutSeconds": 0}))
    with pytest.raises(sup.PointFile):
        sup.load_point(json.dumps({"version": 1, "steps": {"run": ["x"]}, "timeoutSeconds": True}))
    loaded = sup.load_point(
        json.dumps({"version": 1, "runner": ["python3"], "steps": {"run": ["a.py"], "cleanup": None}, "timeoutSeconds": 30})
    )
    assert loaded == {"commands": {"run": ["python3", "a.py"]}, "timeout": 30.0}


def test_a_bad_point_file_exits_failed_without_waiting_for_start(tmp_path):
    path = tmp_path / "point.json"
    path.write_text("{")
    r = Run(str(path), cwd=str(tmp_path))
    assert r.wait() == sup.EXIT_START_FAILED
    assert r.exit_line()["status"] == "failed"
    assert r.exit_line()["steps"] == []


def test_cleanup_reserve_is_bounded():
    assert sup.cleanup_reserve(300) == 30
    assert sup.cleanup_reserve(8) == 2
    assert sup.cleanup_reserve(1000) == 30


def test_exit_code_is_the_worst_step():
    ok = {"step": "run", "status": "exited", "code": 0}
    assert sup.exit_code([ok]) == 0
    assert sup.exit_code([ok, {"step": "cleanup", "status": "exited", "code": 2}]) == 1
    assert sup.exit_code([{"step": "run", "status": "signalled", "signal": 9}]) == 1
    assert sup.exit_code([{"step": "run", "status": "skipped"}]) == 1
    assert sup.exit_code([{"step": "run", "status": "exited", "code": 1}, {"step": "cleanup", "status": "timeout"}]) == 2
    assert sup.exit_code([{"step": "run", "status": "failed"}, {"step": "cleanup", "status": "timeout"}]) == 3


def test_runs_under_isolated_python_from_the_command_line(tmp_path):
    # As koid invokes it: python3 -I /koi/supervisor.py /koi/point.json. The
    # working directory is fixed in the file; here it does not exist, so the
    # step fails to start and says which path.
    p = point(tmp_path, {"run": ["sh", "-c", "echo hi"]})
    proc = subprocess.run(
        [sys.executable, "-I", str(SUPERVISOR), p],
        input=START,
        capture_output=True,
        timeout=30,
        env={"PATH": os.environ["PATH"]},
    )
    lines = proc.stdout.decode().split("\n")
    exit_line = json.loads(lines[-2])
    assert exit_line["event"] == "exit"
    assert signed(lines[-2])
    if Path(sup.WORKSPACE).is_dir():
        assert proc.returncode == 0
    else:
        assert proc.returncode == sup.EXIT_START_FAILED
        assert exit_line["steps"][0]["reason"].startswith(f"{sup.WORKSPACE}: ")
