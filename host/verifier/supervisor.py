#!/usr/bin/env python3
"""The verifier's supervisor: runs one point's steps and carries the runner protocol.

koid puts this file in every verifier's read-only /koi volume, next to
point.json, and makes `python3 -I /koi/supervisor.py /koi/point.json` the
container's entrypoint, whatever the image's own says
(docs/verify.md, "Writing a runner"). Only the standard library is used,
since the image is the project's choice and may hold nothing else.

What it does, in order:

- Makes itself undumpable, then waits for koid's start line on stdin
  ({"version":1,"type":"start","key":"<hex>","timeoutSeconds":<n>}). koid sends
  it once the firewall has bound the run's permits to this container, so a step
  never runs before it can reach the recorder. timeoutSeconds is what the point
  has left then, since opening its context and staging these very files used part
  of its budget. It replaces point.json's, which was written before all that.
- Runs the point's setup, run and cleanup commands one after another, each
  as the manifest's runner prefix plus the step's argv, never through a
  shell, with /workspace as the working directory and an explicit
  environment made of the names in CHILD_ENV and nothing the image set.
- Forwards each child's stdout to its own stdout line by line and untouched,
  and forwards koid's later stdin lines (capture acknowledgments) to the
  running child's stdin. stderr is inherited. A step is reported only once its
  stdout is all forwarded, however slowly koid reads. A step's line says
  output_incomplete when the supervisor stopped short of that for any reason.
- Keeps the point's time budget: the steps share it, with the last part held
  back for cleanup, and a step past its share has its whole process group
  killed, SIGTERM then SIGKILL. Cleanup still runs after a failed setup or
  run when time is left.
- Prints a line of its own as each step ends and a last line that says which
  step the sequence ended on and how, then exits 0 when every step exited 0,
  1 when a step exited otherwise, 2 when a step ran out of time, 3 when a
  step could not start, and 4 when koid never sent start.

The runner shares this stdout and can print a line that looks like one of
these, so each carries a sequence number and an HMAC-SHA256 over the line's
text, keyed by the random key in the start line. koid believes a supervisor
line only when the MAC checks and the number is the next one. The key is not
in this process's argv, environment or files, and no child exists when it
arrives. A child cannot read it from here either: making this process
undumpable closes /proc/<pid>/mem and /proc/<pid>/fd, and ptrace, to its own
uid, and an exec gives the child back its own dumpable state. A MAC rather
than the key itself in each line, because any process in the container can
reach this stdout through /proc/1/fd/1 of the init process, read a line from
the pipe and print it again; a MAC gives it nothing to forge with, and the
sequence number makes a replay show. Before start there is no key, and these
lines go unsigned: koid reads a container that ends there by its exit code and
stderr alone.
"""

import hashlib
import hmac
import json
import math
import os
import select
import signal
import subprocess
import sys
import threading
import time

PROTOCOL_VERSION = 1
WORKSPACE = "/workspace"
STEPS = ("setup", "run", "cleanup")
# The environment a step gets, by name, from the supervisor's own. Anything
# else the image or Docker set stays with the supervisor. PATH is among them
# because koid sets it on the container to a fixed value.
CHILD_ENV = (
    "PATH",
    "HOME",
    "TMPDIR",
    "LANG",
    "TZ",
    "KOI_PROTOCOL_VERSION",
    "KOI_RUN_ID",
    "KOI_POINT_ID",
    "KOI_ATTEMPT",
    "KOI_PREVIEW_URL",
    "KOI_RECORDER_WS",
    "KOI_FIXTURES",
    "KOI_TIMEOUT_SECONDS",
    "KOI_MAX_REQUESTS",
    "KOI_LOGIN_KEY",
)
# How long koid has to send start before the supervisor gives up.
START_TIMEOUT_SECONDS = 120
# After SIGTERM, how long a step has to exit before SIGKILL.
TERM_GRACE_SECONDS = 5
# The most of the budget held back for cleanup, and the share of a small
# budget held back.
CLEANUP_RESERVE_SECONDS = 30
CLEANUP_RESERVE_SHARE = 0.25
# A child's stdout is read in pieces of at most this many bytes, so a line
# without end cannot grow without bound here; koid bounds lines itself.
READ_BYTES = 64 * 1024
# How long a step's stdout may give nothing, once the step has ended, before
# the supervisor stops waiting on it. Time spent forwarding does not count: a
# slow koid is no reason to drop what a step wrote. Silence with the pipe still
# open means a descendant outlived the step and holds it.
DRAIN_IDLE_SECONDS = 5
# PR_SET_DUMPABLE, from linux/prctl.h.
PR_SET_DUMPABLE = 4

# The start line's key: 32 random bytes, in hex.
KEY_HEX_LENGTH = 64

EXIT_OK = 0
EXIT_STEP_FAILED = 1
EXIT_TIMEOUT = 2
EXIT_START_FAILED = 3
EXIT_NOT_STARTED = 4


class PointFile(Exception):
    """point.json is not what koid writes."""


def load_point(text):
    """The steps and the budget from point.json, checked: argv lists of non-empty strings, a positive budget."""
    try:
        data = json.loads(text)
    except ValueError as err:
        raise PointFile(f"point.json is not JSON: {err}") from None
    if not isinstance(data, dict) or data.get("version") != PROTOCOL_VERSION:
        raise PointFile("point.json has no version 1")

    def argv(value, what):
        if value is None:
            return None
        if not isinstance(value, list) or not value or not all(isinstance(a, str) and a for a in value):
            raise PointFile(f"{what} is not a list of non-empty strings")
        return list(value)

    runner = argv(data.get("runner"), "runner") or []
    steps = data.get("steps")
    if not isinstance(steps, dict) or not isinstance(steps.get("run"), list):
        raise PointFile("steps.run is missing")
    commands = {}
    for name in STEPS:
        command = argv(steps.get(name), f"steps.{name}")
        if command is not None:
            commands[name] = runner + command
    timeout = data.get("timeoutSeconds")
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0:
        raise PointFile("timeoutSeconds is not a positive number")
    return {"commands": commands, "timeout": float(timeout)}


def child_env(env):
    """The explicit environment every step gets: CHILD_ENV names present in `env`, in that order."""
    return {name: env[name] for name in CHILD_ENV if name in env}


def cleanup_reserve(timeout):
    """Seconds of the budget held back for cleanup."""
    return min(CLEANUP_RESERVE_SECONDS, timeout * CLEANUP_RESERVE_SHARE)


def make_undumpable():
    """Closes this process to its own uid, so a child cannot read the key from its memory or tap its descriptors.

    Raises when that cannot be done: without it a runner could forge the
    lines koid trusts, so the supervisor would rather not run the steps.
    """
    if not sys.platform.startswith("linux"):
        return
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_DUMPABLE)")


class Output:
    """The supervisor's stdout: the children's bytes forwarded as they come, and the supervisor's own lines on lines of their own."""

    def __init__(self, stream):
        self.stream = stream
        self.lock = threading.Lock()
        # Whether the last byte written ended a line.
        self.at_line_start = True
        # koid's key once the start line has come; each line signed after
        # that takes the next number, from 1.
        self.key = None
        self.seq = 0

    def forward(self, data):
        if not data:
            return
        with self.lock:
            self.stream.write(data)
            self.stream.flush()
            self.at_line_start = data.endswith(b"\n")

    def line(self, fields):
        """One line of the supervisor's own, signed once there is a key.

        The MAC covers the line's exact text up to the MAC field and comes
        last, so koid checks the bytes it read without any canonical form.
        """
        with self.lock:
            record = {"version": PROTOCOL_VERSION, "type": "supervisor"}
            if self.key is not None:
                self.seq += 1
                record["seq"] = self.seq
            record.update(fields)
            text = json.dumps(record, separators=(",", ":"))
            if self.key is not None:
                head = text[:-1]
                mac = hmac.new(self.key, head.encode("ascii"), hashlib.sha256).hexdigest()
                text = f'{head},"mac":"{mac}"}}'
            if not self.at_line_start:
                self.stream.write(b"\n")
            self.stream.write(text.encode("ascii") + b"\n")
            self.stream.flush()
            self.at_line_start = True


class Stdin:
    """koid's lines on the supervisor's stdin: the first is start; the rest go to whichever step runs.

    Read with os.read on the descriptor, not through a buffered file: the
    reader is a daemon thread that may still be blocked in a read when the
    supervisor exits, and a buffered read would hold the file's lock then,
    which Python refuses to shut down over.
    """

    def __init__(self, stream):
        self.fd = stream.fileno()
        self.lock = threading.Lock()
        self.target = None
        self.started = threading.Event()
        self.closed = threading.Event()
        self.first = None
        self.thread = threading.Thread(target=self._read, name="stdin", daemon=True)
        self.thread.start()

    def _read(self):
        pending = b""
        try:
            while True:
                try:
                    data = os.read(self.fd, READ_BYTES)
                except OSError:
                    break
                if not data:
                    break
                pending += data
                while True:
                    at = pending.find(b"\n")
                    if at < 0:
                        break
                    line = pending[: at + 1]
                    pending = pending[at + 1 :]
                    self._line(line)
            if pending:
                self._line(pending)
        finally:
            self.closed.set()
            self.started.set()

    def _line(self, line):
        if not self.started.is_set():
            self.first = line
            self.started.set()
            return
        self._deliver(line)

    def _deliver(self, line):
        with self.lock:
            target = self.target
        if target is None:
            return
        try:
            target.write(line)
        except (BrokenPipeError, OSError, ValueError):
            # The step closed its stdin or exited; the line is for nobody.
            pass

    def wait_for_start(self, timeout):
        """What koid's start line says: its key as bytes and the seconds the point has left, when it says that.

        None when stdin closed, the wait ran out, or the line was not start.
        """
        if not self.started.wait(timeout):
            return None
        if self.first is None:
            return None
        try:
            record = json.loads(self.first)
        except ValueError:
            return None
        if not isinstance(record, dict) or record.get("version") != PROTOCOL_VERSION or record.get("type") != "start":
            return None
        key = record.get("key")
        if not isinstance(key, str) or len(key) != KEY_HEX_LENGTH or any(c not in "0123456789abcdef" for c in key):
            return None
        seconds = record.get("timeoutSeconds")
        if seconds is not None and (isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or seconds <= 0):
            return None
        return key.encode("ascii"), None if seconds is None else float(seconds)

    def attach(self, pipe):
        with self.lock:
            self.target = pipe

    def detach(self):
        with self.lock:
            self.target = None


def group_alive(pgid):
    """Whether any process of the group is still there."""
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def terminate(proc):
    """SIGTERM to the step's whole process group, then SIGKILL to the group after the grace period.

    Waits on the group, not on the leader: a leader that exits at SIGTERM can
    leave a descendant that ignores it and holds the step's stdout. The poll
    reaps the leader, since a zombie would keep the group alive to the end of
    the grace.
    """
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass
    deadline = time.monotonic() + TERM_GRACE_SECONDS
    while time.monotonic() < deadline:
        if proc.poll() is not None and not group_alive(proc.pid):
            return
        time.sleep(0.05)
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    proc.wait()


def pump(stream, ended_fd, output, stop_at, complete):
    """Forwards a child's stdout until it ends, then sets `complete`. Closes both descriptors, whatever happens.

    `ended_fd` turns readable when the step has ended. From then on a read comes
    first, so what the pipe holds goes on however long `output` takes. Only a pipe
    that has given nothing for DRAIN_IDLE_SECONDS, or the point's budget at
    `stop_at`, ends the wait with the pipe still open. `complete` stays unset then
    and on any error, so the step's line reports every way bytes can be dropped.
    Times are time.monotonic(): this thread runs beside the step, so it must not
    read the caller's clock, which a test can script call by call.

    The child's pipe is read here unbuffered and closed only here: a buffered
    reader would hold its lock through a blocking read, so another thread's
    close would wait for a process that may never write or exit.
    """
    fd = stream.fileno()
    ended = False
    idle_since = 0.0
    try:
        while True:
            over = False
            timeout = None
            if ended:
                now = time.monotonic()
                over = now >= stop_at
                timeout = max(0.0, min(stop_at - now, idle_since + DRAIN_IDLE_SECONDS - now))
            ready, _, _ = select.select([fd] if ended else [fd, ended_fd], [], [], timeout)
            if not ready:
                return
            if ended_fd in ready:
                ended = True
                idle_since = time.monotonic()
            if fd in ready:
                data = os.read(fd, READ_BYTES)
                if not data:
                    complete.set()
                    return
                output.forward(data)
                idle_since = time.monotonic()
                if over:
                    return
    except (OSError, ValueError):
        pass
    finally:
        os.close(ended_fd)
        stream.close()


def run_step(name, command, seconds, env, output, stdin, cwd=WORKSPACE, clock=time.monotonic, until=None):
    """Runs one step within `seconds` and returns its result record.

    `until` is when the point's budget ends, on `clock`: what the step wrote may
    take that long to go on, past the step's own share. Without it, the share.
    """
    started = clock()
    if seconds <= 0:
        # The budget ran out, which koid reads the same way as a step stopped
        # at it.
        return {"step": name, "status": "timeout", "reason": "no time left in the point's budget"}
    try:
        # Unbuffered, so nothing here waits on a lock a stuck read or write holds.
        proc = subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            bufsize=0,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,
            start_new_session=True,
            close_fds=True,
        )
    except OSError as err:
        what = err.filename if isinstance(err.filename, str) else command[0]
        return {"step": name, "status": "failed", "reason": f"{what}: {err.strerror or err}"[:500]}
    stdin.attach(proc.stdin)

    ended_r, ended_w = os.pipe()
    complete = threading.Event()
    stop_at = time.monotonic() + (seconds if until is None else until - started)
    reader = threading.Thread(target=pump, args=(proc.stdout, ended_r, output, stop_at, complete), name=f"stdout-{name}", daemon=True)
    reader.start()
    status = "exited"
    try:
        proc.wait(timeout=seconds)
    except subprocess.TimeoutExpired:
        status = "timeout"
        terminate(proc)
    finally:
        stdin.detach()
        try:
            proc.stdin.close()
        except OSError:
            pass
    # The step's line must come after all it wrote, so this waits for the reader
    # with no limit of its own. The reader ends at the pipe's end, its silence or
    # the budget. A forward koid never reads holds it past those, and then this
    # process could not print anything anyway: koid stops the container on a timer
    # of its own, 15 seconds past the budget. The closed pipe tells the reader the
    # step has ended, whatever a descendant is doing.
    os.close(ended_w)
    reader.join()
    elapsed = round(clock() - started, 3)
    result = {"step": name, "status": status, "seconds": elapsed}
    if not complete.is_set():
        result["output_incomplete"] = True
    if status == "exited":
        if proc.returncode < 0:
            result["status"] = "signalled"
            result["signal"] = -proc.returncode
        else:
            result["code"] = proc.returncode
    return result


def exit_code(results):
    """The supervisor's exit code from the step results: the worst of them."""
    code = EXIT_OK
    for r in results:
        if r["status"] == "timeout":
            code = max(code, EXIT_TIMEOUT)
        elif r["status"] == "failed":
            code = max(code, EXIT_START_FAILED)
        elif r["status"] in ("signalled", "skipped") or r.get("code", 0) != 0:
            code = max(code, EXIT_STEP_FAILED)
    return code


def main(argv, stdin=None, stdout=None, env=None, cwd=WORKSPACE, clock=time.monotonic, harden=make_undumpable):
    stdin_stream = stdin if stdin is not None else sys.stdin.buffer
    out = Output(stdout if stdout is not None else sys.stdout.buffer)
    env = os.environ if env is None else env
    results = []

    def finish(step, status, code=None):
        record = {"event": "exit", "status": status, "steps": results}
        if step is not None:
            record["step"] = step
        if code is not None:
            record["code"] = code
        out.line(record)
        return exit_code(results) if results else (EXIT_START_FAILED if status == "failed" else EXIT_NOT_STARTED)

    if len(argv) != 2:
        print("usage: supervisor.py /koi/point.json", file=sys.stderr)
        return finish(None, "failed")
    try:
        with open(argv[1], "rb") as f:
            point = load_point(f.read().decode("utf-8"))
    except (OSError, UnicodeDecodeError, PointFile) as err:
        print(f"supervisor: {err}", file=sys.stderr)
        return finish(None, "failed")

    # Before the key can arrive, and before any child exists.
    try:
        harden()
    except (ImportError, AttributeError, OSError) as err:
        print(f"supervisor: cannot make this process undumpable: {err}", file=sys.stderr)
        return finish(None, "failed")

    reader = Stdin(stdin_stream)
    start = reader.wait_for_start(START_TIMEOUT_SECONDS)
    if start is None:
        print("supervisor: koid did not send start", file=sys.stderr)
        return finish(None, "not-started")
    out.key, seconds = start
    out.line({"event": "started"})

    timeout = point["timeout"] if seconds is None else seconds
    deadline = clock() + timeout
    commands = point["commands"]
    # With no cleanup to run, the time would be kept for nothing and a run that fits
    # its budget would be killed short of it.
    reserve = cleanup_reserve(timeout) if commands.get("cleanup") is not None else 0
    child = child_env(env)
    # What koid set when it created the container is older than the start line.
    if seconds is not None:
        child["KOI_TIMEOUT_SECONDS"] = str(math.ceil(seconds))
    # HOME is under the tmpfs and does not exist yet; a client library that
    # writes there (a cache, a config) should find a directory.
    if child.get("HOME"):
        try:
            os.makedirs(child["HOME"], exist_ok=True)
        except OSError:
            pass
    failed = False
    last = None
    for name in STEPS:
        command = commands.get(name)
        if command is None:
            continue
        if name == "cleanup":
            remaining = deadline - clock()
        else:
            remaining = deadline - reserve - clock()
        if failed and name == "run":
            result = {"step": name, "status": "skipped", "reason": "setup did not exit 0"}
        else:
            result = run_step(name, command, remaining, child, out, reader, cwd=cwd, clock=clock, until=deadline)
        results.append(result)
        out.line({"event": "step", **result})
        last = result
        if result["status"] != "exited" or result.get("code", 0) != 0:
            failed = True
    if last is None:
        return finish(None, "failed")
    return finish(last["step"], last["status"], last.get("code"))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
