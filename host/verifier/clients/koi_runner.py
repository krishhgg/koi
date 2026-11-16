"""The runner protocol for a Python runner (docs/verify.md, "Writing a runner").

A runner prints JSON events on stdout and reads koid's acknowledgments on
stdin; this module does both. The default verifier image has it on the
Python path; a project's own image copies it from host/verifier/clients/.

    import koi_runner as koi

    shot = koi.capture("screenshot", "after-save")      # an artifact id
    state = koi.read("/api/pipelines/7", "saved-row")   # an http-response artifact
    koi.assertion("name-persists", "pass", [shot, state], detail="the row holds the name")

Everything a runner needs from koid is in the environment: koi.env() reads
it. A capture or a read blocks until koid answers; a failed one raises
CaptureFailed with koid's error code. Any line on stdin that is not the
acknowledgment awaited is ignored.

koid discards a line over 8 KiB, so an assertion's detail and a note's text are
cut until the whole line fits. An event that cannot fit without its free text
raises ValueError: printing it would lose it without a word.
"""

import json
import os
import sys
import threading

PROTOCOL_VERSION = 1
OUTCOMES = ("pass", "fail", "blocked", "not-run", "needs-review", "pass-with-recovery")
CAPTURE_KINDS = ("screenshot", "trace", "har", "aria", "file")
PHASES = ("setup", "journey", "recovery", "cleanup")
# The longest line koid reads, without its newline (PROTOCOL_LIMITS.lineBytes in
# packages/daemon/src/verifier.ts). It discards a longer one whole, so an event
# past this would look as if the runner never sent it.
MAX_LINE_BYTES = 8 * 1024
# The longest free text koid's schema takes (RunnerEventSchema). It counts as
# JavaScript does, so a character outside the basic plane counts twice.
MAX_TEXT_UNITS = 4000

_lock = threading.Lock()


class CaptureFailed(Exception):
    """koid answered a capture or a read with status failed."""

    def __init__(self, label, code):
        super().__init__(f"{label}: {code}")
        self.label = label
        self.code = code


class Env:
    """What koid put in the environment, by attribute."""

    def __init__(self, environ=None):
        e = os.environ if environ is None else environ
        self.run_id = e.get("KOI_RUN_ID", "")
        self.point_id = e.get("KOI_POINT_ID", "")
        self.attempt = int(e.get("KOI_ATTEMPT", "1") or 1)
        self.preview_url = e.get("KOI_PREVIEW_URL", "")
        self.recorder_ws = e.get("KOI_RECORDER_WS", "")
        self.timeout_seconds = int(e.get("KOI_TIMEOUT_SECONDS", "0") or 0)
        self.max_requests = int(e.get("KOI_MAX_REQUESTS", "0") or 0)
        self.login_key = e.get("KOI_LOGIN_KEY")
        try:
            fixtures = json.loads(e.get("KOI_FIXTURES", "{}") or "{}")
        except ValueError:
            fixtures = {}
        # Fixture path under .koi/ to its read-only path in the container.
        self.fixtures = fixtures if isinstance(fixtures, dict) else {}


def env(environ=None):
    return Env(environ)


def _line(record):
    """The event as koid reads it. json.dumps escapes all but ASCII, so its length in characters is its length in bytes."""
    return json.dumps(record, separators=(",", ":"))


def _emit(record, out=None):
    line = _line(record)
    if len(line) > MAX_LINE_BYTES:
        raise ValueError(f"a {record['type']} event is {len(line)} bytes, and koid discards a line over {MAX_LINE_BYTES}")
    stream = sys.stdout if out is None else out
    with _lock:
        stream.write(line + "\n")
        stream.flush()


def _text_units(text):
    return len(text.encode("utf-16-le", "surrogatepass")) // 2


def _fit(record, field, value):
    """Sets record[field] to as much of `value` as koid's schema takes and the line bound leaves room for.

    Escapes make the encoded size depend on what the text holds: 6 bytes for a
    Chinese character, 12 for an emoji, 2 for a quote. So the cut is tried against
    the whole encoded line, not worked out from the length of the text.
    """
    text = str(value)[:MAX_TEXT_UNITS]

    def fits(count):
        record[field] = text[:count]
        return _text_units(record[field]) <= MAX_TEXT_UNITS and len(_line(record)) <= MAX_LINE_BYTES

    if fits(len(text)):
        return
    low, high = 0, len(text) - 1
    while low < high:
        middle = (low + high + 1) // 2
        if fits(middle):
            low = middle
        else:
            high = middle - 1
    record[field] = text[:low]


def _await_result(label, inp=None):
    stream = sys.stdin if inp is None else inp
    while True:
        line = stream.readline()
        if not line:
            raise CaptureFailed(label, "stdin_closed")
        try:
            ack = json.loads(line)
        except ValueError:
            continue
        if not isinstance(ack, dict) or ack.get("type") != "capture-result" or ack.get("label") != label:
            continue
        if ack.get("status") == "ready" and isinstance(ack.get("artifact"), str):
            return ack["artifact"]
        raise CaptureFailed(label, str(ack.get("error", "failed")))


def assertion(name, outcome, evidence=(), detail=None, point=None, out=None):
    """Reports one of the point's declared assertions. `point` defaults to KOI_POINT_ID."""
    if outcome not in OUTCOMES:
        raise ValueError(f"outcome {outcome!r} is not one of {', '.join(OUTCOMES)}")
    record = {
        "type": "assertion",
        "point": point or os.environ.get("KOI_POINT_ID", ""),
        "name": name,
        "outcome": outcome,
        "evidence": list(evidence),
    }
    if detail is not None:
        _fit(record, "detail", detail)
    _emit(record, out)


def capture(kind, label, out=None, inp=None):
    """Asks the recorder for a capture of the point's page and returns its artifact id."""
    if kind not in CAPTURE_KINDS:
        raise ValueError(f"kind {kind!r} is not one of {', '.join(CAPTURE_KINDS)}")
    _emit({"type": "capture", "kind": kind, "label": label}, out)
    return _await_result(label, inp)


def read(path, label, method="GET", out=None, inp=None):
    """Asks the recorder to request `path` from the app and returns the http-response artifact id."""
    if not path.startswith("/"):
        raise ValueError("path must start with /: a path on the app's origin")
    record = {"type": "read", "label": label, "path": path}
    if method != "GET":
        record["method"] = method
    _emit(record, out)
    return _await_result(label, inp)


def note(text, out=None):
    record = {"type": "note"}
    _fit(record, "text", text)
    _emit(record, out)


def phase(name, state, out=None):
    if name not in PHASES or state not in ("start", "end"):
        raise ValueError("phase is one of setup, journey, recovery, cleanup, with state start or end")
    _emit({"type": "phase", "name": name, "state": state}, out)
