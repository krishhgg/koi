"""The Python runner client: what it prints, what it waits for, and what it refuses."""

import importlib.util
import io
import json
from pathlib import Path

import pytest

CLIENT = Path(__file__).parent.parent / "clients" / "koi_runner.py"
spec = importlib.util.spec_from_file_location("koi_runner", CLIENT)
koi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(koi)


def events(out):
    return [json.loads(l) for l in out.getvalue().split("\n") if l]


def test_assertion_names_the_point_from_the_environment(monkeypatch):
    monkeypatch.setenv("KOI_POINT_ID", "hello.home")
    out = io.StringIO()
    koi.assertion("home-says-hello", "pass", ["recorder:screenshot:1"], detail="x" * 5000, out=out)
    [event] = events(out)
    assert event["type"] == "assertion"
    assert event["point"] == "hello.home"
    assert event["evidence"] == ["recorder:screenshot:1"]
    assert len(event["detail"]) == 4000
    with pytest.raises(ValueError):
        koi.assertion("x", "ok", out=out)


def only_line(out):
    [line] = out.getvalue().splitlines()
    return line


CHINESE = "\u6d4b\u8bd5" * 1000  # 2,000 characters, 6 bytes each once escaped
EMOJI = "\U0001f600" * 1000  # 12 bytes each once escaped, two UTF-16 units


def check_cut(line, field, text):
    assert len(line.encode()) <= koi.MAX_LINE_BYTES
    kept = json.loads(line)[field]
    assert kept and text.startswith(kept)
    # Cut as little as it could: one more character would pass a bound, and the
    # largest one here, an emoji, is 12 bytes once escaped.
    assert len(line) > koi.MAX_LINE_BYTES - 12 or len(kept) == koi.MAX_TEXT_UNITS


@pytest.mark.parametrize("text", [CHINESE, EMOJI, '"' * 5000, "\x01" * 5000, "\n" * 5000])
def test_a_detail_or_a_note_is_cut_until_the_whole_line_fits(text):
    out = io.StringIO()
    koi.assertion("declared", "fail", [], detail=text, point="hello.home", out=out)
    check_cut(only_line(out), "detail", text)

    out = io.StringIO()
    koi.note(text, out=out)
    check_cut(only_line(out), "text", text)


def test_text_that_fits_the_line_still_keeps_to_what_the_schema_takes():
    # Within the line's bytes and past 4,000 as koid's schema counts a string,
    # which would make the event malformed.
    text = "x" * 3650 + "\U0001f600" * 350
    assert len(text) == 4000 and len(json.dumps(text)) < koi.MAX_LINE_BYTES
    out = io.StringIO()
    koi.note(text, out=out)
    kept = json.loads(only_line(out))["text"]
    assert len(kept.encode("utf-16-le")) // 2 <= koi.MAX_TEXT_UNITS
    assert text.startswith(kept)


def test_text_that_fits_is_kept_whole():
    out = io.StringIO()
    koi.note(CHINESE[:1000], out=out)
    assert json.loads(only_line(out))["text"] == CHINESE[:1000]


def test_an_event_too_large_without_its_text_raises_instead_of_going_missing():
    out = io.StringIO()
    refs = ["recorder:screenshot:%d" % i for i in range(1000)]
    with pytest.raises(ValueError, match="koid discards a line over 8192"):
        koi.assertion("declared", "pass", refs, detail="why", point="hello.home", out=out)
    with pytest.raises(ValueError, match="koid discards a line over 8192"):
        koi.read("/" + "\u6d4b" * 2000, "row", out=out, inp=io.StringIO(""))
    assert out.getvalue() == ""


def test_capture_waits_for_its_own_acknowledgment_and_returns_the_artifact():
    out = io.StringIO()
    inp = io.StringIO(
        "not json\n"
        '{"version":1,"type":"capture-result","label":"other","status":"ready","artifact":"recorder:screenshot:1"}\n'
        '{"version":1,"type":"capture-result","label":"home","status":"ready","artifact":"recorder:screenshot:2"}\n'
    )
    assert koi.capture("screenshot", "home", out=out, inp=inp) == "recorder:screenshot:2"
    assert events(out) == [{"type": "capture", "kind": "screenshot", "label": "home"}]
    with pytest.raises(ValueError):
        koi.capture("video", "x", out=out, inp=inp)


def test_a_failed_result_raises_with_the_code():
    out = io.StringIO()
    inp = io.StringIO('{"version":1,"type":"capture-result","label":"home","status":"failed","error":"withheld"}\n')
    with pytest.raises(koi.CaptureFailed) as err:
        koi.capture("trace", "home", out=out, inp=inp)
    assert err.value.code == "withheld"
    assert err.value.label == "home"


def test_a_closed_stdin_raises():
    with pytest.raises(koi.CaptureFailed) as err:
        koi.capture("aria", "x", out=io.StringIO(), inp=io.StringIO(""))
    assert err.value.code == "stdin_closed"


def test_read_prints_a_read_event_and_refuses_a_path_off_the_origin():
    out = io.StringIO()
    inp = io.StringIO('{"version":1,"type":"capture-result","label":"row","status":"ready","artifact":"recorder:http-response:3"}\n')
    assert koi.read("/api/rows/1", "row", out=out, inp=inp) == "recorder:http-response:3"
    assert events(out) == [{"type": "read", "label": "row", "path": "/api/rows/1"}]
    out = io.StringIO()
    inp = io.StringIO('{"version":1,"type":"capture-result","label":"h","status":"ready","artifact":"recorder:http-response:4"}\n')
    koi.read("/", "h", method="HEAD", out=out, inp=inp)
    assert events(out) == [{"type": "read", "label": "h", "path": "/", "method": "HEAD"}]
    with pytest.raises(ValueError):
        koi.read("http://elsewhere/", "x", out=out, inp=inp)


def test_note_and_phase():
    out = io.StringIO()
    koi.note("first load needed one reconnect", out=out)
    koi.phase("journey", "start", out=out)
    assert events(out) == [
        {"type": "note", "text": "first load needed one reconnect"},
        {"type": "phase", "name": "journey", "state": "start"},
    ]
    with pytest.raises(ValueError):
        koi.phase("assert", "start", out=out)


def test_env_reads_what_koid_sets():
    e = koi.env(
        {
            "KOI_RUN_ID": "r",
            "KOI_POINT_ID": "p.q",
            "KOI_ATTEMPT": "2",
            "KOI_PREVIEW_URL": "http://app.r.invalid:8080",
            "KOI_RECORDER_WS": "ws://10.213.0.3:4317/tok",
            "KOI_FIXTURES": '{"fixtures/a.txt":"/fixtures/fixtures/a.txt"}',
            "KOI_TIMEOUT_SECONDS": "300",
            "KOI_MAX_REQUESTS": "20",
        }
    )
    assert (e.run_id, e.point_id, e.attempt) == ("r", "p.q", 2)
    assert e.preview_url == "http://app.r.invalid:8080"
    assert e.recorder_ws == "ws://10.213.0.3:4317/tok"
    assert e.fixtures == {"fixtures/a.txt": "/fixtures/fixtures/a.txt"}
    assert (e.timeout_seconds, e.max_requests, e.login_key) == (300, 20, None)
    assert koi.env({"KOI_FIXTURES": "nope"}).fixtures == {}


def test_requirements_indent_with_spaces():
    # pip splits a joined line on spaces, so a tab leaves --hash inside the version,
    # and the image does not build.
    text = (Path(__file__).parent.parent / "requirements.txt").read_text()
    assert "\t" not in text
