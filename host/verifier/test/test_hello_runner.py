"""The hello example's runner, driven against a stand-in for Playwright and for koid's acknowledgments.

The real page comes from the recorder's browser over the run network; here
a stub module answers connect_over_cdp with one page whose heading the test
chooses, and the test plays koid: reads the events the runner prints and
answers each capture and read.
"""

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "examples" / "hello" / ".koi" / "runners" / "home.py"
CLIENTS = ROOT / "host" / "verifier" / "clients"

STUB = textwrap.dedent(
    '''
    import os

    class _Page:
        def __init__(self, url, heading):
            self.url = url
            self._heading = heading
            self.visited = []
        def goto(self, url, **kwargs):
            self.visited.append(url)
        def text_content(self, selector):
            return self._heading if selector == "h1" else None

    class _Context:
        def __init__(self, pages):
            self.pages = pages

    class _Browser:
        def __init__(self, contexts):
            self.contexts = contexts

    class _Chromium:
        def connect_over_cdp(self, ws, timeout=None):
            assert ws == os.environ["KOI_RECORDER_WS"], ws
            heading = os.environ["STUB_HEADING"]
            url = os.environ["KOI_PREVIEW_URL"] + "/"
            if os.environ.get("STUB_NO_PAGE"):
                return _Browser([])
            return _Browser([_Context([_Page("about:blank", ""), _Page(url, heading)])])

    class _Playwright:
        chromium = _Chromium()
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            return False

    def sync_playwright():
        return _Playwright()
    '''
)


def run(tmp_path, heading, no_page=False):
    stub = tmp_path / "stub" / "playwright"
    stub.mkdir(parents=True)
    (stub / "__init__.py").write_text("")
    (stub / "sync_api.py").write_text(STUB)
    env = {
        "PATH": os.environ["PATH"],
        "PYTHONPATH": f"{tmp_path / 'stub'}{os.pathsep}{CLIENTS}",
        "KOI_POINT_ID": "hello.home",
        "KOI_PREVIEW_URL": "http://app.run.invalid:8080",
        "KOI_RECORDER_WS": "ws://10.213.0.3:4317/token",
        "STUB_HEADING": heading,
        **({"STUB_NO_PAGE": "1"} if no_page else {}),
    }
    proc = subprocess.Popen(
        [sys.executable, str(RUNNER)],
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    events = []
    artifacts = iter(["recorder:screenshot:1", "recorder:http-response:2"])
    # koid's side: answer each capture or read with the next artifact.
    while True:
        line = proc.stdout.readline()
        if not line:
            break
        event = json.loads(line)
        events.append(event)
        if event["type"] in ("capture", "read"):
            ack = {"version": 1, "type": "capture-result", "label": event["label"], "status": "ready", "artifact": next(artifacts)}
            proc.stdin.write(json.dumps(ack) + "\n")
            proc.stdin.flush()
    code = proc.wait(timeout=30)
    return code, events, proc.stderr.read()


def test_passes_when_the_heading_says_hello(tmp_path):
    code, events, stderr = run(tmp_path, "hello from koi")
    assert code == 0, stderr
    assert [e["type"] for e in events] == ["capture", "read", "assertion"]
    assert events[0] == {"type": "capture", "kind": "screenshot", "label": "home"}
    assert events[1] == {"type": "read", "label": "home-state", "path": "/"}
    assert events[2] == {
        "type": "assertion",
        "point": "hello.home",
        "name": "home-says-hello",
        "outcome": "pass",
        "evidence": ["recorder:screenshot:1", "recorder:http-response:2"],
        "detail": 'the heading reads "hello from koi"',
    }


def test_fails_when_the_heading_says_something_else(tmp_path):
    code, events, stderr = run(tmp_path, "hello from nobody")
    assert code == 0, stderr
    assertion = events[-1]
    assert assertion["outcome"] == "fail"
    assert assertion["evidence"] == ["recorder:screenshot:1", "recorder:http-response:2"]
    assert assertion["detail"] == 'the heading reads "hello from nobody", not "hello from koi"'


def test_reports_blocked_without_a_page_of_the_app(tmp_path):
    code, events, stderr = run(tmp_path, "hello from koi", no_page=True)
    assert code == 1, stderr
    assert events == [
        {
            "type": "assertion",
            "point": "hello.home",
            "name": "home-says-hello",
            "outcome": "blocked",
            "evidence": [],
            "detail": "the recorder's browser has no page of http://app.run.invalid:8080; it has []",
        }
    ]
