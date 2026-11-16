#!/usr/bin/env python3
"""The runner for the hello.home point (docs/verify.md, "Writing a runner").

koi runs it in the verifier with the recorder's browser already open at the
preview's home page. It drives that page over the ws URL in KOI_RECORDER_WS,
reads the heading, asks koi for a screenshot and for the recorder's own read
of GET /, and reports one assertion citing both. koi decides the point's
outcome from that report and the artifacts it holds; the runner only says
what it saw.
"""

import sys

import koi_runner as koi
from playwright.sync_api import sync_playwright

EXPECTED = "hello from koi"


def main():
    env = koi.env()
    with sync_playwright() as p:
        browser = p.chromium.connect_over_cdp(env.recorder_ws, timeout=30_000)
        pages = [page for context in browser.contexts for page in context.pages]
        page = next((pg for pg in pages if pg.url.startswith(env.preview_url)), None)
        if page is None:
            koi.assertion(
                "home-says-hello",
                "blocked",
                detail=f"the recorder's browser has no page of {env.preview_url}; it has {[pg.url for pg in pages]}",
            )
            return 1
        page.goto(f"{env.preview_url}/", wait_until="load", timeout=15_000)
        heading = (page.text_content("h1") or "").strip()
        evidence = []
        try:
            evidence.append(koi.capture("screenshot", "home"))
        except koi.CaptureFailed as err:
            koi.note(f"the screenshot was not kept: {err.code}")
        try:
            evidence.append(koi.read("/", "home-state"))
        except koi.CaptureFailed as err:
            koi.note(f"the read of / was not kept: {err.code}")
        if heading == EXPECTED:
            koi.assertion("home-says-hello", "pass", evidence, detail=f'the heading reads "{heading}"')
        else:
            koi.assertion(
                "home-says-hello",
                "fail",
                evidence,
                detail=f'the heading reads "{heading}", not "{EXPECTED}"',
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
