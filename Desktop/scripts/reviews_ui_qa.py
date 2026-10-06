"""Real owner API/UI and CLI-protocol subprocesses; synthetic evidence, no model calls."""

import json
import os
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import patch

import uvicorn
from playwright.sync_api import expect, sync_playwright
from ui_qa import SyntheticNative, SyntheticPluginDriver, seed

from adr_desktop.api import create_app
from adr_desktop.config import prepare_state_dir
from adr_desktop.hooks import configuration_path
from adr_desktop.review_process import LocalReviewDriver
from adr_desktop.runtime import Runtime

FIXTURE = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "review_cli.py"


def main():
    shots = Path(tempfile.mkdtemp(prefix="adr-review-ui-shots-"))
    with tempfile.TemporaryDirectory(prefix="adr-review-ui-") as temporary:
        base = Path(temporary)
        home = base / "home"
        home.mkdir()

        def config(harness, override=None):
            return configuration_path(harness, override or home)

        with (
            patch.object(Path, "home", return_value=home),
            patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": str(home / ".claude")}),
            patch("adr_desktop.hooks.configuration_path", config),
            patch("adr_desktop.runtime.configuration_path", config),
        ):
            runtime = Runtime(prepare_state_dir(base / "state"), SyntheticNative(), start_collectors=False)
            runtime.integration_driver = SyntheticPluginDriver()
            runtime.reviews.driver = LocalReviewDriver(
                {
                    "claude": [sys.executable, str(FIXTURE), "claude", "finding"],
                    "codex": [sys.executable, str(FIXTURE), "codex", "success"],
                }
            )
            seed(runtime)
            listener = socket.socket()
            server = None
            thread = None
            try:
                listener.bind(("127.0.0.1", 0))
                listener.listen(64)
                runtime.port = listener.getsockname()[1]
                server = uvicorn.Server(
                    uvicorn.Config(
                        create_app(runtime),
                        log_level="error",
                        access_log=False,
                        proxy_headers=False,
                    )
                )
                thread = threading.Thread(target=lambda: server.run(sockets=[listener]), daemon=True)
                thread.start()
                for _ in range(100):
                    if server.started:
                        break
                    time.sleep(0.02)
                with sync_playwright() as playwright:
                    browser = playwright.chromium.launch()
                    page = browser.new_page(viewport={"width": 1440, "height": 1040})
                    errors, outside = [], []
                    page.on("pageerror", lambda error: errors.append(str(error)))
                    page.on(
                        "request",
                        lambda req: (
                            outside.append(req.url)
                            if not req.url.startswith(f"http://127.0.0.1:{runtime.port}/")
                            else None
                        ),
                    )
                    page.goto(f"http://127.0.0.1:{runtime.port}/#ticket={runtime.new_ticket()}")
                    page.get_by_role("link", name="Security reviews", exact=True).click()
                    page.get_by_role("heading", name="Security reviews", exact=True).wait_for()
                    page.get_by_role("button", name="Review now", exact=True).click()
                    modal = page.get_by_role("dialog", name="Security review settings", exact=True)
                    expect(modal).to_be_visible()
                    modal.get_by_label("Tokens per review", exact=True).fill("1000")
                    modal.get_by_label("Review tokens per 24 hours", exact=True).fill("5000")
                    consent = modal.get_by_role(
                        "checkbox", name="I approve sending selected session evidence", exact=False
                    )
                    consent.check()
                    modal.get_by_role("button", name="Save review settings", exact=True).click()
                    expect(modal).to_have_count(0)
                    assert runtime.reviews.preferences()["consented"]
                    assert not runtime.reviews.preferences()["background"]
                    page.get_by_role("button", name="Review now", exact=True).click()
                    launch = page.get_by_role("dialog", name="Review a captured session", exact=True)
                    launch.get_by_role("button", name="Start review", exact=True).click()
                    expect(launch).to_have_count(0)
                    expect(page.get_by_text("Synthetic finding", exact=True)).to_be_visible(timeout=15000)
                    page.get_by_text("Synthetic finding", exact=True).click()
                    page.get_by_role("link", name="View in session", exact=True).click()
                    expect(page.locator(".session-detail")).to_be_visible()
                    page.go_back()
                    page.get_by_role("heading", name="Security reviews", exact=True).wait_for()
                    expect(page.locator(".review-job")).to_have_count(1)

                    page.get_by_text("Agent usage and capacity", exact=True).click()
                    page.get_by_role("button", name="Connect Claude usage", exact=True).click()
                    connect = page.get_by_role("dialog", name="Connect Claude usage reporting?", exact=True)
                    connect.get_by_role("button", name="Connect usage", exact=True).click()
                    expect(connect).to_have_count(0)
                    expect(
                        page.get_by_role("button", name="Disconnect Claude usage", exact=True)
                    ).to_be_visible()
                    assert "review-statusline" in (home / ".claude" / "settings.json").read_text()

                    page.get_by_role("button", name="Review settings", exact=True).click()
                    modal.get_by_label("Agent", exact=True).select_option("codex")
                    modal.get_by_role(
                        "checkbox", name="I approve sending selected session evidence", exact=False
                    ).check()
                    modal.get_by_role("button", name="Save review settings", exact=True).click()
                    expect(modal).to_have_count(0)
                    if page.locator(".review-usage").get_attribute("open") is None:
                        page.get_by_text("Agent usage and capacity", exact=True).click()
                    page.get_by_role("button", name="Refresh agent usage", exact=True).click()
                    expect(page.locator(".review-quota-window")).to_have_count(2)
                    page.get_by_role("button", name="Review now", exact=True).click()
                    launch.get_by_role("button", name="Start review", exact=True).click()
                    expect(page.locator(".review-job")).to_have_count(2, timeout=15000)
                    expect(page.get_by_text("Synthetic review completed.", exact=True)).to_be_visible(
                        timeout=15000
                    )
                    expect(page.locator(".toast")).to_have_count(0, timeout=10000)
                    for width, scheme in ((1440, "light"), (390, "light"), (390, "dark")):
                        page.set_viewport_size({"width": width, "height": 1040})
                        page.emulate_media(color_scheme=scheme)
                        page.evaluate("window.scrollTo(0,0)")
                        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
                        page.screenshot(path=str(shots / f"reviews-{width}-{scheme}.png"), full_page=True)
                    assert not errors, errors
                    assert not outside, outside
                    browser.close()
                print(
                    json.dumps(
                        {
                            "reviews_ui_qa": "passed",
                            "screenshots": str(shots),
                            "data": "synthetic",
                            "model_requests": 0,
                        }
                    )
                )
            finally:
                if server:
                    server.should_exit = True
                if thread:
                    thread.join(timeout=5)
                runtime.close()
                listener.close()


if __name__ == "__main__":
    main()
