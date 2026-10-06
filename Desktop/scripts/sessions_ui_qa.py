"""Exercise Sessions against an isolated API/browser. Never start the real app or collectors."""

import argparse
import json
import socket
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import uvicorn
from playwright.sync_api import expect, sync_playwright

from adr_desktop.api import create_app
from adr_desktop.config import prepare_state_dir
from adr_desktop.hooks import configuration_path
from adr_desktop.runtime import Runtime


class SessionsNative:
    connected = True

    def call(self, operation, arguments=None, timeout=30):
        if operation in ("login_status", "set_login"):
            return {"available": True, "enabled": False, "requires_approval": False}
        raise AssertionError(f"Sessions must not call native operations: {operation}")


def seed_sessions(runtime):
    """Only invented projects, messages, and results; no real logs or discovery."""
    runtime.store.setting("onboarding_complete", True)
    now = datetime.now(timezone.utc)

    def add(identifier, title, *, source="codex", project="garden", ago=0, messages=None, context=None):
        payload = {
            "source": source, "session_id": identifier, "username": "synthetic",
            "timestamp": (now - timedelta(days=ago)).isoformat(),
            "project_path": f"/workspace/synthetic/{project}", "model": "synthetic-model",
            "chat_history": messages or [
                {"role": "user", "content": title, "tools": []},
                {"role": "assistant", "content": "The synthetic validation check passes.", "tools": []},
            ],
        }
        if context:
            payload["session_context"] = context
        runtime.store.ingest(payload)
        return runtime.store.one("SELECT id FROM sessions WHERE source_session_id=?", (identifier,))["id"]

    parent_messages = [
        {"role": "developer", "content": "Synthetic setup only.", "tools": []},
        {"role": "developer", "content": "Synthetic setup only.", "tools": []},
        {"role": "user", "content": "Fix cache expiry in the garden app", "tools": []},
        {"role": "assistant", "content": "[Assistant decided to use a tool]", "tools": [{
            "tool_name": "Read", "arguments": {"file_path": "src/cache.py"}, "status": "success",
            "result": "Synthetic uninteresting output. " * 1000
            + "cedarneedle: expire the cache after the retry. <img src=x onerror=window.synthetic_xss=true> "
            + "Full synthetic trailing output. " * 300,
        }]},
        *[
            {"role": "user" if index % 2 else "assistant",
             "content": f"Synthetic garden context {index + 1}.\nKeep every original message.", "tools": []}
            for index in range(60)
        ],
        {"role": "assistant", "tools": [],
         "content": "lastanswerneedle: Use the validated expiry and retain the retry test."},
    ]
    parent = add("synthetic-garden-parent", "Fix cache expiry", messages=parent_messages)
    child = add("synthetic-garden-child", "Check the retry regression", context={
        "parent_session_id": "synthetic-garden-parent", "agent_path": "/root/verify_expiry_tests",
    })
    peer = add(
        "synthetic-notes-peer", "Reuse a cache fix", source="opencode", project="notes", ago=1, messages=[
            {"role": "user", "content": "Reuse a cache fix in notes", "tools": []},
            {"role": "assistant", "tools": [],
             "content": "cedarneedle: The note cache needs the same expiry check."},
        ],
    )
    for index in range(35):
        add(f"synthetic-archive-{index}", f"Improve synthetic input validation {index + 1}",
            source="claude" if index % 2 else "codex", project="notes" if index % 3 else "garden",
            ago=index + 2)
    return {"parent": parent, "child": child, "peer": peer}


def ready(page):
    expect(page.locator("#page")).to_have_attribute("aria-busy", "false")


def check_search_and_transcript(page, ids, output):
    search = page.get_by_label("Search your captured work", exact=True)
    expect(search).to_be_visible()
    assert search.evaluate("node => getComputedStyle(node).borderTopWidth") == "0px"
    assert search.evaluate("node => node.getBoundingClientRect().height") >= 46
    page.locator("h1").focus()
    page.keyboard.press("/")
    expect(search).to_be_focused()
    search.fill("cedarneedle")
    search.press("Enter")
    expect(page.locator(".sessions-results-heading")).to_contain_text("2 sessions found")
    expect(page.locator(".search-snippet mark")).to_have_count(2)
    assert "q=cedarneedle" in page.url
    page.get_by_label("Agent", exact=True).select_option("codex")
    expect(page.locator(".sessions-results-heading")).to_contain_text("1 session found")
    page.get_by_label("Project", exact=True).select_option("/workspace/synthetic/garden")
    ready(page)
    page.get_by_label("Updated", exact=True).select_option("today")
    ready(page)
    page.get_by_label("Sort search results").select_option("newest")
    ready(page)
    expect(search).to_have_value("cedarneedle")
    expect(page.get_by_label("Sort search results")).to_have_value("newest")
    page.screenshot(path=str(output / "sessions-search-light.png"), full_page=True)

    page.locator(f'a.session-row[href^="/sessions/{ids["parent"]}"]').click()
    expect(page.locator(".current-passage")).to_have_class("tool-call current-passage")
    expect(page.locator(".tool-bundle")).to_have_attribute("open", "")
    expect(page.locator(".tool-call")).to_have_attribute("open", "")
    expect(page.locator(".tool-body pre").last).to_contain_text("Full synthetic trailing output.")
    assert page.evaluate("window.synthetic_xss") is None
    assert page.locator(".tool-body img").count() == 0
    finder = page.get_by_label("Find in this session", exact=True)
    expect(finder).to_have_value("cedarneedle")
    finder.fill("lastanswerneedle")
    finder.press("Enter")
    expect(page.locator(".current-passage")).to_contain_text("Use the validated expiry")
    expect(page.locator(".transcript-match-status")).to_have_text("1 of 1 matching passages")
    page.get_by_role("button", name="Next matching passage", exact=True).click()
    expect(page.locator(".transcript-match-status")).to_have_text("1 of 1 matching passages")
    page.get_by_role("button", name="Previous matching passage", exact=True).click()
    expect(page.locator(".transcript-match-status")).to_have_text("1 of 1 matching passages")

    # Stub clipboard in this disposable document; do not overwrite the host clipboard.
    page.evaluate("""Object.defineProperty(navigator, "clipboard", {configurable:true, value:{
        writeText: async text => {window.syntheticCopiedAnswer = text}
    }})""")
    page.locator(".current-passage").get_by_role("button", name="Copy answer").click()
    assert page.evaluate("window.syntheticCopiedAnswer").startswith("lastanswerneedle:")
    page.get_by_role("button", name="Clear session search", exact=True).click()
    expect(finder).to_have_value("")
    assert "find=" in page.url
    page.get_by_role("link", name="Latest answer", exact=True).click()
    expect(page.locator(".current-passage")).to_be_focused()
    page.get_by_role("link", name="Back to search results", exact=True).click()
    ready(page)
    expect(search).to_have_value("cedarneedle")
    expect(page.get_by_label("Agent", exact=True)).to_have_value("codex")
    expect(page.get_by_label("Project", exact=True)).to_have_value("/workspace/synthetic/garden")
    expect(page.get_by_label("Updated", exact=True)).to_have_value("today")
    page.reload()
    ready(page)
    expect(search).to_have_value("cedarneedle")
    expect(page.get_by_label("Sort search results")).to_have_value("newest")

    search.focus()
    search.press("Escape")
    ready(page)
    expect(search).to_have_value("")
    expect(search).to_be_focused()
    expect(page.get_by_label("Agent", exact=True)).to_have_value("codex")
    page.get_by_role("button", name="Clear all", exact=True).click()
    ready(page)
    assert page.url.endswith("/sessions")
    page.go_back()
    ready(page)
    expect(page.get_by_label("Agent", exact=True)).to_have_value("codex")
    page.go_forward()
    ready(page)
    expect(page.get_by_label("Agent", exact=True)).to_have_value("")


def check_browse_and_state(page, ids, base):
    expect(page.locator(".session-results-list > li")).to_have_count(30)
    page.get_by_role("button", name="Next", exact=True).click()
    ready(page)
    assert "offset=30" in page.url
    expect(page.locator("#sessions-results-title")).to_be_focused()
    expect(page.locator(".session-results-list > li")).to_have_count(7)
    page.get_by_role("button", name="Previous", exact=True).click()
    ready(page)
    parent = page.locator(".session-family").filter(
        has=page.locator(f'a.session-row[href="/sessions/{ids["parent"]}"]')
    ).first
    parent.locator(".session-children > summary").click()
    page.locator(f'a.session-row[href="/sessions/{ids["child"]}"]').wait_for()
    page.locator(f'a.session-row[href="/sessions/{ids["parent"]}"]').click()
    ready(page)
    expect(page.get_by_role("heading", name="Related work", exact=True)).to_be_visible()
    page.locator(".session-children > summary").click()
    page.locator(f'a.session-row[href="/sessions/{ids["child"]}"]').click()
    ready(page)
    expect(page.get_by_role("heading", name="verify expiry tests", exact=True)).to_be_focused()
    page.go_back()
    ready(page)
    expect(page.locator(".session-children")).to_have_attribute("open", "")
    expect(page.locator(f'a.session-row[href="/sessions/{ids["child"]}"]')).to_be_focused()
    expect(page.locator(".setup-bundle > summary")).to_contain_text("2 entries")
    page.locator(".setup-bundle > summary").click()
    expect(page.locator(".setup-entry > summary")).to_contain_text("2 occurrences")

    # Refresh retains reading position and expanded source details.
    page.evaluate("window.scrollTo(0, 850)")
    page.wait_for_timeout(150)
    page.get_by_role("button", name="Refresh", exact=True).evaluate("node => node.click()")
    ready(page)
    assert abs(page.evaluate("window.scrollY") - 850) < 5
    expect(page.locator(".setup-bundle")).to_have_attribute("open", "")

    page.goto(base + "/sessions?date=custom&from=2026-10-07&to=2026-10-01")
    ready(page)
    expect(page.get_by_role("alert")).to_contain_text("The end date must be on or after")
    expect(page.get_by_label("Search your captured work", exact=True)).to_be_visible()
    expect(page.get_by_label("From", exact=True)).to_have_value("2026-10-07")
    page.get_by_role("button", name="Clear all", exact=True).click()
    ready(page)
    page.get_by_label("Search your captured work", exact=True).fill("no_such_synthetic_answer")
    page.get_by_label("Agent", exact=True).select_option("opencode")
    ready(page)
    expect(page.get_by_label("Search your captured work", exact=True)).to_have_value(
        "no_such_synthetic_answer"
    )
    expect(page.get_by_role("heading", name="No sessions match yet", exact=True)).to_be_visible()
    page.get_by_role("button", name="Clear search and filters", exact=True).click()
    ready(page)
    assert page.locator(".sessions-page").evaluate(
        "node => [...node.childNodes].every(child => child.nodeType !== 3 || !child.textContent.trim())"
    )


def check_error_and_races(page):
    def fail(route):
        route.fulfill(status=500, content_type="application/json",
                      body=json.dumps({"detail": "Synthetic search failure"}))

    page.route("**/api/history/search?**", fail)
    search = page.get_by_label("Search your captured work", exact=True)
    search.fill("cedarneedle")
    search.press("Enter")
    expect(page.get_by_role("alert")).to_contain_text("Synthetic search failure")
    expect(page.get_by_role("alert")).to_be_focused()
    expect(search).to_have_value("cedarneedle")
    page.unroute("**/api/history/search?**", fail)
    page.get_by_role("button", name="Try again", exact=True).click()
    expect(page.locator(".sessions-results-heading")).to_contain_text("2 sessions found")
    held = []

    def delay(route):
        if "slowneedle" in route.request.url:
            held.append(route)
        else:
            route.continue_()

    page.route("**/api/history/search?**", delay)
    search.fill("slowneedle")
    search.press("Enter")
    expect(page.locator("#view-status")).to_have_text("Opening view…")
    search.fill("cedarneedle")
    page.get_by_label("Agent", exact=True).select_option("opencode")
    expect(page.locator(".sessions-results-heading")).to_contain_text("1 session found")
    assert held
    held[0].fulfill(status=200, content_type="application/json", body=json.dumps({
        "items": [], "total": 0, "offset": 0, "limit": 30, "next_offset": None,
    }))
    page.wait_for_timeout(100)
    expect(page.locator(".sessions-results-heading")).to_contain_text("1 session found")
    expect(search).to_have_value("cedarneedle")
    page.unroute("**/api/history/search?**", delay)


def check_responsive(page, output):
    for width, scheme in ((1440, "dark"), (390, "light"), (390, "dark")):
        page.set_viewport_size({"width": width, "height": 940})
        page.emulate_media(color_scheme=scheme, reduced_motion="reduce")
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        search = page.get_by_label("Search your captured work", exact=True)
        search.focus()
        assert search.evaluate("node => getComputedStyle(node.parentElement).outlineStyle") != "none"
        assert search.evaluate("node => getComputedStyle(node).borderTopWidth") == "0px"
        page.screenshot(path=str(output / f"sessions-search-{width}-{scheme}.png"), full_page=True)
    page.locator("a.session-row").first.click()
    ready(page)
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    page.screenshot(path=str(output / "sessions-transcript-narrow-dark.png"), full_page=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    output = args.output or Path(tempfile.mkdtemp(prefix="adr-sessions-qa-images-"))
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="adr-sessions-qa-") as folder:
        home = Path(folder) / "home"
        home.mkdir()

        def fixture_path(harness, override=None):
            return configuration_path(harness, override or home)

        with (
            patch.object(Path, "home", return_value=home),
            patch("adr_desktop.hooks.configuration_path", fixture_path),
            patch("adr_desktop.runtime.configuration_path", fixture_path),
            patch("adr_desktop.runtime.publish_target"),
            patch("adr_desktop.runtime.upgrade_guard"),
        ):
            runtime = Runtime(
                prepare_state_dir(Path(folder) / "state"), SessionsNative(), start_collectors=False,
            )
            ids = seed_sessions(runtime)
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            listener.listen(64)
            runtime.port = listener.getsockname()[1]
            server = uvicorn.Server(uvicorn.Config(
                create_app(runtime), log_level="error", access_log=False, proxy_headers=False,
            ))
            worker = threading.Thread(target=lambda: server.run(sockets=[listener]), daemon=True)
            worker.start()
            for _ in range(100):
                if server.started:
                    break
                time.sleep(0.02)
            errors = []
            try:
                with sync_playwright() as playwright:
                    browser = playwright.chromium.launch()
                    context = browser.new_context(
                        viewport={"width": 1440, "height": 1000}, timezone_id="Europe/Amsterdam",
                    )
                    page = context.new_page()
                    page.on("pageerror", lambda error: errors.append(str(error)))
                    base = f"http://127.0.0.1:{runtime.port}"
                    page.goto(f"{base}/sessions#ticket={runtime.new_ticket()}")
                    page.get_by_role("heading", name="Sessions", exact=True).wait_for()
                    ready(page)
                    check_search_and_transcript(page, ids, output)
                    check_browse_and_state(page, ids, base)
                    check_error_and_races(page)
                    check_responsive(page, output)
                    context.close()
                    browser.close()
                if errors:
                    raise AssertionError("\n".join(errors))
                print(json.dumps({
                    "sessions_ui_qa": "passed", "data": "synthetic only", "screenshots": str(output),
                }))
            finally:
                server.should_exit = True
                worker.join(timeout=5)
                runtime.close()
                listener.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
