"""Check route, keyboard and dialog behavior with synthetic local data only."""

import json
import socket
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import uvicorn
from playwright.sync_api import expect, sync_playwright
from ui_qa import SyntheticNative, SyntheticPluginDriver, seed

from adr_desktop.api import create_app
from adr_desktop.config import prepare_state_dir
from adr_desktop.hooks import configuration_path
from adr_desktop.runtime import Runtime


def seed_conversation(runtime, name, *, parent=None):
    payload = {
        "source": "codex",
        "session_id": f"codex_navigation_{name}",
        "username": "synthetic",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "project_path": "/workspace/synthetic/navigation",
        "model": "synthetic-model",
        "chat_history": [
            {
                "role": "user" if index % 2 == 0 else "assistant",
                "content": f"Navigation {name} message {index + 1}\nSynthetic test content.",
                "tools": [],
            }
            for index in range(40)
        ],
    }
    if parent:
        payload["session_context"] = {"parent_session_id": f"codex_navigation_{parent}"}
    runtime.store.ingest(payload)
    return runtime.store.one(
        "SELECT id FROM sessions WHERE source_session_id=?", (payload["session_id"],)
    )["id"]


def wait_for_view(page):
    expect(page.locator("#page")).to_have_attribute("aria-busy", "false")


def check_routes(page, parent_id, child_id):
    page.locator('a[data-route="/sessions"]').click()
    page.get_by_role("heading", name="Sessions", exact=True).wait_for()
    wait_for_view(page)
    parent = page.locator(f'a.session-row[href="/sessions/{parent_id}"]')
    parent.click()
    expect(page.locator(".conversation > .message")).to_have_count(40)
    wait_for_view(page)
    assert page.evaluate("window.scrollY") == 0
    expect(page.locator("h1")).to_be_focused()

    # Related work now sits near the top. Even after scrolling the parent,
    # its child must open at the beginning and Back must restore the parent.
    page.locator(".session-children > summary").click()
    child = page.locator(f'a.session-row[href="/sessions/{child_id}"]')
    child.wait_for()
    page.evaluate("window.scrollTo(0, 120)")
    child.scroll_into_view_if_needed()
    old_scroll = page.evaluate("window.scrollY")
    assert old_scroll > 0
    child.click()
    expect(page.get_by_text(
        "Navigation child message 1\nSynthetic test content.", exact=True
    )).to_be_visible()
    wait_for_view(page)
    assert page.evaluate("window.scrollY") == 0
    expect(page.locator("h1")).to_be_focused()

    page.go_back()
    expect(page.locator(".session-children")).to_have_attribute("open", "")
    wait_for_view(page)
    assert abs(page.evaluate("window.scrollY") - old_scroll) <= 2
    expect(page.locator(f'a.session-row[href="/sessions/{child_id}"]')).to_be_visible()

    # An ordinary refresh must not reset the reader's position.
    page.evaluate("window.scrollTo(0, 800)")
    # Use the rendered sticky-header location. Locator.click() otherwise asks
    # Chromium to scroll this already-visible sticky button into view.
    refresh_box = page.get_by_role("button", name="Refresh", exact=True).bounding_box()
    page.mouse.click(
        refresh_box["x"] + refresh_box["width"] / 2,
        refresh_box["y"] + refresh_box["height"] / 2,
    )
    wait_for_view(page)
    after_refresh = page.evaluate("window.scrollY")
    assert abs(after_refresh - 800) <= 2, f"Refresh moved the transcript to {after_refresh}"

    # A slow request finishing after a newer navigation must not overwrite it
    # or pull the page back to the old transcript's scroll position.
    page.locator('a[data-route="/sessions"]').click()
    page.get_by_role("heading", name="Sessions", exact=True).wait_for()
    held = []

    def defer(route):
        held.append(route)

    page.route(f"**/api/sessions/{parent_id}", defer)
    try:
        page.locator(f'a.session-row[href="/sessions/{parent_id}"]').click()
        expect(page.locator("#view-status")).to_have_text("Opening view…")
        expect(page.locator("#page")).to_have_attribute("aria-busy", "true")
        page.locator('a[data-route="/settings"]').click()
        page.get_by_role("heading", name="Your device. Your settings.", exact=True).wait_for()
        assert held
        with page.expect_response(f"**/api/sessions/{parent_id}"):
            held[0].continue_()
        page.evaluate("new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))")
        wait_for_view(page)
        expect(page.get_by_role("heading", name="Your device. Your settings.", exact=True)).to_be_visible()
        assert page.evaluate("window.scrollY") == 0
    finally:
        page.unroute(f"**/api/sessions/{parent_id}", defer)

    # Links remain actual links. Browser modifiers should not be hijacked by
    # the client router (test cancellation, without opening another profile).
    for modifiers in (
        {"metaKey": True}, {"ctrlKey": True}, {"shiftKey": True}, {"altKey": True}, {"button": 1}
    ):
        result = page.locator('a[data-route="/sessions"]').evaluate(
            """(node, modifiers) => {
                const event = new MouseEvent("click", {
                    bubbles: true, cancelable: true, button: 0, ...modifiers
                });
                let intercepted;
                node.addEventListener("click", e => {
                    intercepted = e.defaultPrevented;
                    e.preventDefault(); // Suppress the real new tab, after the router has run.
                }, {once: true});
                node.dispatchEvent(event);
                return intercepted;
            }""",
            modifiers,
        )
        assert result is False


def check_dialog(page):
    page.locator('a[data-route="/protection"]').click()
    page.get_by_role("button", name="Protect a path", exact=True).click()
    modal = page.get_by_role("dialog", name="Protect a file or folder", exact=True)
    expect(modal).to_be_visible()
    path = modal.get_by_label("File or folder", exact=True)
    path.fill("/workspace/synthetic/keep-this-value")
    modal.get_by_label("Name", exact=True).fill("Preserved form")
    attempts = []
    pending = []

    def reject(route):
        attempts.append(route.request.method)
        pending.append(route)

    page.route("**/api/protection/rules", reject)
    try:
        modal.get_by_role("button", name="Add protection", exact=True).click()
        expect(modal.locator("form")).to_have_attribute("aria-busy", "true")
        expect(modal.get_by_role("button", name="Working…", exact=True)).to_be_disabled()
        # A second form-submit event cannot create a duplicate request.
        modal.locator("form").evaluate("node => node.requestSubmit()")
        assert attempts == ["POST"]
        pending[0].fulfill(
            status=400,
            content_type="application/json",
            body=json.dumps({"detail": "Synthetic validation error: choose an absolute file path."}),
        )
        error = modal.get_by_role("alert")
        expect(error).to_contain_text("Synthetic validation error")
        expect(error).to_be_focused()
        expect(path).to_have_value("/workspace/synthetic/keep-this-value")
        expect(modal.get_by_label("Name", exact=True)).to_have_value("Preserved form")
        expect(modal.get_by_role("button", name="Add protection", exact=True)).to_be_enabled()
        expect(modal.locator("form")).to_have_attribute("aria-busy", "false")
        assert attempts == ["POST"]
        page.keyboard.press("Escape")
        expect(modal).to_have_count(0)
        expect(page.get_by_role("button", name="Protect a path", exact=True)).to_be_focused()
    finally:
        page.unroute("**/api/protection/rules", reject)


def check_keyboard_and_layout(page):
    page.locator(".skip-link").focus()
    expect(page.get_by_role("link", name="Skip to content")).to_be_visible()
    page.keyboard.press("Enter")
    expect(page.locator("#page")).to_be_focused()
    for width, scheme in ((1440, "light"), (390, "light"), (390, "dark")):
        page.set_viewport_size({"width": width, "height": 900})
        page.emulate_media(color_scheme=scheme, reduced_motion="reduce")
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
        assert page.get_by_role("button", name="Protect a path", exact=True).evaluate(
            "node => getComputedStyle(node).transitionDuration"
        ) == "0s"
        assert page.locator('a[data-route="/sessions"]').get_attribute("title") == "Sessions"


def check_narrow_dialog(page):
    page.set_viewport_size({"width": 390, "height": 900})
    page.emulate_media(color_scheme="dark")
    page.locator('a[data-route="/credentials"]').click()
    page.get_by_role("button", name="Add API credential", exact=True).click()
    modal = page.get_by_role("dialog", name="Add an API credential", exact=True)
    fields = modal.locator(".form-fields")
    heading = modal.locator(".dialog-heading")
    footer = modal.locator(".dialog-actions")
    save = modal.get_by_role("button", name="Continue to secure window", exact=True)
    expect(save).to_be_in_viewport(ratio=1)
    original_heading = heading.bounding_box()
    original_footer = footer.bounding_box()
    modal.get_by_label("Name", exact=True).fill("Synthetic narrow dialog")
    modal.get_by_label("Credential type", exact=True).select_option("api_key")
    modal.get_by_label("Service URL", exact=True).fill("https://api.example.com")
    modal.locator(".vault-details > summary").click()
    paths = modal.get_by_label("Allowed paths", exact=True)
    paths.fill("/synthetic")
    expect(paths).to_be_focused()
    expect(paths).to_be_in_viewport(ratio=1)
    expect(save).to_be_in_viewport(ratio=1)
    assert fields.evaluate("node => node.scrollTop > 0")
    assert modal.evaluate("node => node.scrollTop === 0")
    assert abs(heading.bounding_box()["y"] - original_heading["y"]) <= 2
    assert abs(footer.bounding_box()["y"] - original_footer["y"]) <= 2
    field_box, body_box, footer_box = paths.bounding_box(), fields.bounding_box(), footer.bounding_box()
    assert field_box["y"] >= body_box["y"]
    assert field_box["y"] + field_box["height"] <= footer_box["y"]

    def reject(route):
        route.fulfill(
            status=400,
            content_type="application/json",
            body=json.dumps({"detail": "Synthetic validation error. Your inputs have been kept."}),
        )

    page.route("**/api/credentials", reject)
    try:
        save.click()
        error = modal.get_by_role("alert")
        expect(error).to_be_focused()
        expect(error).to_be_in_viewport(ratio=1)
        expect(save).to_be_in_viewport(ratio=1)
        expect(paths).to_have_value("/synthetic")
        # Keyboard focus can still reach a field after the inline error takes
        # space; the footer does not overlay the scrollable body.
        paths.focus()
        expect(paths).to_be_in_viewport(ratio=1)
        expect(save).to_be_in_viewport(ratio=1)
        screenshots = Path(__file__).resolve().parents[1] / "screenshots"
        screenshots.mkdir(exist_ok=True)
        page.screenshot(path=str(screenshots / "synthetic-dialog-body-scroll-dark.png"), full_page=True)
        modal.get_by_role("button", name="Close dialog", exact=True).click()
    finally:
        page.unroute("**/api/credentials", reject)


def main():
    with tempfile.TemporaryDirectory(prefix="adr-navigation-qa-") as folder:
        home = Path(folder) / "home"
        home.mkdir()

        def fixture_path(harness, override=None):
            return configuration_path(harness, override or home)

        with (
            patch.object(Path, "home", return_value=home),
            patch("adr_desktop.hooks.configuration_path", fixture_path),
            patch("adr_desktop.runtime.configuration_path", fixture_path),
        ):
            runtime = Runtime(
                prepare_state_dir(Path(folder) / "state"), SyntheticNative(), start_collectors=False
            )
            runtime.integration_driver = SyntheticPluginDriver()
            seed(runtime)
            parent_id = seed_conversation(runtime, "parent")
            child_id = seed_conversation(runtime, "child", parent="parent")
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            listener.listen(64)
            runtime.port = listener.getsockname()[1]
            server = uvicorn.Server(
                uvicorn.Config(create_app(runtime), log_level="error", access_log=False, proxy_headers=False)
            )
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
                    context = browser.new_context(viewport={"width": 1440, "height": 1040})
                    page = context.new_page()
                    page.on("pageerror", lambda error: errors.append(str(error)))
                    page.goto(f"http://127.0.0.1:{runtime.port}/#ticket={runtime.new_ticket()}")
                    page.get_by_role("heading", name="Your agents, at a glance").wait_for()
                    check_routes(page, parent_id, child_id)
                    check_dialog(page)
                    check_keyboard_and_layout(page)
                    check_narrow_dialog(page)
                    context.close()
                    browser.close()
                if errors:
                    raise AssertionError("\n".join(errors))
                print(json.dumps({"navigation_qa": "passed", "data": "synthetic only"}))
            finally:
                server.should_exit = True
                worker.join(timeout=5)
                runtime.close()
                listener.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
