"""Exercise first-run setup using an empty profile and synthetic integrations."""

import argparse
import copy
import json
import socket
import tempfile
import threading
import time
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import uvicorn
from playwright.sync_api import expect, sync_playwright
from qa_support import browser_evidence, isolated_agent_profile
from ui_qa import SyntheticNative, SyntheticPluginDriver

from adr_desktop.agent_plugins import read_receipt
from adr_desktop.api import create_app
from adr_desktop.config import prepare_state_dir
from adr_desktop.runtime import Runtime


class SetupNative(SyntheticNative):
    def __init__(self):
        super().__init__()
        self.calls = []

    def call(self, operation, arguments=None, timeout=30):
        self.calls.append(operation)
        return super().call(operation, arguments, timeout)


class SetupPlugins(SyntheticPluginDriver):
    def __init__(self):
        super().__init__()
        self.available = {"claude", "codex"}
        self.fail = {"codex"}
        self.installs = []

    def executable(self, harness):
        if harness not in self.available:
            raise ValueError("Synthetic agent is not installed")
        return super().executable(harness)

    def install(self, harness, *_args, **_kwargs):
        self.installs.append(harness)
        if harness in self.fail:
            raise ValueError("Synthetic plugin installation failure")


class NoModel:
    def available(self):
        return {"claude": True, "codex": True}

    def probe(self, *_args, **_kwargs):
        raise AssertionError("Opening setup must not probe a model provider")

    def run(self, *_args, **_kwargs):
        raise AssertionError("Opening setup must not run a model")


def open_setup(page):
    page.locator('a[data-route="/settings"]').click()
    page.get_by_role("heading", name="Setup & settings", exact=True).wait_for()
    expect(page.locator("#page")).to_have_attribute("aria-busy", "false")


def check_passive_setup(page, runtime, writes, shots):
    initial_settings = runtime.store.settings()
    initial_policy = copy.deepcopy(runtime.policy)
    expect(page.locator(".metric-grid")).to_have_count(0)
    page.screenshot(path=str(shots / "first-run-overview.png"), full_page=True)
    page.get_by_role("link", name="Set up ADR", exact=True).click()
    page.get_by_role("heading", name="Setup & settings", exact=True).wait_for()
    expect(page.get_by_role("heading", name="Agent connections", exact=True)).to_be_visible()
    expect(page.get_by_label("Capture interval", exact=True)).to_be_hidden()
    expect(page.get_by_role("button", name="Open Full Disk Access", exact=True)).to_be_hidden()
    expect(page.get_by_role("button", name="Delete history", exact=True)).to_be_hidden()
    expect(page.get_by_role("button", name="Start local capture", exact=True)).to_be_visible()
    page.screenshot(path=str(shots / "first-run-setup.png"), full_page=True)

    for route, heading in (
        ("/sessions", "Sessions"), ("/inventory", "AI inventory"),
        ("/reviews", "Security reviews"), ("/protection", "File protection"),
        ("/threats", "Malicious artifacts"), ("/credentials", "Credential vault"),
    ):
        page.locator(f'a[data-route="{route}"]').click()
        page.get_by_role("heading", name=heading, exact=True).wait_for()
        expect(page.locator("#page")).to_have_attribute("aria-busy", "false")
        if route in ("/protection", "/credentials"):
            expect(page.get_by_role("button", name="Connect installed agents", exact=True)).to_have_count(0)
            page.get_by_role("link", name="Manage agent connections", exact=True).click()
            page.get_by_role("heading", name="Setup & settings", exact=True).wait_for()
            expect(page.locator("h1")).to_be_focused()
            page.go_back()
            page.get_by_role("heading", name=heading, exact=True).wait_for()
    assert writes == [], f"Viewing a feature caused a mutation: {writes}"
    page.locator('a[data-route="/"]').click()
    page.get_by_role("button", name="Hide introduction", exact=True).click()
    expect(page.locator(".welcome")).to_have_count(0)
    assert writes == [("PATCH", "/api/settings", {"onboarding_complete": True})]
    assert runtime.store.settings() == {**initial_settings, "onboarding_complete": True}
    assert runtime.policy == initial_policy
    assert runtime.integration_driver.installs == []
    assert runtime.store.rows("SELECT id FROM grants") == []
    assert runtime.collector.status()["inventory_phase"] == "idle"
    assert not runtime.reviews.preferences()["consented"]
    assert not runtime.reviews.preferences()["background"]
    assert set(runtime.native.calls) <= {"file_access_identity", "login_status", "vault_storage_status"}

    # Dismissing the introduction survives reload, without becoming an
    # assertion that capture or protection has been configured.
    page.reload()
    page.get_by_role("heading", name="Your agents, at a glance", exact=True).wait_for()
    expect(page.locator(".welcome")).to_have_count(0)
    expect(page.get_by_role("button", name="Start capture", exact=True)).to_be_visible()


def check_capture(page, runtime):
    open_setup(page)

    def reject(route):
        route.fulfill(status=503, json={"detail": "Synthetic capture failure. Try again."})

    page.route("**/api/collector/start", reject)
    try:
        page.get_by_role("button", name="Start local capture", exact=True).click()
        expect(page.get_by_role("alert")).to_contain_text("Synthetic capture failure")
        expect(page.get_by_role("button", name="Start local capture", exact=True)).to_be_enabled()
        expect(page.get_by_role("button", name="Start capture", exact=True)).to_be_enabled()
        assert runtime.store.settings()["recording"] is False
    finally:
        page.unroute("**/api/collector/start", reject)

    held = []
    page.route("**/api/collector/start", lambda route: held.append(route))
    try:
        page.get_by_role("button", name="Start local capture", exact=True).click()
        expect(page.get_by_role("button", name="Start local capture", exact=True)).to_be_disabled()
        header = page.get_by_role("button", name="Start capture", exact=True)
        expect(header).to_be_disabled()
        header.dispatch_event("click")
        assert len(held) == 1, "Both controls must share the in-flight capture action"
        with page.expect_response("**/api/collector/start"):
            held[0].continue_()
        expect(page.get_by_role("button", name="Pause local capture", exact=True)).to_be_enabled()
        expect(page.get_by_role("button", name="Pause local capture", exact=True)).to_be_focused()
        expect(page.get_by_role("button", name="Pause capture", exact=True)).to_be_enabled()
        expect(page.get_by_text("Capture is on", exact=True)).to_be_visible()
        assert runtime.store.settings()["recording"] is True
    finally:
        page.unroute("**/api/collector/start")
    page.get_by_role("button", name="Pause local capture", exact=True).click()
    expect(page.get_by_text("Capture is paused", exact=True)).to_be_visible()
    expect(page.get_by_role("button", name="Start local capture", exact=True)).to_be_focused()
    assert runtime.store.settings()["recording"] is False


def check_connections(page, runtime, writes, shots):
    before = list(writes)
    page.get_by_role("button", name="Connect installed agents", exact=True).click()
    consent = page.get_by_role("dialog", name="Connect installed agents", exact=True)
    expect(consent).to_contain_text("across this device")
    expect(consent).to_contain_text("including credentials you add later")
    expect(consent).to_contain_text("Local programs receive the real values")
    page.keyboard.press("Escape")
    expect(consent).to_have_count(0)
    assert writes == before and runtime.integration_driver.installs == []

    page.get_by_role("button", name="Connect installed agents", exact=True).click()
    with page.expect_response("**/api/integrations/connect-all", timeout=60000) as response:
        consent.get_by_role("button", name="Connect installed agents", exact=True).click()
    assert response.value.status == 200
    assert {item["harness"]: item["status"] for item in response.value.json()["items"]} == {
        "claude": "configured", "codex": "needs_repair",
        "opencode": "not_installed", "copilot": "not_installed",
    }
    results = page.get_by_role("dialog", name="ADR connection results", exact=True)
    expect(results).to_contain_text("Completed connections are kept")
    expect(results).to_contain_text("Setup failed")
    expect(results).to_contain_text("CLI not found")
    results.get_by_role("button", name="Done", exact=True).click()
    rows = page.locator(".integration-list > li")
    claude = rows.filter(has=page.get_by_text("Claude Code", exact=True))
    expect(claude).to_contain_text("Configured")
    expect(claude).to_contain_text("No hook activity received yet")
    assert len(runtime.store.rows("SELECT id FROM grants WHERE revoked=0")) == 1
    saved_grant = read_receipt(runtime.state_dir, "claude")["grant_id"]
    page.screenshot(path=str(shots / "setup-partial-connections.png"), full_page=True)

    runtime.integration_driver.fail.clear()
    page.get_by_role("button", name="Update installed agents", exact=True).click()
    with page.expect_response("**/api/integrations/connect-all", timeout=60000):
        consent.get_by_role("button", name="Connect installed agents", exact=True).click()
    expect(consent).to_have_count(0)
    expect(rows.filter(has=page.get_by_text("Codex", exact=True))).to_contain_text("Configured")
    assert read_receipt(runtime.state_dir, "claude")["grant_id"] == saved_grant
    assert len(runtime.store.rows("SELECT id FROM grants WHERE revoked=0")) == 2
    assert runtime.store.settings()["recording"] is False
    assert not runtime.reviews.preferences()["consented"]

    # Disclosure/focus state survives refresh and a new reported hook event.
    preferences = page.locator('details[data-view-key="capture-preferences"]')
    preferences.locator("summary").focus()
    page.keyboard.press("Enter")
    expect(preferences).to_have_attribute("open", "")
    runtime.store.execute(
        """INSERT INTO hook_events(timestamp,harness,session_id,tool,decision,reason,paths)
           VALUES (?,?,?,?,?,?,?)""",
        (datetime.now(timezone.utc).isoformat(), "claude", "synthetic-setup",
         "Read", "pass", "Synthetic hook report", "[]"),
    )
    expect(claude).to_contain_text("Last hook activity:", timeout=10000)
    expect(preferences).to_have_attribute("open", "")
    expect(preferences.locator("summary")).to_be_focused()
    page.keyboard.press("Enter")
    expect(page.get_by_label("Capture interval", exact=True)).to_be_hidden()

    # Controls and links also keep focus when another status update arrives.
    connect = page.get_by_role("button", name="Update installed agents", exact=True)
    connect.focus()
    runtime.store.execute(
        """INSERT INTO hook_events(timestamp,harness,session_id,tool,decision,reason,paths)
           VALUES (?,?,?,?,?,?,?)""",
        (datetime.now(timezone.utc).isoformat(), "codex", "synthetic-setup",
         "Read", "pass", "Synthetic hook report", "[]"),
    )
    expect(rows.filter(has=page.get_by_text("Codex", exact=True))).to_contain_text(
        "Last hook activity:", timeout=10000,
    )
    expect(connect).to_be_focused()
    feature = page.locator("#capability-protection")
    feature.focus()
    runtime.store.setting("interval_seconds", 900)
    expect(page.get_by_label("Capture interval", exact=True)).to_have_value("900", timeout=10000)
    expect(feature).to_be_focused()


def check_vault_without_capture(page, runtime):
    # Capture is optional: zero-session users still need actionable approvals.
    credential = runtime.broker.create({
        "name": "Synthetic approval", "origin": "https://api.example.com",
        "auth_type": "bearer", "allowed_paths": ["/status"],
    })
    grant = runtime.create_grant("Synthetic approval agent", "/synthetic", [credential["id"]])
    principal = runtime.store.one("SELECT * FROM grants WHERE id=?", (grant["id"],))
    runtime.broker.enqueue(principal, credential["id"], "/status")
    assert runtime.store.rows("SELECT id FROM sessions") == []
    assert runtime.store.settings()["recording"] is False
    page.locator('a[data-route="/"]').click()
    approval = page.get_by_role("link", name="1 credential request needs your approval", exact=True)
    expect(approval).to_be_visible()
    approval.click()
    page.get_by_role("heading", name="Credential vault", exact=True).wait_for()
    expect(page.get_by_role("heading", name="Requests needing your approval", exact=True)).to_be_visible()

    def old_hook(route):
        response = route.fetch()
        data = response.json()
        for hook in data["hooks"]:
            if hook["harness"] == "claude":
                assert hook["vault_connected"]
                hook["needs_update"] = True
        route.fulfill(response=response, json=data)

    page.route("**/api/status", old_hook)
    try:
        page.reload()
        summary = page.get_by_role("region", name="Agent connection status", exact=True)
        expect(summary).to_contain_text("2 agents configured")
        expect(summary).to_contain_text("1 connection needs an update")
        expect(summary).not_to_contain_text("Connect an agent to use this feature")
    finally:
        page.unroute("**/api/status", old_hook)
    page.reload()
    page.get_by_role("heading", name="Credential vault", exact=True).wait_for()
    open_setup(page)


def check_layout(page, shots):
    expect(page.locator("#notifications .toast")).to_have_count(0, timeout=10000)
    for width, scheme in ((1440, "light"), (390, "light"), (390, "dark")):
        page.set_viewport_size({"width": width, "height": 900})
        page.emulate_media(color_scheme=scheme, reduced_motion="reduce")
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
        page.screenshot(path=str(shots / f"setup-{width}-{scheme}.png"), full_page=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    shots = args.output or Path(tempfile.mkdtemp(prefix="adr-setup-shots-"))
    shots.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="adr-setup-qa-") as temporary:
        base = Path(temporary)
        home = base / "home"
        home.mkdir()
        with isolated_agent_profile(home):
            runtime = Runtime(prepare_state_dir(base / "state"), SetupNative(), start_collectors=False)
            runtime.integration_driver = SetupPlugins()
            runtime.reviews.driver = NoModel()
            listener = socket.socket()
            server, thread = None, None
            try:
                listener.bind(("127.0.0.1", 0))
                listener.listen(64)
                runtime.port = listener.getsockname()[1]
                server = uvicorn.Server(uvicorn.Config(
                    create_app(runtime), log_level="error", access_log=False, proxy_headers=False,
                ))
                thread = threading.Thread(target=lambda: server.run(sockets=[listener]), daemon=True)
                thread.start()
                for _ in range(100):
                    if server.started:
                        break
                    time.sleep(0.02)
                with sync_playwright() as playwright, ExitStack() as evidence:
                    browser = playwright.chromium.launch()
                    context = browser.new_context(viewport={"width": 1440, "height": 1040})
                    evidence.enter_context(browser_evidence(context, shots))
                    page = context.new_page()
                    errors, writes, outside = [], [], []
                    page.on("pageerror", lambda error: errors.append(str(error)))

                    def request_seen(request):
                        path = urlsplit(request.url).path
                        if not request.url.startswith(f"http://127.0.0.1:{runtime.port}/"):
                            outside.append(request.url)
                        if request.method not in ("GET", "HEAD") and path != "/api/auth/bootstrap":
                            writes.append((request.method, path, request.post_data_json))

                    page.on("request", request_seen)
                    page.goto(f"http://127.0.0.1:{runtime.port}/#ticket={runtime.new_ticket()}")
                    page.get_by_role("heading", name="Your agents, at a glance", exact=True).wait_for()
                    check_passive_setup(page, runtime, writes, shots)
                    check_capture(page, runtime)
                    check_connections(page, runtime, writes, shots)
                    check_vault_without_capture(page, runtime)
                    check_layout(page, shots)
                    assert errors == [], errors
                    assert outside == [], outside
                print(json.dumps({"setup_ui_qa": "passed", "data": "empty synthetic profile only"}))
            finally:
                if server:
                    server.should_exit = True
                if thread:
                    thread.join(timeout=5)
                runtime.close()
                listener.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
