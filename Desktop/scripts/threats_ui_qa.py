"""Malicious artifact protection browser checks using disposable synthetic data.

The main workflow exercises real owner APIs. Explicit response fixtures cover
rare display states; they are UI contract tests, not backend enforcement proof.
No external reference is opened and no real agent configuration is inspected.
"""

import argparse
import copy
import hashlib
import json
import socket
import tempfile
import threading
import time
from contextlib import ExitStack
from pathlib import Path

import uvicorn
from playwright.sync_api import expect, sync_playwright
from qa_support import browser_evidence, isolated_agent_profile

from adr_desktop.api import create_app
from adr_desktop.config import prepare_state_dir, utcnow
from adr_desktop.protection import evaluate_operation
from adr_desktop.runtime import Runtime

SKILL_BODY = "---\nname: Synthetic threat QA skill\n---\nHarmless browser-test fixture.\n"
SKILL_HASH = hashlib.sha256(SKILL_BODY.encode()).hexdigest()
ENDPOINT = "https://synthetic-threat.invalid/mcp"
FEED_ID = "synthetic-browser-threats"


def synthetic_feed(revision=1):
    return {
        "schema_version": 1,
        "feed_id": FEED_ID,
        "revision": revision,
        "published_at": "2026-10-05T00:00:00Z",
        "indicators": [
            {
                "id": "synthetic-skill",
                "status": "active",
                "kind": "skill_sha256",
                "summary": "Harmless synthetic skill identity used only for browser QA.",
                "references": ["https://example.invalid/synthetic-skill"],
                "target": {"sha256": SKILL_HASH},
            },
            {
                "id": "synthetic-endpoint",
                "status": "active",
                "kind": "mcp_endpoint",
                "summary": "Synthetic endpoint; this address is never contacted.",
                "references": ["https://example.invalid/synthetic-endpoint"],
                "target": {"url": ENDPOINT},
            },
            {
                "id": "synthetic-all-versions",
                "status": "active",
                "kind": "package",
                "summary": "Synthetic package name used only to test the all-version warning.",
                "references": ["https://example.invalid/synthetic-package"],
                "target": {
                    "ecosystem": "npm",
                    "registry": "https://registry.npmjs.org",
                    "name": "adr-synthetic-browser-qa-never-install",
                    "all_versions": True,
                },
            },
        ],
    }


def seed_threats(runtime):
    """Create harmless local identities, then use the actual matcher/service."""
    home = Path.home()
    if not home.is_relative_to(runtime.state_dir.parent):
        raise ValueError("Threat QA requires a disposable home beside the disposable state directory")
    skill = home / ".claude/skills/synthetic-threat-qa/SKILL.md"
    skill.parent.mkdir(parents=True, exist_ok=True)
    skill.write_text(SKILL_BODY)
    project = home / "synthetic-threat-project"
    project.mkdir(exist_ok=True)
    config = project / ".mcp.json"
    config.write_text(json.dumps({"mcpServers": {
        "synthetic-browser": {"type": "http", "url": ENDPOINT},
    }}))
    runtime.store.setting("inventory_snapshot", {
        "assets": [
            {
                "asset_id": "synthetic-skill-asset", "kind": "skill", "name": "Synthetic threat QA skill",
                "install_path": str(skill.parent), "liveness": "declared_only",
            },
            {
                "asset_id": "synthetic-mcp-asset", "kind": "mcp_server", "name": "synthetic-browser",
                "install_path": str(config), "liveness": "declared_only",
            },
        ],
        "coverage": {}, "review_queue": [], "findings": [],
    })
    runtime.store.setting("inventory_updated_at", utcnow())
    runtime.store.ingest({
        "source": "claude", "session_id": "synthetic-threat-project", "username": "synthetic",
        "timestamp": utcnow(), "project_path": str(project), "model": "synthetic",
        "chat_history": [{"role": "user", "content": "Synthetic threat UI fixture.", "tools": []}],
    })
    document = json.dumps(synthetic_feed())
    runtime.threats.import_feed(
        document, expected_revision=runtime.threats.status()["revision"], confirm=True,
    )
    runtime.threats.check_installed()
    event = {
        "tool_name": "Read", "tool_input": {"file_path": str(skill)},
        "cwd": str(project), "session_id": "synthetic-threat-session",
    }
    decision = evaluate_operation(event, "claude", runtime.policy, state_dir=runtime.state_dir)
    assert decision.decision == "deny" and decision.reason_code == "known_malicious_artifact"
    runtime.threats.record_block(decision, harness="claude", source="hook")
    return {"skill": str(skill), "project": str(project), "document": document}


def _open(page):
    page.locator('a[data-route="/threats"]').click()
    page.get_by_role("heading", name="Malicious artifacts", exact=True).wait_for()
    expect(page.locator("#page")).to_have_attribute("aria-busy", "false")


def _upload(page, document):
    page.locator('a[data-route="/settings"]').click()
    page.get_by_role("heading", name="Setup & settings", exact=True).wait_for()
    expect(page.locator("#page")).to_have_attribute("aria-busy", "false")
    lists = page.locator('details[data-view-key="artifact-lists"]')
    if lists.get_attribute("open") is None:
        lists.locator("summary").click()
    with page.expect_file_chooser() as chosen:
        page.get_by_role("button", name="Import local list", exact=True).click()
    chosen.value.set_files({
        "name": "synthetic-threat-list.json", "mimeType": "application/json",
        "buffer": document.encode() if isinstance(document, str) else document,
    })


def _refresh(page):
    _open(page)


def _fits(page):
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    assert page.locator(".threat-location, .threat-facts dd").evaluate_all(
        "nodes => nodes.every(node => node.scrollWidth <= node.clientWidth)"
    )


def check_threats(page, runtime, screenshots):
    """Exercise the real UI and owner endpoints against seed_threats fixtures."""
    original_file_policy = {
        key: copy.deepcopy(runtime.policy[key])
        for key in ("enabled", "rules", "opaque_tools", "strict_execution")
    }
    _open(page)
    page.reload()
    page.get_by_role("heading", name="Malicious artifacts", exact=True).wait_for()
    artifact_nav = page.get_by_role("link", name="Malicious artifacts", exact=True)
    expect(artifact_nav).to_have_attribute("href", "/threats")
    expect(artifact_nav).to_have_attribute("title", "Malicious artifacts")
    assert artifact_nav.locator("svg path").get_attribute("d") != page.get_by_role(
        "link", name="File protection", exact=True,
    ).locator("svg path").get_attribute("d"), "Artifact and file protection need distinct icons"
    switch = page.get_by_role("switch", name="Block known-malicious artifacts", exact=True)
    expect(switch).to_have_attribute("aria-checked", "true")
    expect(page.locator(".threat-finding")).not_to_have_count(0)
    expect(page.locator(".threat-block")).to_have_count(1)
    expect(page.locator(".threat-finding").get_by_text("Blocked", exact=True)).to_have_count(0)
    expect(page.locator(".threat-block a")).to_have_count(0)
    expect(page.get_by_role("button", name="Import local list", exact=True)).to_have_count(0)
    expect(page.locator(".threat-connection-note")).to_have_count(0)
    expect(page.locator(".topbar button")).to_have_count(0)
    expect(page.get_by_text("A zero count means", exact=False)).to_be_hidden()
    page.locator(".threat-feed-card > summary").click()
    expect(page.get_by_text("A zero count means", exact=False)).to_be_visible()
    switch.focus()
    switch.press("Space")
    expect(switch).to_have_attribute("aria-checked", "false")
    assert not runtime.threats.status()["enabled"]
    assert original_file_policy == {
        key: runtime.policy[key] for key in original_file_policy
    }
    switch.press("Space")
    expect(switch).to_have_attribute("aria-checked", "true")

    links = page.get_by_role("link", name="View item in AI inventory", exact=True)
    expect(links).to_have_count(1)
    links.first.click()
    page.get_by_role("heading", name="AI inventory", exact=True).wait_for()
    expect(page.locator(".inventory-table tbody tr")).to_have_count(1)
    expect(page.get_by_role("button", name="Show all items", exact=True)).to_be_visible()
    page.go_back()
    page.get_by_role("heading", name="Malicious artifacts", exact=True).wait_for()

    generation = runtime.threats.status()["feed"]["generation"]
    _upload(page, "{not valid JSON}")
    expect(page.locator(".threat-action-error")).to_be_visible()
    expect(page.locator("dialog[open]")).to_have_count(0)
    assert runtime.threats.status()["feed"]["generation"] == generation

    _upload(page, b"x" * (512 * 1024 + 1))
    expect(page.locator(".threat-action-error")).to_have_text(
        "Choose a JSON threat list no larger than 512 KiB."
    )
    assert runtime.threats.status()["feed"]["generation"] == generation

    imported = json.dumps(synthetic_feed(revision=2))
    _upload(page, imported)
    modal = page.get_by_role("dialog", name="Import this threat list?", exact=True)
    expect(modal).to_be_visible()
    expect(modal).to_contain_text("This replaces your previous custom list. The bundled feed is kept.")
    expect(modal).to_contain_text("1 package indicator matches all versions")
    assert runtime.threats.status()["feed"]["generation"] == generation
    modal.get_by_role("button", name="Cancel", exact=True).click()
    assert runtime.threats.status()["feed"]["generation"] == generation
    _upload(page, imported)
    modal.get_by_role("button", name="Import list", exact=True).click()
    expect(modal).to_have_count(0)
    _open(page)
    expect(page.get_by_text("These results need a new check", exact=True)).to_be_visible()
    assert runtime.threats.status()["feed"]["generation"] != generation
    pending_checks = []

    def hold_check(route):
        pending_checks.append(route)

    page.route("**/api/threats/check", hold_check)
    check_button = page.get_by_role("button", name="Check installed items", exact=True)
    try:
        check_button.click()
        expect(check_button).to_be_disabled()
        expect(switch).to_be_disabled()
        expect(page.get_by_role("button", name="Import local list", exact=True)).to_have_count(0)
        assert len(pending_checks) == 1
        pending_checks.pop().continue_()
        expect(check_button).to_be_enabled()
    finally:
        for request in pending_checks:
            request.abort()
        page.unroute("**/api/threats/check", hold_check)
    expect(page.get_by_text("These results need a new check", exact=True)).to_have_count(0)
    expect(page.locator(".threat-finding")).not_to_have_count(0)

    _upload(page, json.dumps(synthetic_feed(revision=3)))
    expect(modal).to_be_visible()
    current = runtime.threats.status()
    runtime.threats.change_settings(enabled=False, expected_revision=current["revision"])
    active_generation = runtime.threats.status()["feed"]["generation"]
    modal.get_by_role("button", name="Import list", exact=True).click()
    expect(modal.locator(".dialog-error")).to_be_visible()
    assert runtime.threats.status()["feed"]["generation"] == active_generation
    modal.get_by_role("button", name="Cancel", exact=True).click()
    runtime.threats.change_settings(
        enabled=True, expected_revision=runtime.threats.status()["revision"],
    )
    _refresh(page)

    page.locator(".threat-finding").first.locator("summary").click()
    expect(page.locator(".threat-finding .threat-reference").first).to_have_attribute(
        "rel", "noopener noreferrer",
    )
    expect(page.locator(".toast")).to_have_count(0, timeout=10000)
    switch.focus()
    page.evaluate("window.scrollTo({top: 0, behavior: 'instant'})")
    page.screenshot(path=str(screenshots / "synthetic-threats-real-api.png"), full_page=True)
    for width, scheme in ((390, "light"), (390, "dark"), (640, "dark")):
        page.set_viewport_size({"width": width, "height": 1000})
        page.emulate_media(color_scheme=scheme)
        page.evaluate("window.scrollTo({top: 0, behavior: 'instant'})")
        _fits(page)
        expect(switch).to_be_visible()
        page.screenshot(path=str(screenshots / f"synthetic-threats-{width}-{scheme}.png"), full_page=True)
    page.set_viewport_size({"width": 1440, "height": 1040})
    page.emulate_media(color_scheme="light")
    check_threat_display_states(page, runtime, screenshots)


def check_threat_display_states(page, runtime, screenshots):
    """Response fixtures intentionally test rendering, not backend behavior."""
    status = copy.deepcopy(runtime.threats.status())
    fixture = copy.deepcopy(status)
    requested = []

    def respond(route):
        requested.append(route.request.method)
        assert route.request.method == "GET", "Display-state fixtures must not simulate mutation success"
        route.fulfill(json=fixture)

    page.route("**/api/threats", respond)
    try:
        fixture["scan"] = {
            "state": "not_run", "checked_at": None, "generation": None, "stale": False,
            "checked_items": 0, "skipped_items": 0, "findings": [], "issues": [],
        }
        fixture["blocks"] = []
        _refresh(page)
        expect(page.locator(".threat-empty")).to_contain_text("Run a check")
        expect(page.get_by_text("No artifact blocks recorded.", exact=False)).to_be_visible()
        for scan_state in ("complete", "partial"):
            fixture["scan"].update(
                state=scan_state, checked_at=utcnow(), checked_items=3,
                skipped_items=2 if scan_state == "partial" else 0,
                issues=[{"reason": "unreadable_file", "count": 2}] if scan_state == "partial" else [],
            )
            _refresh(page)
            expect(page.locator(".threat-empty")).to_have_text(
                "No matches in the items checked against this feed."
            )
        expect(page.get_by_text("Only part of the inventory", exact=False)).to_be_visible()
        page.get_by_text("Skipped items and check limits", exact=True).click()
        expect(page.get_by_text("unreadable file: 2", exact=True)).to_be_visible()
        fixture["scan"]["state"] = "error"
        _refresh(page)
        expect(page.get_by_text("The installed-item check did not finish.", exact=False)).to_be_visible()
        expect(page.locator(".threat-empty")).to_have_text("There is no completed result for this check.")

        fixture["feed"].update(state="empty", counts={key: 0 for key in status["feed"]["counts"]})
        _refresh(page)
        expect(page.locator(".banner").get_by_text("No active indicators", exact=True)).to_be_visible()
        page.locator(".threat-feed-card > summary").click()
        expect(page.locator(".threat-counts dd")).to_have_text(["0"] * 5)
        fixture["feed"].update(state="degraded", error="Synthetic local feed could not be read.")
        _refresh(page)
        expect(page.locator(".banner").get_by_text("Feed needs attention", exact=True)).to_be_visible()
        expect(page.get_by_text("Synthetic local feed could not be read.", exact=True)).to_be_visible()

        fixture = copy.deepcopy(status)
        finding = copy.deepcopy(fixture["scan"]["findings"][0])
        finding.update(
            label='<img src=x onerror="window.__threat_xss=true">',
            location="/workspace/synthetic/" + "long-path-segment" * 20 + "/SKILL.md",
            target_display="a" * 64, inventory_asset_id=None,
            references=["javascript:window.__threat_xss=true", "https://example.invalid/source"],
        )
        fixture["scan"].update(
            stale=True, state="partial", skipped_items=1,
            findings=[{**finding, "id": f"synthetic-{index}"} for index in range(23)],
        )
        _refresh(page)
        expect(page.locator(".threat-finding")).to_have_count(20)
        expect(page.locator(".threat-finding img")).to_have_count(0)
        page.locator(".threat-finding").first.locator("summary").click()
        expect(page.locator(".threat-finding").first.locator("a")).to_have_count(1)
        assert not page.evaluate("Boolean(window.__threat_xss)")
        page.get_by_role("button", name="Next matches", exact=True).click()
        expect(page.locator(".threat-finding")).to_have_count(3)
        page.set_viewport_size({"width": 390, "height": 1000})
        page.locator(".threat-finding").first.locator("summary").click()
        _fits(page)
        page.evaluate("window.scrollTo({top: 0, behavior: 'instant'})")
        page.screenshot(path=str(screenshots / "synthetic-threats-contract-long-values.png"), full_page=True)
        assert requested and set(requested) == {"GET"}
    finally:
        page.unroute("**/api/threats", respond)
        page.set_viewport_size({"width": 1440, "height": 1040})
        page.emulate_media(color_scheme="light")
        _refresh(page)


def main():
    from ui_qa import SyntheticNative, SyntheticPluginDriver, seed

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", "--screenshots", dest="screenshots", type=Path)
    args = parser.parse_args()
    screenshots = args.screenshots or Path(tempfile.mkdtemp(prefix="adr-threat-ui-shots-"))
    screenshots.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="adr-threat-ui-") as folder:
        directory = Path(folder)
        home = directory / "home"
        home.mkdir()

        with isolated_agent_profile(home):
            runtime = Runtime(
                prepare_state_dir(directory / "state"), SyntheticNative(), start_collectors=False,
            )
            runtime.integration_driver = SyntheticPluginDriver()
            listener = socket.socket()
            server = None
            worker = None
            try:
                seed(runtime)
                seed_threats(runtime)
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
                external = []
                with sync_playwright() as playwright, ExitStack() as evidence:
                    browser = playwright.chromium.launch()
                    context = browser.new_context(viewport={"width": 1440, "height": 1040})
                    evidence.enter_context(browser_evidence(context, screenshots))
                    page = context.new_page()
                    page.on("pageerror", lambda error: errors.append(str(error)))
                    page.on("request", lambda request: external.append(request.url)
                            if not request.url.startswith(f"http://127.0.0.1:{runtime.port}/") else None)
                    page.goto(f"http://127.0.0.1:{runtime.port}/#ticket={runtime.new_ticket()}")
                    page.get_by_role("heading", name="Your agents, at a glance").wait_for()
                    check_threats(page, runtime, screenshots)
                    assert not external, "The threat workflow must not request external resources"
                    assert not errors, "\n".join(errors)
                print(json.dumps({
                    "threat_ui_qa": "passed", "screenshots": str(screenshots),
                    "data": "synthetic only", "coverage": "real owner API + explicit display fixtures",
                }))
            finally:
                if server:
                    server.should_exit = True
                if worker:
                    worker.join(timeout=5)
                runtime.close()
                listener.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
