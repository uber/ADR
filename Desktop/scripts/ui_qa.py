"""Exercise the real local API/UI in a disposable, synthetic browser profile."""

import argparse
import copy
import json
import socket
import tempfile
import threading
import time
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from pathlib import Path

import uvicorn
from environment_ui_qa import check_environment_vault
from inventory_ui_qa import check_inventory
from playwright.sync_api import expect, sync_playwright
from qa_support import browser_evidence, isolated_agent_profile

from adr_desktop.api import create_app
from adr_desktop.config import prepare_state_dir, token
from adr_desktop.runtime import Runtime

ROOT = Path(__file__).resolve().parents[1]


class SyntheticNative:
    connected = True

    def __init__(self):
        self.environment_entries = {}
        self.local_ids = set()
        self.storage_errors = {}

    def call(self, operation, arguments=None, timeout=30):
        if operation == "environment_prompt_store":
            self.environment_entries[arguments["id"]] = dict(arguments)
            self.local_ids.add(arguments["id"])
            return {"stored": True}
        if operation == "vault_storage_status":
            return {"backend": "local_encrypted", "entries": [
                {"id": identifier, "storage": "local_encrypted",
                 "state": "available" if identifier in self.local_ids else "missing",
                 "kind": "environment" if identifier in self.environment_entries else "service",
                 **({"state": "unavailable", "reason_code": self.storage_errors[identifier]}
                    if identifier in self.storage_errors else {})}
                for identifier in arguments["ids"]
            ]}
        if operation == "vault_migrate_legacy":
            self.local_ids.update(arguments["ids"])
            return {"backend": "local_encrypted", "keychain_originals_retained": True, "results": [
                {"id": identifier, "status": "migrated"} for identifier in arguments["ids"]
            ]}
        if operation == "vault_check_text":
            matches = [
                identifier for identifier in arguments["environment_ids"]
                if "synthetic-browser-password-123" in arguments["text"]
            ]
            return {"checked": True, "matched": bool(matches), "aliases": [
                self.environment_entries[identifier]["env_name"] for identifier in matches
            ]}
        if operation == "environment_execute":
            return {"exit_code": 0, "stdout": "synthetic command completed", "stderr": ""}
        if operation == "vault_perform":
            return {"status": 200, "body": {"login": "synthetic-user"}, "content_type": "application/json"}
        if operation == "choose_path":
            return {"path": "/workspace/synthetic/private", "kind": "directory"}
        if operation in ("login_status", "set_login"):
            return {"available": True, "enabled": False, "requires_approval": False}
        if operation == "vault_prompt_store":
            self.local_ids.add(arguments["id"])
            return {"stored": True}
        if operation == "vault_delete":
            self.local_ids.discard(arguments["id"])
            return {"removed": True}
        if operation == "file_access_identity":
            return {"app_name": "ADR", "bundle_path": "/Applications/ADR.app",
                    "full_disk_access": "not_determined"}
        if operation == "open_access_settings":
            return {"request_accepted": True, "grants_access": False, "full_disk_access": "not_determined"}
        raise RuntimeError("Unsupported synthetic native operation")


class SyntheticPluginDriver:
    def __init__(self, *, first_install_delay=0):
        self.first_install_delay = first_install_delay

    def executable(self, harness):
        return f"/synthetic/{harness}"

    def install(self, *_args, **_kwargs):
        delay, self.first_install_delay = self.first_install_delay, 0
        if delay:
            time.sleep(delay)

    def remove(self, *_args, **_kwargs):
        return None


def seed(runtime):
    runtime.store.setting("onboarding_complete", True)
    projects = ["/workspace/synthetic/atlas", "/workspace/synthetic/site"]
    samples = [
        ("claude", "Tighten input validation in the API", "example-reasoning-model"),
        ("codex", "Trace the settings persistence bug", "example-coding-model"),
        ("cursor", "Simplify the onboarding flow", "example-coding-model"),
        ("copilot", "Add regression tests for file imports", "example-coding-model"),
        ("claude", "Review error handling before release", "example-reasoning-model"),
        ("gemini", "Document the local development setup", "example-coding-model"),
    ]
    for index in range(18):
        source, title, model = samples[index % len(samples)]
        runtime.store.ingest(
            {
                "source": source,
                "session_id": f"synthetic-{index}",
                "username": "synthetic",
                "timestamp": (datetime.now(timezone.utc) - timedelta(hours=index * 9)).isoformat(),
                "project_path": projects[index % 2],
                "model": model,
                "token_usage": {"input_tokens": 1700 + index * 100, "output_tokens": 700 + index * 50},
                "chat_history": [
                    {"role": "user", "content": title, "tools": []},
                    {
                        "role": "assistant",
                        "content": "I checked the implementation and found the edge case.\n"
                        '<img src=x onerror="window.__adr_xss=true">',
                        "tools": [
                            {
                                "tool_name": "Read",
                                "arguments": {"file_path": "src/settings.py"},
                                "result": "Synthetic result: configuration loaded successfully.",
                                "status": "success",
                            }
                        ],
                    },
                    {
                        "role": "assistant",
                        "content": "[Assistant decided to use a tool]",
                        "tools": [
                            {
                                "tool_name": "Grep",
                                "arguments": {"pattern": "oauth_refresh"},
                                "result": "Synthetic keyword: sharedcontextneedle",
                            }
                        ],
                    },
                ],
            }
        )
    runtime.change_policy(
        add={
            "path": "/workspace/synthetic/private",
            "kind": "directory",
            "action": "block",
            "label": "Private documents",
        }
    )
    runtime.change_policy(
        add={
            "path": "/workspace/synthetic/atlas/.env",
            "kind": "file",
            "action": "ask",
            "label": "Environment file",
        }
    )
    credential = runtime.broker.create(
        {
            "name": "GitHub · synthetic test",
            "origin": "https://api.github.com",
            "auth_type": "bearer",
            "allowed_paths": ["/user", "/repos"],
        }
    )
    grant = runtime.create_grant("Synthetic coding agent", projects[0], [credential["id"]])
    principal = runtime.store.one("SELECT * FROM grants WHERE id=?", (grant["id"],))
    runtime.broker.enqueue(principal, credential["id"], "/user")
    runtime.store.setting(
        "inventory_snapshot",
        {
            "assets": [
                {
                    "name": "Claude Code",
                    "kind": "cli_agent",
                    "liveness": "installed",
                    "version": "synthetic",
                    "path": "/workspace/synthetic/bin/claude",
                },
                {
                    "name": "Project notes",
                    "kind": "skill",
                    "liveness": "declared_only",
                    "version": None,
                    "path": "/workspace/synthetic/atlas/.claude/skills/project-notes",
                },
                {
                    "name": "ADR",
                    "kind": "mcp_server",
                    "liveness": "declared_only",
                    "version": "0.1.0",
                    "path": "/workspace/synthetic/adr",
                },
            ],
            "findings": [],
            "coverage": {"denied": [], "boundaries_hit": []},
        },
    )
    runtime.store.setting("inventory_updated_at", datetime.now(timezone.utc).isoformat())


def check_capture_controls(page, context, runtime):
    """Exercise two tabs sharing a browser, without starting real collectors."""
    pauses = []
    refreshes = []

    def response_seen(response):
        if response.url.endswith("/api/collector/pause"):
            pauses.append(response.status)
        if response.url.endswith("/api/auth/session"):
            refreshes.append(response.status)

    page.on("response", response_seen)
    page.get_by_role("button", name="Start capture", exact=True).click()
    page.get_by_role("button", name="Pause capture", exact=True).wait_for()
    other = context.new_page()
    try:
        other.goto(f"http://127.0.0.1:{runtime.port}/#ticket={runtime.new_ticket()}")
        other.get_by_role("heading", name="Your agents, at a glance").wait_for()
        page.get_by_role("button", name="Pause capture", exact=True).click()
        page.get_by_role("button", name="Start capture", exact=True).wait_for()
        assert pauses == [200], "Opening another tab must not invalidate the first"
        assert refreshes == []
        assert runtime.store.settings()["recording"] is False
    finally:
        other.close()

    page.get_by_role("button", name="Start capture", exact=True).click()
    page.get_by_role("button", name="Pause capture", exact=True).wait_for()
    # Simulate a concurrent session change in this synthetic server, not in the
    # user's browser. The old tab should recover once without repeating a write.
    with runtime.auth_lock:
        runtime.sessions = {key: (token(), expiry) for key, (_, expiry) in runtime.sessions.items()}
    before = len(runtime.store.rows("SELECT id FROM audit WHERE kind='collection_changed'"))
    pauses.clear()
    page.get_by_role("button", name="Pause capture", exact=True).click()
    page.get_by_role("button", name="Start capture", exact=True).wait_for()
    assert pauses == [403, 200]
    assert refreshes == [200]
    assert runtime.store.settings()["recording"] is False
    assert len(runtime.store.rows("SELECT id FROM audit WHERE kind='collection_changed'")) == before + 1
    assert page.get_by_role("alert").count() == 0
    page.remove_listener("response", response_seen)


def check_csrf_retry_boundaries(page):
    """Only an explicit, pre-execution CSRF rejection permits one retry."""
    page.locator('a[data-route="/settings"]').click()
    page.get_by_role("heading", name="Setup & settings", exact=True).wait_for()
    page.locator('details[data-view-key="capture-preferences"] > summary').click()
    interval = page.get_by_label("Capture interval", exact=True)
    stale = {"code": "csrf_mismatch", "message": "Synthetic stale token"}
    for status, detail, expected_attempts, expired in [
        (403, "Cross-origin requests are not allowed", 1, False),
        (401, "Open ADR from the menu-bar app", 1, False),
        (500, "Synthetic server failure", 1, False),
        (None, None, 1, False),
        (403, stale, 2, False),
        (403, stale, 1, True),
    ]:
        attempts = []
        refreshes = []

        def request_seen(request):
            if request.url.endswith("/api/auth/session"):
                refreshes.append(request.method)

        def reject(route):
            attempts.append(route.request.method)
            if status is None:
                route.abort("failed")
            else:
                route.fulfill(
                    status=status,
                    content_type="application/json",
                    body=json.dumps({"detail": detail}),
                )

        def expire_session(route):
            route.fulfill(
                status=401,
                content_type="application/json",
                body=json.dumps({"detail": "Open ADR from the menu-bar app"}),
            )

        page.on("request", request_seen)
        page.route("**/api/settings", reject)
        if expired:
            page.route("**/api/auth/session", expire_session)
        try:
            interval.select_option("900")
            expect(interval).to_have_value("300")
            expect(interval).to_be_enabled()
            expect(page.get_by_role("alert").last).to_be_visible()
            assert attempts == ["PATCH"] * expected_attempts, (
                f"Unexpected application retries for status={status}: {attempts}"
            )
            assert refreshes == (["GET"] if expected_attempts == 2 or expired else []), (
                f"Unexpected session refresh for status={status}: {refreshes}"
            )
        finally:
            page.unroute("**/api/settings", reject)
            if expired:
                page.unroute("**/api/auth/session", expire_session)
            page.remove_listener("request", request_seen)
    page.locator('a[data-route="/"]').click()
    page.get_by_role("heading", name="Your agents, at a glance").wait_for()
    # Expected errors are transient notifications, not persistent page state.
    expect(page.get_by_role("alert")).to_have_count(0, timeout=10000)


def check_capture_intervals(page, runtime):
    page.locator('a[data-route="/settings"]').click()
    page.get_by_role("heading", name="Setup & settings", exact=True).wait_for()
    page.locator('details[data-view-key="capture-preferences"] > summary').click()
    interval = page.get_by_label("Capture interval", exact=True)
    assert interval.locator("option").all_text_contents() == [
        "Every 5 minutes",
        "Every 15 minutes",
        "Every 30 minutes",
        "Every 60 minutes",
    ]
    assert interval.input_value() == "300"
    for seconds in (900, 1800, 3600, 300):
        with page.expect_response(
            lambda response: response.url.endswith("/api/settings") and response.request.method == "PATCH"
        ) as saved:
            interval.select_option(str(seconds))
        assert saved.value.status == 200
        assert runtime.store.settings()["interval_seconds"] == seconds
        assert runtime.store.settings()["recording"] is False
        page.reload()
        page.get_by_role("heading", name="Setup & settings", exact=True).wait_for()
        page.locator('details[data-view-key="capture-preferences"] > summary').click()
        assert interval.input_value() == str(seconds)
    assert page.get_by_role("alert").count() == 0


def check_starter_protection(page, runtime, screenshots):
    starter_rules = page.locator(".starter-rules > summary").filter(has_text="Starter rules (")
    runtime.change_policy(
        add={
            "path": str(Path.home() / ".ssh"),
            "kind": "directory",
            "action": "ask",
            "label": "My SSH choice",
        }
    )
    original_rules = list(runtime.policy["rules"])
    expected = runtime.starter_protection()["available"]
    page.locator('a[data-route="/protection"]').click()
    page.get_by_role("heading", name="File protection", exact=True).wait_for()
    expect(page.get_by_role("button", name="Add starter protections", exact=True)).to_be_disabled()
    assert not any(item["installed"] for item in runtime.status()["hooks"])
    protection_tab = page.context.new_page()
    try:
        protection_tab.goto(f"http://127.0.0.1:{runtime.port}/protection")
        protection_tab.get_by_role("heading", name="File protection", exact=True).wait_for()
        page.get_by_role("link", name="Manage agent connections", exact=True).click()
        page.get_by_role("heading", name="Setup & settings", exact=True).wait_for()
        page.get_by_role("button", name="Connect installed agents", exact=True).click()
        modal = page.locator("dialog[open]")
        expect(modal.locator('input[name="project"], input[name="credentials"]')).to_have_count(0)
        # Wait for setup itself, not just the click. A separate feature tab
        # must keep its starter action disabled while installation is pending.
        with page.expect_response(
            lambda response: (
                response.url.endswith("/api/integrations/connect-all")
                and response.request.method == "POST"
            ),
            timeout=60000,
        ) as connected:
            modal.get_by_role("button", name="Connect installed agents", exact=True).click()
            expect(modal.get_by_role("button", name="Working…", exact=True)).to_be_disabled()
            expect(protection_tab.get_by_role(
                "button", name="Add starter protections", exact=True
            )).to_be_disabled()
    finally:
        protection_tab.close()
    assert connected.value.status == 200
    assert {item["harness"]: item["status"] for item in connected.value.json()["items"]} == {
        "claude": "configured", "codex": "configured",
        "opencode": "configured", "copilot": "configured",
    }
    expect(modal).to_have_count(0)
    assert runtime.starter_protection()["connected"] is True
    page.locator('a[data-route="/protection"]').click()
    page.get_by_role("heading", name="File protection", exact=True).wait_for()
    expect(page.get_by_role("button", name="Add starter protections", exact=True)).to_be_enabled()
    page.locator(".starter-preview > summary").click()
    page.get_by_text("Ask first kept", exact=True).wait_for()
    page.screenshot(path=str(screenshots / "synthetic-starter-review.png"), full_page=True)
    with page.expect_response(
        lambda response: (
            response.url.endswith("/api/protection/starter") and response.request.method == "POST"
        )
    ) as added:
        page.get_by_role("button", name="Add starter protections", exact=True).click()
    assert added.value.status == 200
    assert added.value.json()["added"] == expected
    expect(page.get_by_role("heading", name="Start with the essentials", exact=True)).to_have_count(0)
    assert runtime.policy["rules"][: len(original_rules)] == original_rules
    assert len(runtime.policy["rules"]) == len(original_rules) + expected
    assert {item["harness"] for item in runtime.status()["hooks"] if item["vault_connected"]} == {
        "claude", "codex", "opencode", "copilot",
    }
    page.reload()
    page.get_by_role("heading", name="File protection", exact=True).wait_for()
    expect(page.get_by_role("heading", name="Start with the essentials", exact=True)).to_have_count(0)
    page.get_by_role("button", name="Pause file rules", exact=True).click()
    page.get_by_role("button", name="Enable file rules", exact=True).wait_for()
    page.get_by_text("Your rules are saved, but file protection is paused.", exact=True).wait_for()
    starter_rules.click()
    page.get_by_role("button", name="Remove Docker credentials", exact=True).click()
    page.locator("dialog[open]").get_by_role("button", name="Remove rule", exact=True).click()
    expect(page.get_by_role("button", name="Restore missing starter rules", exact=True)).to_be_enabled()
    with page.expect_response(
        lambda response: (
            response.url.endswith("/api/protection/starter") and response.request.method == "POST"
        )
    ) as restored:
        page.get_by_role("button", name="Restore missing starter rules", exact=True).click()
    assert restored.value.json()["added"] == 1
    expect(page.get_by_role("button", name="Restore missing starter rules", exact=True)).to_have_count(0)
    assert runtime.policy["enabled"] is False
    page.get_by_role("button", name="Enable file rules", exact=True).click()
    page.get_by_role("button", name="Pause file rules", exact=True).wait_for()
    page.screenshot(path=str(screenshots / "synthetic-starter-added.png"), full_page=True)
    page.set_viewport_size({"width": 640, "height": 1000})
    starter_rules.click()
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    page.screenshot(path=str(screenshots / "synthetic-starter-narrow.png"), full_page=True)
    page.emulate_media(color_scheme="dark")
    page.set_viewport_size({"width": 1440, "height": 1040})
    starter_rules.click()
    page.screenshot(path=str(screenshots / "synthetic-starter-dark.png"), full_page=True)
    page.emulate_media(color_scheme="light")


def check_context_and_vault_access(page, runtime, screenshots):
    expect(page.locator('a[data-route="/history"]')).to_have_count(0)
    expect(page.get_by_role("button", name="Connect history search")).to_have_count(0)
    grant = runtime.store.one("SELECT * FROM grants WHERE kind='agent'")
    assert grant["history_scope"] == "device" and grant["credentials"] == '["*"]'
    page.locator('a[data-route="/sessions"]').click()
    page.get_by_label("Search your captured work", exact=True).fill("sharedcontextneedle")
    page.get_by_role("button", name="Search", exact=True).click()
    page.get_by_role("heading", name="Search results", exact=True).wait_for()
    expect(page.locator(".search-snippet")).to_have_count(18)
    page.get_by_label("Search your captured work", exact=True).fill("")
    page.get_by_role("button", name="Search", exact=True).click()
    page.locator('a[data-route="/credentials"]').click()
    row = page.locator(".credential-row").filter(has_text="Second synthetic credential")
    row.get_by_role("button", name="Allow agent use", exact=True).click()
    modal = page.locator("dialog[open]")
    modal.locator('input[name="name"]').fill("Synthetic automatic vault")
    modal.locator('input[name="confirm_automatic"]').check()
    modal.get_by_role("button", name="Allow selected access", exact=True).click()
    page.get_by_role("heading", name="Connect ADR Vault to your agent", exact=True).wait_for()
    assert "adr_vault" in page.locator(".config-block").inner_text()
    page.locator("dialog[open]").get_by_role("button", name="Done", exact=True).click()
    grant = runtime.store.one("SELECT * FROM grants WHERE name='Synthetic automatic vault'")
    assert grant["history_scope"] == "none" and grant["approval_mode"] == "automatic"
    page.screenshot(path=str(screenshots / "synthetic-vault.png"), full_page=True)


def check_credential_setup(page, runtime, screenshots):
    """Exercise real form behavior, with a synthetic native broker and no secrets."""
    page.locator('a[data-route="/credentials"]').click()
    page.get_by_role("button", name="Add API credential", exact=True).click()
    modal = page.get_by_role("dialog", name="Add an API credential", exact=True)
    assert modal.locator('input[type="password"]').count() == 0
    assert modal.locator('input[name="secret"], textarea[name="secret"]').count() == 0
    auth = modal.get_by_label("Credential type", exact=True)
    header = modal.locator('input[name="header_name"]')
    username = modal.locator('input[name="username"]')
    expect(header).to_be_hidden()
    expect(header).to_be_disabled()
    expect(username).to_be_hidden()
    expect(username).to_be_disabled()

    auth.select_option("basic")
    expect(username).to_be_visible()
    expect(username).to_have_attribute("required", "")
    username.fill("synthetic-api-user")
    expect(header).to_be_hidden()
    auth.select_option("api_key")
    expect(username).to_be_hidden()
    expect(username).to_be_disabled()
    expect(header).to_be_visible()
    expect(header).to_have_value("X-API-Key")
    # A service shortcut only fills non-secret metadata. Switching types must
    # not submit a stale username/header from a previously selected type.
    modal.get_by_role("button", name="Use GitHub settings", exact=True).click()
    expect(auth).to_have_value("bearer")
    expect(modal.locator('input[name="origin"]')).to_have_value("https://api.github.com")
    expect(modal.locator('textarea[name="paths"]')).to_have_value("/user\n/repos")
    modal.get_by_label("Name", exact=True).fill("Second synthetic credential")
    page.screenshot(path=str(screenshots / "synthetic-credential-setup.png"), full_page=True)
    with page.expect_response(
        lambda response: response.url.endswith("/api/credentials") and response.request.method == "POST"
    ) as saved:
        modal.get_by_role("button", name="Continue to secure window", exact=True).click()
    response = saved.value
    assert response.status == 200
    assert response.request.post_data_json == {
        "name": "Second synthetic credential", "origin": "https://api.github.com",
        "auth_type": "bearer", "header_name": "Authorization", "username": "",
        "allowed_paths": ["/user", "/repos"],
    }
    row = page.locator(".credential-row").filter(has_text="Second synthetic credential")
    expect(row).to_contain_text("No agent access yet")
    row.get_by_role("button", name="Use with an agent", exact=True).click()
    help_dialog = page.get_by_role("dialog", name="Second synthetic credential", exact=True)
    expect(help_dialog).to_contain_text("adr_list_credentials")
    expect(help_dialog).to_contain_text("adr_request_service")
    expect(help_dialog).to_contain_text("adr_service_result")
    credential = runtime.store.one("SELECT * FROM credentials WHERE name='Second synthetic credential'")
    expect(help_dialog).to_contain_text(credential["id"])
    help_dialog.get_by_role("button", name="Done", exact=True).click()
    support = page.locator(".vault-support")
    support.locator("summary").click()
    expect(support).to_contain_text("Multiline values work as environment text")
    expect(support).to_contain_text("ADR does not automatically import it")
    expect(support).to_contain_text("Unlabeled, unfamiliar passwords cannot always be recognized")
    page.screenshot(path=str(screenshots / "synthetic-vault-support.png"), full_page=True)

    row.get_by_role("button", name="Allow agent use", exact=True).click()
    grant_dialog = page.get_by_role("dialog", name="Allow an agent to use the vault", exact=True)
    consent = grant_dialog.locator('input[name="confirm_automatic"]')
    grant_dialog.get_by_label("Credential permission").select_option("ask")
    expect(consent).to_be_hidden()
    expect(consent).to_be_disabled()
    grant_dialog.get_by_label("Credential permission").select_option("automatic")
    expect(consent).to_be_visible()
    expect(consent).not_to_be_checked()
    grant_dialog.get_by_role("button", name="Close dialog", exact=True).click()


def check_conversation_families(page, runtime, screenshots):
    """Exercise lineage and setup presentation without discarding original records."""
    repeated = {"role": "developer", "content": "Synthetic recurring setup.", "tools": []}
    request = {"role": "user", "content": "Please check the grouping again", "tools": []}
    parent = {
        "source": "codex", "session_id": "codex_ui-parent", "username": "synthetic",
        "timestamp": datetime.now(timezone.utc).isoformat(), "project_path": "/workspace/synthetic",
        "session_context": {"session_title": "Conversation grouping preview"},
        "chat_history": [
            {"role": "user", "content": "<environment_context>synthetic</environment_context>", "tools": []},
            *[copy.deepcopy(repeated) for _ in range(100)],
            copy.deepcopy(request), copy.deepcopy(request),
        ],
    }
    child = copy.deepcopy(parent)
    child["session_id"] = "codex_ui-child"
    child["session_context"] = {
        "parent_session_id": parent["session_id"], "agent_path": "/root/inspect_session_metadata",
    }
    child["chat_history"].append({"role": "assistant", "content": "groupingchildneedle", "tools": []})
    fork = copy.deepcopy(parent)
    fork["session_id"] = "codex_ui-fork"
    fork["session_context"]["forked_from_session_id"] = parent["session_id"]
    for payload in (parent, child, fork):
        runtime.store.ingest(payload)
    ids = {
        row["source_session_id"]: row["id"] for row in runtime.store.sessions(limit=100)["items"]
    }
    parent_id, child_id, fork_id = (ids[payload["session_id"]] for payload in (parent, child, fork))
    page.locator('a[data-route="/sessions"]').click()
    expect(page.locator(".brand span")).to_have_text("Agent Security and Observability")
    page.get_by_role("heading", name="Recent conversations", exact=True).wait_for()
    expect(page.locator(f'.session-row[href="/sessions/{child_id}"]')).to_have_count(0)
    family = page.locator(".session-family").filter(
        has=page.locator(f'.session-row[href="/sessions/{parent_id}"]')
    ).first
    family.locator(".session-children > summary").click()
    page.locator(f'.session-row[href="/sessions/{child_id}"]').wait_for()
    expect(page.locator(f'.session-row[href="/sessions/{child_id}"]')).to_contain_text(
        "inspect session metadata"
    )
    expect(page.locator(f'.session-row[href="/sessions/{fork_id}"]')).to_contain_text("Fork")
    page.screenshot(path=str(screenshots / "synthetic-session-families.png"), full_page=True)
    page.locator(f'.session-row[href="/sessions/{parent_id}"]').click()
    page.locator(".setup-bundle").wait_for()
    assert page.locator(".setup-bundle").evaluate("node => !node.open")
    expect(page.locator(".setup-bundle > summary")).to_contain_text("101 entries")
    expect(page.locator(".message.user-message").filter(has_text=request["content"])).to_have_count(2)
    page.locator(".setup-bundle > summary").click()
    expect(page.locator(".setup-entry")).to_have_count(2)
    page.get_by_text("100 occurrences", exact=True).wait_for()
    page.screenshot(path=str(screenshots / "synthetic-session-setup.png"), full_page=True)
    assert runtime.store.session(parent_id)["payload"] == parent
    page.locator('a[data-route="/sessions"]').click()
    page.get_by_label("Search your captured work", exact=True).fill("groupingchildneedle")
    page.get_by_role("button", name="Search", exact=True).click()
    page.get_by_role("heading", name="Search results", exact=True).wait_for()
    page.locator(f'.session-row[href^="/sessions/{child_id}"]').click()
    page.get_by_role("link", name="Parent conversation: Conversation grouping preview", exact=True).click()
    page.get_by_role("heading", name="Conversation grouping preview", exact=True).wait_for()
    page.locator('a[data-route="/sessions"]').click()
    page.get_by_label("Search your captured work", exact=True).fill("")
    page.get_by_role("button", name="Search", exact=True).click()
    page.locator(f'.session-row[href="/sessions/{fork_id}"]').click()
    page.get_by_role("link", name="Forked from: Conversation grouping preview", exact=True).wait_for()
    page.set_viewport_size({"width": 640, "height": 1000})
    page.emulate_media(color_scheme="dark")
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    page.screenshot(path=str(screenshots / "synthetic-session-narrow-dark.png"), full_page=True)
    page.set_viewport_size({"width": 1440, "height": 1040})
    page.emulate_media(color_scheme="light")


def check_dropdowns_and_protection_activity(page, runtime, screenshots):
    page.locator('a[data-route="/credentials"]').click()
    page.get_by_role("button", name="Add API credential", exact=True).click()
    modal = page.locator("dialog[open]")
    credential_type = modal.get_by_label("Credential type", exact=True)
    expect(credential_type).to_have_value("bearer")
    credential_type.focus()
    # Native typeahead works without driving an OS-owned popup menu.
    credential_type.press("a")
    expect(credential_type).to_have_value("api_key")
    measurements = credential_type.evaluate("""select => {
      const arrow = select.parentElement.querySelector(".select-chevron");
      return {padding: parseFloat(getComputedStyle(select).paddingRight),
        inset: select.getBoundingClientRect().right - arrow.getBoundingClientRect().right,
        appearance: getComputedStyle(select).appearance,
        arrowReceivesClicks: getComputedStyle(arrow).pointerEvents !== "none"};
    }""")
    assert measurements["padding"] >= 40 and measurements["inset"] >= 12
    assert measurements["appearance"] == "none" and not measurements["arrowReceivesClicks"]
    page.screenshot(path=str(screenshots / "synthetic-credential-dropdown.png"), full_page=True)
    page.set_viewport_size({"width": 390, "height": 900})
    page.emulate_media(color_scheme="dark")
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    assert modal.evaluate("node => node.scrollWidth <= node.clientWidth")
    page.screenshot(path=str(screenshots / "synthetic-credential-dropdown-narrow-dark.png"), full_page=True)
    page.emulate_media(forced_colors="active")
    assert credential_type.evaluate(
        'select => getComputedStyle(select.parentElement.querySelector(".select-chevron")).display'
    ) == "none"
    page.emulate_media(forced_colors="none", color_scheme="light")
    page.set_viewport_size({"width": 1440, "height": 1040})
    modal.get_by_role("button", name="Close dialog", exact=True).click()

    def event(decision, reason, tool, approved=False):
        runtime.store.execute(
            """INSERT INTO hook_events(
               timestamp,harness,session_id,tool,decision,reason,paths,approval_requested)
               VALUES (?,?,?,?,?,?,?,?)""",
            (datetime.now(timezone.utc).isoformat(), "codex", "synthetic", tool, decision,
             reason, json.dumps(["/workspace/synthetic/private.env"]), approved),
        )

    event("deny", "A synthetic protected file was blocked", "Blocked synthetic read")
    event("ask", "A synthetic file needs approval", "Asked synthetic read", True)
    event("pass", "Allowed once in ADR", "Approved synthetic read", True)
    for _ in range(125):
        event("pass", "No protected path matched", "Routine synthetic read")
    page.locator('a[data-route="/protection"]').click()
    activity = page.locator(".card").filter(
        has=page.get_by_role("heading", name="Blocks and approvals", exact=True)
    )
    expect(activity.locator(".protection-event")).to_have_count(3)
    expect(activity.get_by_text("Routine synthetic read", exact=False)).to_have_count(0)
    expect(activity.get_by_text("0", exact=True)).to_have_count(0)
    for label in ("Blocked", "Approval requested", "Allowed after approval"):
        expect(activity.get_by_text(label, exact=True)).to_have_count(1)
    assert page.locator("select").evaluate_all(
        'nodes => nodes.every(node => node.parentElement.classList.contains("select-control"))'
    )
    # Routine successful calls must not keep rebuilding the page and closing
    # the user's controls. A subsequent block must still refresh the activity.
    # Let the normal status poll observe the initial seeded events.
    page.wait_for_timeout(4500)
    advanced = page.locator(".starter-rules > summary").filter(has_text="Advanced: command approvals")
    advanced.click()
    summary_node = advanced.element_handle()
    event("pass", "No protected path matched", "Another routine read")
    page.wait_for_timeout(4500)
    assert summary_node.evaluate("node => node.isConnected && node.parentElement.open")
    event("deny", "A later synthetic block", "Later blocked read")
    event("pass", "No protected path matched", "Routine read after block")
    expect(activity.locator(".protection-event")).to_have_count(4, timeout=6000)
    page.screenshot(path=str(screenshots / "synthetic-protection-interventions.png"), full_page=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    screenshots = args.output or ROOT / "screenshots"
    screenshots.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="adr-ui-qa-") as folder:
        home = Path(folder) / "home"
        home.mkdir()

        with isolated_agent_profile(home):
            runtime = Runtime(
                prepare_state_dir(Path(folder) / "state"), SyntheticNative(), start_collectors=False
            )
            # Exercise setup that outlasts Playwright's default five-second
            # assertion window, without invoking real agents or providers.
            runtime.integration_driver = SyntheticPluginDriver(first_install_delay=6)
            seed(runtime)
            listener = socket.socket()
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
            worker = threading.Thread(target=lambda: server.run(sockets=[listener]), daemon=True)
            worker.start()
            for _ in range(100):
                if server.started:
                    break
                time.sleep(0.02)
            errors = []
            try:
                with sync_playwright() as playwright, ExitStack() as evidence:
                    browser = playwright.chromium.launch()
                    context = browser.new_context(
                        viewport={"width": 1440, "height": 1040}, color_scheme="light"
                    )
                    evidence.enter_context(browser_evidence(context, screenshots))
                    page = context.new_page()
                    page.on("pageerror", lambda error: errors.append(str(error)))
                    page.goto(f"http://127.0.0.1:{runtime.port}/#ticket={runtime.new_ticket()}")
                    page.get_by_role("heading", name="Your agents, at a glance").wait_for()
                    check_capture_controls(page, context, runtime)
                    check_csrf_retry_boundaries(page)
                    assert not page.evaluate("Boolean(window.__adr_xss)")
                    page.screenshot(path=str(screenshots / "synthetic-overview.png"), full_page=True)
                    for route, title in [
                        ("/sessions", "Sessions"),
                        ("/inventory", "AI inventory"),
                        ("/protection", "File protection"),
                        ("/credentials", "Credential vault"),
                        ("/settings", "Setup & settings"),
                    ]:
                        page.locator(f'nav a[href="{route}"], .sidebar-bottom a[href="{route}"]').click()
                        page.get_by_role("heading", name=title, exact=True).wait_for()
                        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
                        page.screenshot(path=str(screenshots / f"synthetic-{route[1:]}.png"), full_page=True)

                    check_capture_intervals(page, runtime)
                    page.locator('a[data-route="/sessions"]').click()
                    page.locator(".session-row").first.click()
                    page.locator(".conversation").wait_for()
                    assert page.get_by_text(
                        '<img src=x onerror="window.__adr_xss=true">', exact=False
                    ).count()
                    assert not page.evaluate("Boolean(window.__adr_xss)")
                    expect(page.get_by_text("[Assistant decided to use a tool]", exact=True)).to_have_count(0)
                    expect(page.locator(".tool-bundle")).to_have_count(1)
                    page.locator(".tool-bundle > summary").first.click()
                    page.locator(".tool-call summary").first.click()
                    page.get_by_text("Synthetic result: configuration loaded successfully.").wait_for()
                    page.screenshot(path=str(screenshots / "synthetic-session-detail.png"), full_page=True)

                    page.locator('a[data-route="/protection"]').click()
                    page.get_by_role("button", name="Protect a path", exact=True).click()
                    modal = page.locator("dialog[open]")
                    modal.locator('input[name="path"]').fill(str(home / "private"))
                    modal.locator('input[name="label"]').fill("QA private folder")
                    modal.get_by_role("button", name="Add protection", exact=True).click()
                    page.get_by_text("QA private folder", exact=True).wait_for()
                    assert any(rule["label"] == "QA private folder" for rule in runtime.policy["rules"])
                    check_starter_protection(page, runtime, screenshots)

                    check_credential_setup(page, runtime, screenshots)

                    page.get_by_role("button", name="Approve once", exact=True).click()
                    expect(page.get_by_role("button", name="Approve once", exact=True)).to_have_count(0)
                    assert runtime.store.one("SELECT state FROM broker_requests")["state"] == "succeeded"
                    check_context_and_vault_access(page, runtime, screenshots)
                    check_conversation_families(page, runtime, screenshots)
                    check_dropdowns_and_protection_activity(page, runtime, screenshots)
                    check_environment_vault(page, runtime, screenshots)
                    check_inventory(page, runtime, screenshots)

                    page.set_viewport_size({"width": 800, "height": 1000})
                    page.locator('a[data-route="/"]').click()
                    page.get_by_role("heading", name="Your agents, at a glance").wait_for()
                    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
                    page.screenshot(path=str(screenshots / "synthetic-overview-narrow.png"), full_page=True)
                    page.emulate_media(color_scheme="dark")
                    page.set_viewport_size({"width": 1440, "height": 1040})
                    page.screenshot(path=str(screenshots / "synthetic-overview-dark.png"), full_page=True)
                if errors:
                    raise AssertionError("\n".join(errors))
                print(
                    json.dumps({"ui_qa": "passed", "screenshots": str(screenshots), "data": "synthetic only"})
                )
            finally:
                server.should_exit = True
                worker.join(timeout=5)
                runtime.close()
                listener.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
