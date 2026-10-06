import json
import subprocess
import sys

import pytest
from conftest import FakePluginDriver, grant_token, sample_session

from adr_desktop import agent_plugins, hooks


@pytest.fixture
def driver(runtime):
    result = FakePluginDriver()
    runtime.integration_driver = result
    return result


@pytest.mark.parametrize("harness", ["claude", "codex", "copilot", "opencode"])
def test_one_bundle_contains_hooks_and_read_only_context(runtime, driver, harness):
    result = agent_plugins.connect(runtime, harness, allow_context=True, driver=driver)
    assert result["status"] == "configured"
    receipt = agent_plugins.read_receipt(runtime.state_dir, harness)
    root = agent_plugins.directory(runtime.state_dir, harness) / "catalog/plugins/adr-agent"
    mcp = json.loads((root / ".mcp.json").read_text())
    assert "adr_context" in mcp["mcpServers"]
    assert (root / "hooks/hooks.json").is_file()
    grant = runtime.store.one("SELECT * FROM grants WHERE id=?", (receipt["grant_id"],))
    assert grant["kind"] == "context" and grant["history_scope"] == "device"
    assert grant["credentials"] == "[]" and grant["approval_mode"] == "ask"
    access = json.loads((runtime.state_dir / "agents" / f"{grant['id']}.json").read_text())
    for relative in receipt["files"]:
        assert access["token"] not in (root / relative).read_text()
    assert hooks.installed(harness, state_dir=runtime.state_dir)
    assert runtime.starter_protection()["connected"]


@pytest.mark.parametrize("harness", ["claude", "codex"])
def test_native_bundle_names_its_protection_checks(runtime, driver, harness):
    agent_plugins.connect(runtime, harness, allow_context=True, driver=driver)
    root = agent_plugins.directory(runtime.state_dir, harness) / "catalog/plugins/adr-agent"
    configured = json.loads((root / "hooks/hooks.json").read_text())["hooks"]
    assert configured["PreToolUse"][0]["hooks"][0]["statusMessage"] == "ADR: check file access"
    assert configured["PostToolUse"][0]["hooks"][0]["statusMessage"] == "ADR: check tool output"


def test_no_context_permission_is_created_without_consent(runtime, driver):
    with pytest.raises(ValueError, match="consent"):
        agent_plugins.connect(runtime, "codex", allow_context=False, driver=driver)
    assert runtime.store.rows("SELECT * FROM grants") == []
    assert driver.calls == []


def test_updates_reuse_the_permission_and_private_marketplace(runtime, driver):
    agent_plugins.connect(runtime, "codex", allow_context=True, driver=driver)
    before = agent_plugins.read_receipt(runtime.state_dir, "codex")
    agent_plugins.connect(runtime, "codex", allow_context=True, driver=driver)
    after = agent_plugins.read_receipt(runtime.state_dir, "codex")
    assert before["grant_id"] == after["grant_id"] and before["market"] == after["market"]
    assert len(runtime.store.rows("SELECT * FROM grants")) == 1


def test_failed_install_revokes_new_context_access(runtime, driver, monkeypatch):
    monkeypatch.setattr(
        driver, "install", lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("synthetic"))
    )
    with pytest.raises(RuntimeError):
        agent_plugins.connect(runtime, "codex", allow_context=True, driver=driver)
    assert runtime.store.one("SELECT revoked FROM grants")["revoked"] == 1
    assert agent_plugins.read_receipt(runtime.state_dir, "codex")["status"] == "needs_repair"


def test_disconnect_revokes_access_before_a_native_uninstall_failure(runtime, driver, monkeypatch):
    agent_plugins.connect(runtime, "codex", allow_context=True, driver=driver)
    monkeypatch.setattr(
        driver, "remove", lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("synthetic"))
    )
    with pytest.raises(RuntimeError):
        agent_plugins.disconnect(runtime, "codex", driver=driver)
    assert runtime.store.one("SELECT revoked FROM grants")["revoked"] == 1
    assert not agent_plugins.configured(runtime.state_dir, "codex")


def test_native_bundle_replaces_only_older_direct_adr_hooks(runtime, driver):
    target = hooks.configuration_path("claude")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Read",
                            "hooks": [{"type": "command", "command": "echo keep"}],
                        }
                    ]
                }
            }
        )
    )
    hooks.install("claude", runtime.state_dir)
    agent_plugins.connect(runtime, "claude", allow_context=True, driver=driver)
    commands = [
        item["command"]
        for group in json.loads(target.read_text())["hooks"]["PreToolUse"]
        for item in group["hooks"]
    ]
    assert commands == ["echo keep"]
    assert hooks.installed("claude", state_dir=runtime.state_dir)


def test_owner_endpoint_requires_context_consent_and_does_not_grant_vault(client, owner, runtime, driver):
    url = "/api/integrations/codex/connect"
    assert client.post(url, json={"allow_context": True}).status_code == 401
    assert client.post(url, headers=owner, json={}).status_code == 400
    assert client.post(url, headers=owner, json={"allow_context": True}).status_code == 200
    receipt = agent_plugins.read_receipt(runtime.state_dir, "codex")
    grant = {"id": receipt["grant_id"]}
    headers = {"Authorization": "Bearer " + grant_token(runtime, grant)}
    assert client.get("/api/agent/status", headers=headers).json()["kind"] == "context"
    assert client.get("/api/agent/credentials", headers=headers).status_code == 403
    assert client.get("/api/protection", headers=headers).status_code == 401


def test_cli_enrollment_cannot_self_approve_or_be_triggered_by_a_web_page(client, runtime, driver):
    body = {"harness": "codex", "allow_context": True}
    assert (
        client.post(
            "/api/integrations/enroll",
            json=body,
            headers={"Origin": "http://127.0.0.1:48321"},
        ).status_code
        == 403
    )
    assert client.post("/api/integrations/enroll", json=body).status_code == 403
    assert runtime.native.calls[-1][0] == "approve_integration"
    assert runtime.store.rows("SELECT * FROM grants") == []


def test_native_owner_approval_enrolls_the_bundle(client, runtime, driver, monkeypatch):
    monkeypatch.setattr(runtime.native, "call", lambda *_args, **_kwargs: {"allowed": True})
    response = client.post("/api/integrations/enroll", json={"harness": "codex", "allow_context": True})
    assert response.status_code == 200
    assert response.json()["context"] is True
    token = json.loads(next((runtime.state_dir / "agents").glob("*.json")).read_text())["token"]
    assert token not in response.text


def test_context_tools_are_agent_facing_and_old_history_route_is_not_a_hub(client, owner, runtime):
    assert client.get("/history", follow_redirects=False).status_code == 307
    grant = runtime.create_grant("Context", kind="context", confirm_device_history=True)
    access = runtime.state_dir / "agents" / f"{grant['id']}.json"
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    ]
    result = subprocess.run(
        [sys.executable, "-m", "adr_desktop", "mcp", "--access-file", str(access)],
        input="".join(json.dumps(message) + "\n" for message in messages),
        text=True,
        capture_output=True,
        timeout=10,
    )
    replies = [json.loads(line) for line in result.stdout.splitlines()]
    assert replies[0]["result"]["serverInfo"]["name"] == "ADR Context"
    names = {tool["name"] for tool in replies[-1]["result"]["tools"]}
    assert names == {
        "adr_status",
        "adr_search_conversations",
        "adr_list_conversations",
        "adr_get_conversation",
    }
    page = client.get("/assets/app.js").text
    assert '"History MCP"' not in page and "historyConnectionDialog" not in page


def test_context_search_crosses_projects_and_agents_with_new_scope(client, runtime):
    for source, project in [("claude", "/project/a"), ("opencode", "/project/b")]:
        runtime.store.ingest(
            sample_session(source=source, session_id=source, project=project, content="contextneedle")
        )
    grant = runtime.create_grant("Context", kind="context", confirm_device_history=True)
    result = client.get(
        "/api/agent/history/search?q=contextneedle",
        headers={"Authorization": "Bearer " + grant_token(runtime, grant)},
    )
    assert result.json()["total"] == 2


def test_bundle_directory_symlink_does_not_write_outside_state(runtime, driver, tmp_path):
    target = agent_plugins.directory(runtime.state_dir, "codex")
    target.parent.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    target.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError):
        agent_plugins.connect(runtime, "codex", allow_context=True, driver=driver)
    assert not list(outside.iterdir())
    assert runtime.store.rows("SELECT * FROM grants") == []
