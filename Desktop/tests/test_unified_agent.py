import json

import pytest
from conftest import FakePluginDriver, grant_token, sample_session

from adr_desktop import agent_plugins
from adr_desktop.config import read_private_json
from adr_desktop.mcp_server import tools_for
from adr_desktop.native import NativeUnavailable


def active_grant(runtime, harness="codex"):
    receipt = agent_plugins.read_receipt(runtime.state_dir, harness)
    return runtime.store.one("SELECT * FROM grants WHERE id=?", (receipt["grant_id"],))


@pytest.fixture
def driver(runtime):
    result = FakePluginDriver()
    runtime.integration_driver = result
    return result


def test_single_owner_action_connects_all_harnesses_without_per_key_configuration(
    client, owner, runtime, driver
):
    assert client.post("/api/integrations/connect-all", json={"allow_agents": True}).status_code == 401
    assert client.post("/api/integrations/connect-all", headers=owner, json={}).status_code == 400
    assert not driver.calls
    result = client.post("/api/integrations/connect-all", headers=owner, json={"allow_agents": True})
    assert result.status_code == 200
    assert {item["harness"] for item in result.json()["items"] if item["status"] == "configured"} == {
        "claude",
        "codex",
        "copilot",
        "opencode",
    }
    for harness in agent_plugins.hooks.HARNESS_LABELS:
        principal = active_grant(runtime, harness)
        assert principal["kind"] == "agent"
        assert principal["history_scope"] == "device"
        assert principal["approval_mode"] == "automatic"
        assert principal["project"] == ""
        assert json.loads(principal["credentials"]) == ["*"]
        root = agent_plugins.directory(runtime.state_dir, harness) / "catalog/plugins/adr-agent"
        assert set(json.loads((root / ".mcp.json").read_text())["mcpServers"]) == {"adr"}
        assert (root / "skills/adr/SKILL.md").is_file()
        assert (root / "hooks/hooks.json").is_file()
        assert grant_token(runtime, principal) not in result.text


def test_new_keys_are_available_in_every_connected_agent_without_reconnection(runtime, driver, tmp_path):
    agent_plugins.connect_all(runtime, allow_agents=True, driver=driver)
    tokens = {
        harness: grant_token(runtime, active_grant(runtime, harness)) for harness in ("claude", "codex")
    }
    first = runtime.environment_vault.create("First", "FIRST_PASSWORD")
    second = runtime.environment_vault.create("Second", "SECOND_PASSWORD")
    for harness in ("claude", "codex"):
        principal = active_grant(runtime, harness)
        assert {item["id"] for item in runtime.environment_vault.permitted(principal)} == {
            first["id"],
            second["id"],
        }
        assert grant_token(runtime, principal) == tokens[harness]
        # Commands can run from different projects without changing a grant.
        for cwd in (tmp_path, tmp_path / "another-project"):
            cwd.mkdir(exist_ok=True)
            result = runtime.environment_vault.execute(principal, 'test -n "$FIRST_PASSWORD"', str(cwd))
            assert result["exit_code"] == 0
    assert not any(operation == "approve_tool" for operation, _ in runtime.native.calls)
    assert {tool["name"] for tool in tools_for({"kind": "agent"})} == {
        "adr_status",
        "adr_list_environment",
        "adr_run_command",
        "adr_search_conversations",
        "adr_list_conversations",
        "adr_get_conversation",
    }
    runtime.environment_vault.remove(first["id"])
    assert [item["id"] for item in runtime.environment_vault.permitted(active_grant(runtime))] == [
        second["id"]
    ]


def test_read_only_tokens_are_not_silently_upgraded_and_success_revokes_previous(runtime, driver):
    agent_plugins.connect(runtime, "codex", allow_context=True, driver=driver)
    previous = active_grant(runtime)
    with pytest.raises(PermissionError):
        runtime.environment_vault.permitted(previous)
    agent_plugins.connect(runtime, "codex", allow_context=True, allow_credentials=True, driver=driver)
    current = active_grant(runtime)
    assert current["id"] != previous["id"]
    assert runtime.grant(grant_token(runtime, previous)) is None
    assert runtime.grant(grant_token(runtime, current))["kind"] == "agent"
    agent_plugins.connect(runtime, "codex", allow_context=True, allow_credentials=True, driver=driver)
    assert active_grant(runtime)["id"] == current["id"]
    assert len(runtime.store.rows("SELECT * FROM grants WHERE revoked=0")) == 1


def test_failed_upgrade_keeps_prior_scope_and_retry_does_not_leave_untracked_grants(
    runtime, driver, monkeypatch
):
    agent_plugins.connect(runtime, "codex", allow_context=True, driver=driver)
    previous = active_grant(runtime)
    install = driver.install

    def failure(*_args, **_kwargs):
        raise ValueError("synthetic install failure")

    monkeypatch.setattr(driver, "install", failure)
    with pytest.raises(ValueError):
        agent_plugins.connect(runtime, "codex", allow_context=True, allow_credentials=True, driver=driver)
    assert runtime.grant(grant_token(runtime, previous))["kind"] == "context"
    assert not runtime.store.rows("SELECT * FROM grants WHERE kind='agent' AND revoked=0")
    monkeypatch.setattr(driver, "install", install)
    agent_plugins.connect(runtime, "codex", allow_context=True, allow_credentials=True, driver=driver)
    assert runtime.grant(grant_token(runtime, previous)) is None
    assert len(runtime.store.rows("SELECT * FROM grants WHERE revoked=0")) == 1


def test_all_setup_reports_missing_and_failed_agents_without_rolling_back_other_successes(runtime, driver):
    def executable(harness):
        if harness == "opencode":
            raise ValueError("not installed")
        return "/synthetic/" + harness

    def install(harness, *_args, **_kwargs):
        if harness == "copilot":
            raise RuntimeError("private configuration must not be included in a response")

    driver.executable, driver.install = executable, install
    result = agent_plugins.connect_all(runtime, allow_agents=True, driver=driver)
    assert {item["harness"]: item["status"] for item in result["items"]} == {
        "claude": "configured",
        "codex": "configured",
        "copilot": "needs_repair",
        "opencode": "not_installed",
    }
    assert "private configuration" not in json.dumps(result)
    assert {row["kind"] for row in runtime.store.rows("SELECT * FROM grants WHERE revoked=0")} == {"agent"}
    assert len(runtime.store.rows("SELECT * FROM grants WHERE revoked=0")) == 2


def test_unified_credential_use_preserves_file_rules_and_cannot_administer_adr(
    client, owner, runtime, driver, tmp_path
):
    runtime.environment_vault.create("Synthetic", "MY_PASSWORD")
    runtime.change_policy(add={"path": str(tmp_path / "private"), "kind": "file", "action": "block"})
    before = (runtime.state_dir / "policy.json").read_bytes()
    agent_plugins.connect_all(runtime, allow_agents=True, driver=driver)
    assert (runtime.state_dir / "policy.json").read_bytes() == before
    principal = active_grant(runtime)
    headers = {"Authorization": "Bearer " + grant_token(runtime, principal)}
    assert (
        client.post("/api/integrations/connect-all", headers=headers, json={"allow_agents": True}).status_code
        == 401
    )
    assert client.get("/api/environment-credentials", headers=headers).status_code == 401
    assert client.get("/api/agent/environment", headers=headers).status_code == 200
    assert (
        client.post(
            "/api/agent/environment/run",
            headers=headers,
            json={"command": "cat private", "cwd": str(tmp_path)},
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/agent/environment/run",
            headers=headers,
            json={"command": "pwd"},
        ).status_code
        == 400
    )
    assert not any(operation == "environment_execute" for operation, _ in runtime.native.calls)
    client.post("/api/integrations/codex/disconnect", headers=owner)
    assert client.get("/api/agent/environment", headers=headers).status_code == 401
    assert runtime.environment_vault.entries()[0]["state"] == "active"


def test_file_ask_still_applies_without_per_credential_approval(runtime, driver, tmp_path):
    runtime.environment_vault.create("Synthetic", "MY_PASSWORD")
    agent_plugins.connect_all(runtime, allow_agents=True, driver=driver)
    runtime.change_policy(add={"path": str(tmp_path / "private"), "kind": "file", "action": "ask"})
    with pytest.raises(PermissionError, match="not approved"):
        runtime.environment_vault.execute(active_grant(runtime), "cat private", str(tmp_path))
    assert any(operation == "approve_tool" for operation, _ in runtime.native.calls)


def test_model_history_withholds_credentials_without_changing_original_records(client, runtime, driver):
    saved = runtime.environment_vault.create("Synthetic", "MY_PASSWORD")
    secret = runtime.native.environment_values[saved["id"]]
    runtime.store.ingest(sample_session(content="old historyneedle contains " + secret))
    session_id = runtime.store.one("SELECT id FROM sessions")["id"]
    agent_plugins.connect_all(runtime, allow_agents=True, driver=driver)
    headers = {"Authorization": "Bearer " + grant_token(runtime, active_grant(runtime))}
    for path in (
        f"/api/agent/sessions/{session_id}",
        "/api/agent/history/search?q=historyneedle",
        "/api/agent/sessions",
    ):
        result = client.get(path, headers=headers)
        assert result.status_code == 200
        assert result.json()["output_withheld"] is True
        assert secret not in result.text
    assert secret in json.dumps(runtime.store.session(session_id))
    assert not runtime.store.rows("SELECT * FROM prompt_blocks")
    checked = [arguments for operation, arguments in runtime.native.calls if operation == "vault_check_text"]
    assert checked and all(item["purpose"] == "output" for item in checked)


def test_model_history_passes_safe_content_and_withholds_uncheckable_results(runtime):
    runtime.environment_vault.create("Synthetic", "MY_PASSWORD")
    value = {"content": "Use the saved $MY_PASSWORD"}
    assert runtime.environment_vault.model_history(value) == value
    runtime.native.connected = False
    assert runtime.environment_vault.model_history(value)["output_withheld"]
    assert runtime.environment_vault.model_history({"content": "x" * (256 * 1024)})["output_withheld"]


def test_unified_access_cannot_be_requested_through_old_unconfirmed_grant_endpoint(client, owner, runtime):
    with pytest.raises(ValueError, match="Confirm"):
        runtime.create_grant("Unconfirmed agent", kind="agent")
    assert (
        client.post("/api/agents", headers=owner, json={"name": "Agent", "kind": "agent"}).status_code == 422
    )


def test_unified_native_enrollment_requires_one_owner_confirmation(client, runtime, driver, monkeypatch):
    payload = {"harness": "all", "allow_agents": True}
    assert client.post("/api/integrations/enroll", json=payload).status_code == 403
    assert not runtime.store.rows("SELECT * FROM grants")
    assert runtime.native.calls[-1] == (
        "approve_integration",
        {"harness": "installed agents", "credentials": True},
    )
    runtime.last_enrollment = 0
    native = runtime.native.call
    monkeypatch.setattr(
        runtime.native,
        "call",
        lambda operation, *args, **kwargs: (
            {"allowed": True} if operation == "approve_integration" else native(operation, *args, **kwargs)
        ),
    )
    response = client.post("/api/integrations/enroll", json=payload)
    assert response.status_code == 200
    assert len(response.json()["items"]) == 4
    status = runtime.status()
    assert all(item["vault_connected"] and not item["needs_update"] for item in status["hooks"])
    for row in runtime.store.rows("SELECT * FROM grants"):
        capability = read_private_json(runtime.state_dir / "agents" / f"{row['id']}.json")
        assert capability["token"] not in response.text


def test_keychain_failure_is_availability_not_false_pasted_secret(
    client, runtime, driver, monkeypatch, tmp_path,
):
    runtime.environment_vault.create("Synthetic", "MY_PASSWORD")
    agent_plugins.connect(runtime, "codex", allow_context=True, allow_credentials=True, driver=driver)
    native = runtime.native.call

    def unavailable(operation, *args, **kwargs):
        if operation == "vault_check_text":
            raise NativeUnavailable("keychain_unavailable")
        return native(operation, *args, **kwargs)

    monkeypatch.setattr(runtime.native, "call", unavailable)
    headers = {"Authorization": "Bearer " + grant_token(runtime, active_grant(runtime))}
    response = client.post(
        "/api/agent/environment/run",
        headers=headers,
        json={"command": 'test -n "$MY_PASSWORD"', "cwd": str(tmp_path)},
    )
    assert response.status_code == 503
    assert response.json()["detail"] == "keychain_unavailable"
    assert not runtime.store.rows("SELECT * FROM prompt_blocks")
    assert not any(operation == "environment_execute" for operation, _ in runtime.native.calls)


@pytest.mark.parametrize("detail", ["keychain_unavailable", "untrusted-response-secret-123"])
def test_mcp_client_surfaces_only_closed_availability_messages(monkeypatch, tmp_path, detail):
    from adr_desktop import local_client

    class Response:
        status = 503

        def read(self, _limit):
            return json.dumps({"detail": detail}).encode()

    class Connection:
        def request(self, *_args, **_kwargs):
            pass

        def getresponse(self):
            return Response()

        def close(self):
            pass

    monkeypatch.setattr(local_client, "read_private_json", lambda *_args, **_kwargs: {"port": 48321})
    monkeypatch.setattr(local_client.http.client, "HTTPConnection", lambda *_args, **_kwargs: Connection())
    with pytest.raises(local_client.LocalUnavailable) as failure:
        local_client.request(tmp_path, "POST", "/api/agent/environment/run")
    if detail == "keychain_unavailable":
        assert "macOS Keychain" in str(failure.value)
    else:
        assert detail not in str(failure.value)
        assert "HTTP 503" in str(failure.value)
