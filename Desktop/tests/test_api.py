import json
import time

import pytest
from conftest import add_credential, grant_token, sample_session

from adr_desktop.api import COOKIE
from adr_desktop.config import token_hash


def test_ui_requires_a_one_time_ticket(client, runtime):
    assert client.get("/api/status").status_code == 401
    ticket = runtime.new_ticket()
    response = client.post("/api/auth/bootstrap", json={"ticket": ticket})
    assert response.status_code == 200
    assert "HttpOnly" in response.headers["set-cookie"]
    assert "SameSite=strict" in response.headers["set-cookie"]
    assert client.post("/api/auth/bootstrap", json={"ticket": ticket}).status_code == 403
    assert client.get("/api/status").status_code == 200


def test_owner_cookie_needs_csrf_for_mutations(client, runtime):
    response = client.post("/api/auth/bootstrap", json={"ticket": runtime.new_ticket()})
    assert client.patch("/api/settings", json={"history_days": 7}).status_code == 403
    assert (
        client.patch(
            "/api/settings",
            json={"history_days": 7},
            headers={"X-ADR-CSRF": response.json()["csrf"]},
        ).status_code
        == 200
    )


def test_opening_a_second_tab_keeps_pause_working_in_the_first(client, runtime):
    first = client.post("/api/auth/bootstrap", json={"ticket": runtime.new_ticket()})
    runtime.store.setting("recording", True)
    second = client.post("/api/auth/bootstrap", json={"ticket": runtime.new_ticket()})
    assert second.status_code == 200
    response = client.post("/api/collector/pause", headers={"X-ADR-CSRF": first.json()["csrf"]})
    assert response.status_code == 200
    assert response.json()["recording"] is False
    assert second.json()["csrf"] == first.json()["csrf"]


def test_stale_csrf_is_rejected_before_pause_and_can_be_refreshed(client, runtime):
    client.post("/api/auth/bootstrap", json={"ticket": runtime.new_ticket()})
    runtime.store.setting("recording", True)
    response = client.post("/api/collector/pause", headers={"X-ADR-CSRF": "stale-tab-token"})
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "csrf_mismatch"
    assert runtime.store.settings()["recording"] is True
    assert runtime.store.rows("SELECT * FROM audit WHERE kind='collection_changed'") == []
    csrf = client.get("/api/auth/session").json()["csrf"]
    assert client.post("/api/collector/pause", headers={"X-ADR-CSRF": csrf}).status_code == 200
    assert runtime.store.settings()["recording"] is False
    assert len(runtime.store.rows("SELECT * FROM audit WHERE kind='collection_changed'")) == 1


def test_reused_session_still_requires_a_fresh_unexpired_ticket(client, runtime):
    first_ticket = runtime.new_ticket()
    client.post("/api/auth/bootstrap", json={"ticket": first_ticket})
    cookie = client.cookies.get(COOKIE)
    current = client.get("/api/auth/session").json()
    expired_ticket = runtime.new_ticket()
    runtime.tickets[token_hash(expired_ticket)] = time.monotonic() - 1
    for ticket in (first_ticket, expired_ticket, "invalid-ticket"):
        response = client.post("/api/auth/bootstrap", json={"ticket": ticket})
        assert response.status_code == 403
        assert "set-cookie" not in response.headers
        assert client.cookies.get(COOKIE) == cookie
        assert client.get("/api/auth/session").json() == current


def test_reopening_renews_valid_session_without_rotating_it(client, runtime):
    first = client.post("/api/auth/bootstrap", json={"ticket": runtime.new_ticket()})
    cookie = client.cookies.get(COOKIE)
    original_expiry = time.monotonic() + 60
    runtime.sessions[token_hash(cookie)] = (first.json()["csrf"], original_expiry)
    second = client.post("/api/auth/bootstrap", json={"ticket": runtime.new_ticket()})
    assert second.status_code == 200
    assert client.cookies.get(COOKIE) == cookie
    assert second.json() == first.json()
    assert runtime.sessions[token_hash(cookie)][1] > original_expiry
    assert len(runtime.sessions) == 1


def test_expired_session_needs_a_ticket_and_is_replaced(client, runtime):
    first = client.post("/api/auth/bootstrap", json={"ticket": runtime.new_ticket()})
    cookie = client.cookies.get(COOKIE)
    runtime.sessions[token_hash(cookie)] = (first.json()["csrf"], time.monotonic() - 1)
    assert client.get("/api/auth/session").status_code == 401
    assert client.post(
        "/api/collector/pause", headers={"X-ADR-CSRF": first.json()["csrf"]}
    ).status_code == 401
    second = client.post("/api/auth/bootstrap", json={"ticket": runtime.new_ticket()})
    assert second.status_code == 200
    assert client.cookies.get(COOKIE) != cookie
    assert second.json()["csrf"] != first.json()["csrf"]
    assert token_hash(cookie) not in runtime.sessions
    assert len(runtime.sessions) == 1


def test_bootstrap_does_not_adopt_an_unrecognized_cookie(client, runtime):
    client.cookies.set(COOKIE, "unrecognized-cookie", domain="127.0.0.1", path="/")
    response = client.post("/api/auth/bootstrap", json={"ticket": runtime.new_ticket()})
    assert response.status_code == 200
    assert client.cookies.get(COOKIE) != "unrecognized-cookie"
    assert runtime.session("unrecognized-cookie") is None


@pytest.mark.parametrize(
    "headers",
    [
        {"Origin": "https://evil.example"},
        {"Origin": "http://127.0.0.1:48322"},
        {"Sec-Fetch-Site": "cross-site"},
    ],
)
def test_cross_origin_cannot_refresh_csrf_or_consume_a_ticket(client, runtime, headers):
    client.post("/api/auth/bootstrap", json={"ticket": runtime.new_ticket()})
    current = client.get("/api/auth/session").json()
    response = client.get("/api/auth/session", headers=headers)
    assert response.status_code == 403
    assert current["csrf"] not in response.text
    ticket = runtime.new_ticket()
    response = client.post("/api/auth/bootstrap", json={"ticket": ticket}, headers=headers)
    assert response.status_code == 403
    assert "set-cookie" not in response.headers
    assert client.post("/api/auth/bootstrap", json={"ticket": ticket}).status_code == 200
    assert client.get("/api/auth/session").json() == current


@pytest.mark.parametrize("seconds", [300, 900, 1800, 3600])
def test_capture_interval_accepts_minute_presets(client, owner, runtime, seconds):
    response = client.patch("/api/settings", headers=owner, json={"interval_seconds": seconds})
    assert response.status_code == 200
    assert runtime.store.settings()["interval_seconds"] == seconds
    assert runtime.store.settings()["recording"] is False


@pytest.mark.parametrize("seconds", [15, 30, 60, 120, 301, 7200, True, "300", 300.0])
def test_capture_interval_rejects_other_values(client, owner, runtime, seconds):
    before = runtime.store.settings()
    response = client.patch("/api/settings", headers=owner, json={"interval_seconds": seconds})
    assert response.status_code == 422
    assert runtime.store.settings() == before


@pytest.mark.parametrize("origin", ["https://evil.example", "http://127.0.0.1:48322", "null"])
def test_cross_origin_requests_are_rejected_even_with_capability(client, owner, origin):
    assert client.get("/api/status", headers={**owner, "Origin": origin}).status_code == 403


@pytest.mark.parametrize("host", ["evil.example:48321", "127.0.0.1.evil.example:48321", "127.0.0.1"])
def test_dns_rebinding_hosts_are_rejected(client, owner, host):
    assert client.get("/api/status", headers={**owner, "Host": host}).status_code == 403


def test_agent_token_cannot_administer_app(client, runtime):
    grant = runtime.create_grant("Test agent", "/workspace/sample", [])
    headers = {"Authorization": "Bearer " + grant_token(runtime, grant)}
    for path in ["/api/status", "/api/credentials", "/api/agents", "/api/protection", "/api/audit"]:
        assert client.get(path, headers=headers).status_code == 401
    assert client.post("/api/control/open", headers=headers).status_code == 401
    assert client.patch("/api/protection", headers=headers, json={"enabled": False}).status_code == 401
    assert client.post("/api/approvals/fake", headers=headers, json={"allow": True}).status_code == 401


def test_hook_capability_can_only_report_decisions(client, runtime):
    headers = {"Authorization": f"Bearer {runtime.hook_token}"}
    body = {"harness": "claude", "decision": "deny", "reason": "Synthetic test", "tool": "Read"}
    assert client.post("/api/hooks/events", headers=headers, json=body).status_code == 200
    assert client.get("/api/credentials", headers=headers).status_code == 401
    assert client.patch("/api/settings", headers=headers, json={"history_days": 30}).status_code == 401


def test_session_scope_and_message_paging(client, runtime):
    for identifier, project in [("one", "/workspace/sample"), ("two", "/workspace/other")]:
        runtime.store.ingest(sample_session(session_id=identifier, project=project))
    grant = runtime.create_grant("Test agent", "/workspace/sample", [])
    headers = {"Authorization": "Bearer " + grant_token(runtime, grant)}
    rows = client.get("/api/agent/sessions", headers=headers).json()["items"]
    assert len(rows) == 1
    page = client.get(f"/api/agent/sessions/{rows[0]['id']}?limit=1", headers=headers).json()
    assert len(page["payload"]["chat_history"]) == 1
    assert page["page"]["total_messages"] == 2
    other = runtime.store.sessions(project="/workspace/other")["items"][0]
    assert client.get(f"/api/agent/sessions/{other['id']}", headers=headers).status_code == 404


def test_project_aliases_match_without_changing_retained_payload(client, runtime, tmp_path):
    project = tmp_path / "actual-project"
    project.mkdir()
    alias = tmp_path / "project-alias"
    alias.symlink_to(project, target_is_directory=True)
    runtime.store.ingest(sample_session(project=str(alias)))
    grant = runtime.create_grant("Alias test", str(project), [])
    headers = {"Authorization": "Bearer " + grant_token(runtime, grant)}
    rows = client.get("/api/agent/sessions", headers=headers).json()["items"]
    assert len(rows) == 1
    data = client.get(f"/api/agent/sessions/{rows[0]['id']}", headers=headers).json()
    assert data["payload"]["project_path"] == str(alias)


def test_secrets_are_not_accepted_by_web_api(client, owner, runtime):
    response = client.post(
        "/api/credentials",
        headers=owner,
        json={
            "name": "Synthetic",
            "origin": "https://api.github.com",
            "allowed_paths": ["/user"],
            "secret": "This must never be accepted through this API",
        },
    )
    assert response.status_code == 422
    assert not runtime.native.calls


def test_credential_entry_is_delegated_to_native_prompt(client, owner, runtime):
    response = client.post(
        "/api/credentials",
        headers=owner,
        json={
            "name": "Synthetic",
            "origin": "https://api.github.com",
            "allowed_paths": ["/user"],
        },
    )
    assert response.status_code == 200
    operation, arguments = runtime.native.calls[0]
    assert operation == "vault_prompt_store"
    assert "secret" not in arguments and "password" not in arguments
    assert "secret" not in response.json()
    assert runtime.store.rows("SELECT * FROM credentials")[0]["state"] == "active"


def test_broker_requires_separate_one_shot_owner_approval(client, owner, runtime):
    credential = add_credential(runtime)
    grant = runtime.create_grant("Test agent", "/workspace/sample", [credential["id"]])
    headers = {"Authorization": "Bearer " + grant_token(runtime, grant)}
    response = client.post(
        "/api/agent/broker",
        headers=headers,
        json={
            "credential_id": credential["id"],
            "path": "/user",
        },
    )
    identifier = response.json()["request_id"]
    assert response.json()["state"] == "pending"
    assert not any(operation == "vault_perform" for operation, _ in runtime.native.calls)
    assert (
        client.post(f"/api/approvals/{identifier}", headers=headers, json={"allow": True}).status_code == 401
    )
    assert client.post(f"/api/approvals/{identifier}", headers=owner, json={"allow": True}).status_code == 200
    assert client.post(f"/api/approvals/{identifier}", headers=owner, json={"allow": True}).status_code == 400
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        result = client.get(f"/api/agent/broker/{identifier}", headers=headers).json()
        if result["state"] != "running":
            break
        time.sleep(0.01)
    assert result["state"] == "succeeded"
    assert result["result"]["body"] == {"login": "synthetic"}
    assert sum(operation == "vault_perform" for operation, _ in runtime.native.calls) == 1


def test_ungranted_credentials_are_invisible_and_unusable(client, runtime):
    credential = add_credential(runtime)
    grant = runtime.create_grant("Insights only", "/workspace/sample", [])
    headers = {"Authorization": "Bearer " + grant_token(runtime, grant)}
    assert client.get("/api/agent/credentials", headers=headers).json()["items"] == []
    assert (
        client.post(
            "/api/agent/broker",
            headers=headers,
            json={
                "credential_id": credential["id"],
                "path": "/user",
            },
        ).status_code
        == 403
    )


def test_agent_revocation_is_immediate(client, runtime):
    grant = runtime.create_grant("Test agent", "/workspace/sample", [])
    headers = {"Authorization": "Bearer " + grant_token(runtime, grant)}
    assert client.get("/api/agent/status", headers=headers).status_code == 200
    runtime.revoke_grant(grant["id"])
    assert client.get("/api/agent/status", headers=headers).status_code == 401


def test_security_headers_and_fixed_static_allowlist(client, owner):
    response = client.get("/")
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert client.get("/assets/desktop.sqlite3").status_code == 404
    assert client.get("/docs").status_code == 404


def test_unknown_settings_cannot_change_policy_or_capabilities(client, owner):
    assert client.patch("/api/settings", headers=owner, json={"owner_token": "bad"}).status_code == 422
    assert client.patch("/api/settings", headers=owner, json={"protection_enabled": False}).status_code == 422


def test_grant_response_has_scoped_mcp_configuration_not_bearer_token(client, owner, runtime):
    response = client.post("/api/agents", headers=owner, json={"name": "Synthetic", "project": "/workspace"})
    assert response.status_code == 200
    content = response.json()
    grant = runtime.store.one("SELECT * FROM grants WHERE id=?", (content["id"],))
    configuration = content["configuration"]["mcpServers"]["adr"]
    assert "--access-file" in configuration["args"]
    raw = json.loads((runtime.state_dir / "agents" / f"{content['id']}.json").read_text())
    assert raw["token"] not in response.text
    assert grant["token_hash"] not in response.text
