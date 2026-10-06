import copy
import sqlite3
import time
import zlib

import pytest
from conftest import add_credential, grant_token, sample_session

from adr_desktop.config import canonical, prepare_state_dir
from adr_desktop.mcp_server import tools_for
from adr_desktop.store import SCHEMA, Store


def history_grant(runtime):
    return runtime.create_grant("History", kind="history", confirm_device_history=True)


def test_history_search_finds_messages_and_tool_results_across_agents(runtime):
    for source, project in [("claude", "/work/a"), ("codex", "/work/b"), ("opencode", "/work/c")]:
        payload = sample_session(source=source, session_id=source, project=project)
        payload["chat_history"][1]["tools"][0]["result"] = "Diagnosed the oauth refresh regression"
        runtime.store.ingest(payload)
    result = runtime.store.search_history("oauth refresh")
    assert result["total"] == 3
    assert {row["source"] for row in result["items"]} == {"claude", "codex", "opencode"}
    assert all("oauth" in row["snippet"] for row in result["items"])
    assert runtime.store.search_history("oauth", source="codex")["total"] == 1
    page = runtime.store.search_history("oauth", limit=1)
    assert page["next_offset"] == 1
    assert len(runtime.store.search_history("oauth", limit=1, offset=1)["items"]) == 1


def test_search_reindexes_changed_results_and_does_not_restore_older_snapshots(runtime):
    payload = sample_session()
    payload["chat_history"][1]["tools"][0]["result"] = "obsoletekeyword"
    runtime.store.ingest(payload)
    changed = copy.deepcopy(payload)
    changed["chat_history"][1]["tools"][0]["result"] = "currentkeyword"
    runtime.store.ingest(changed)
    assert runtime.store.search_history("obsoletekeyword")["total"] == 0
    assert runtime.store.search_history("currentkeyword")["total"] == 1
    payload["timestamp"] = "2026-01-01T00:00:00Z"
    runtime.store.ingest(payload)
    assert runtime.store.search_history("currentkeyword")["total"] == 1
    runtime.store.purge_history()
    assert runtime.store.search_history("currentkeyword")["total"] == 0
    assert runtime.store.rows("SELECT * FROM history_documents") == []


@pytest.mark.parametrize("query", ["", "  ", "*", "a" * 201, "word " * 33])
def test_search_bounds_and_operator_only_queries(runtime, query):
    with pytest.raises(ValueError):
        runtime.store.search_history(query)


def test_search_treats_operators_and_sql_as_literal_words(runtime):
    runtime.store.ingest(sample_session(content="needle"))
    assert runtime.store.search_history('needle OR "missing"')["total"] == 0
    assert runtime.store.search_history("'; DROP TABLE sessions; --")["total"] == 0
    assert runtime.store.sessions()["total"] == 1


def test_device_history_connection_is_explicit_and_cannot_use_vault(client, runtime):
    with pytest.raises(ValueError, match="Confirm"):
        runtime.create_grant("History", kind="history")
    for source, project in [("claude", "/work/a"), ("codex", "/work/b")]:
        runtime.store.ingest(
            sample_session(source=source, session_id=source, project=project, content="needle")
        )
    grant = history_grant(runtime)
    headers = {"Authorization": "Bearer " + grant_token(runtime, grant)}
    result = client.get("/api/agent/history/search?q=needle", headers=headers)
    assert result.status_code == 200
    assert result.json()["total"] == 2
    for row in result.json()["items"]:
        assert client.get(f"/api/agent/sessions/{row['id']}", headers=headers).status_code == 200
    assert client.get("/api/agent/credentials", headers=headers).status_code == 403
    credential = add_credential(runtime)
    assert (
        client.post(
            "/api/agent/broker", headers=headers, json={"credential_id": credential["id"], "path": "/user"}
        ).status_code
        == 403
    )
    runtime.revoke_grant(grant["id"])
    assert client.get("/api/agent/history/search?q=needle", headers=headers).status_code == 401


def test_existing_project_grant_stays_project_scoped_for_search(client, runtime):
    for project in ("/work/a", "/work/b"):
        runtime.store.ingest(sample_session(session_id=project, project=project, content="needle"))
    grant = runtime.create_grant("Existing", "/work/a", [])
    headers = {"Authorization": "Bearer " + grant_token(runtime, grant)}
    result = client.get("/api/agent/history/search?q=needle", headers=headers).json()
    assert result["total"] == 1
    assert result["items"][0]["project"] == "/work/a"
    assert (
        runtime.store.one("SELECT approval_mode FROM grants WHERE id=?", (grant["id"],))["approval_mode"]
        == "ask"
    )


def test_vault_connection_has_no_history_access_and_needs_explicit_automatic_permission(client, runtime):
    credential = add_credential(runtime)
    with pytest.raises(ValueError, match="Confirm automatic"):
        runtime.create_grant("Vault", credentials=[credential["id"]], kind="vault", approval_mode="automatic")
    grant = runtime.create_grant(
        "Vault",
        credentials=[credential["id"]],
        kind="vault",
        approval_mode="automatic",
        confirm_automatic=True,
    )
    headers = {"Authorization": "Bearer " + grant_token(runtime, grant)}
    for path in ("/api/agent/sessions", "/api/agent/history/search?q=needle", "/api/agent/sessions/unknown"):
        assert client.get(path, headers=headers).status_code == 403
    result = client.post(
        "/api/agent/broker", headers=headers, json={"credential_id": credential["id"], "path": "/user"}
    )
    assert result.status_code == 200
    assert result.json()["state"] == "running"
    identifier = result.json()["request_id"]
    for _ in range(100):
        response = client.get(f"/api/agent/broker/{identifier}", headers=headers).json()
        if response["state"] != "running":
            break
        time.sleep(0.01)
    assert response["state"] == "succeeded"
    assert sum(operation == "vault_perform" for operation, _ in runtime.native.calls) == 1
    assert (
        client.post(
            "/api/agent/broker", headers=headers, json={"credential_id": credential["id"], "path": "/outside"}
        ).status_code
        == 403
    )


def test_mcp_tool_lists_separate_history_and_vault():
    history = {tool["name"] for tool in tools_for({"kind": "history"})}
    vault = {tool["name"] for tool in tools_for({"kind": "vault"})}
    assert "adr_search_history" in history and "adr_request_service" not in history
    assert "adr_request_service" in vault and "adr_get_session" not in vault


def test_owner_must_confirm_device_history_and_can_retrieve_setup(client, owner, runtime):
    assert (
        client.post("/api/agents", headers=owner, json={"name": "History", "kind": "history"}).status_code
        == 400
    )
    response = client.post(
        "/api/agents",
        headers=owner,
        json={"name": "History", "kind": "history", "confirm_device_history": True},
    )
    assert response.status_code == 200
    data = response.json()
    assert "adr_history" in data["configuration"]["mcpServers"]
    config = client.get(f"/api/agents/{data['id']}/configuration", headers=owner)
    assert config.json() == data["configuration"]
    assert grant_token(runtime, data) not in config.text


def test_v1_migration_backfills_history_and_preserves_old_permissions(runtime, tmp_path):
    directory = prepare_state_dir(tmp_path / "v1-profile")
    db = sqlite3.connect(directory / "desktop.sqlite3")
    db.executescript(SCHEMA.split("CREATE TABLE IF NOT EXISTS history_documents(")[0])
    payload = sample_session(content="migrationneedle")
    db.execute(
        "INSERT INTO snapshots VALUES (?,?,?,?)",
        ("digest", "session", "now", zlib.compress(canonical(payload).encode())),
    )
    db.execute(
        "INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("session", "claude", "one", "/work", "model", "title", "now", "now", "now", 2, 1, None, "digest", 0),
    )
    db.execute("INSERT INTO grants VALUES (?,?,?,?,?,?,?)", ("grant", "old", "hash", "/work", "[]", "now", 0))
    db.execute("PRAGMA user_version=1")
    db.commit()
    db.close()
    migrated = Store(directory)
    try:
        assert migrated.search_history("migrationneedle")["total"] == 1
        grant = migrated.one("SELECT * FROM grants")
        assert grant["history_scope"] == "project" and grant["project"] == "/work"
        assert grant["approval_mode"] == "ask" and grant["kind"] == "legacy"
        assert migrated.session("session")["payload"] == payload
        assert migrated.one("PRAGMA user_version")["user_version"] == 3
    finally:
        migrated.close()
