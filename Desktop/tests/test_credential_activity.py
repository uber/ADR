"""Session attribution must be exact, local, and independent of vault authority."""

import copy
import io
import json
import sys
from types import SimpleNamespace

import pytest
from conftest import grant_token, sample_session

from adr_desktop.config import canonical
from adr_desktop.credential_activity import recent_runs, record_session, result_run_ids
from adr_desktop.hooks import run_hook
from adr_desktop.local_client import LocalUnavailable
from adr_desktop.mcp_server import serve
from adr_desktop.store import Store

RUN = "b" * 32


def command(runtime, tmp_path):
    if not runtime.environment_vault.entries():
        runtime.environment_vault.create("Synthetic", "TEST_TOKEN")
    grant = runtime.create_grant("Same agent", kind="agent", confirm_agent=True)
    principal = runtime.store.one("SELECT * FROM grants WHERE id=?", (grant["id"],))
    receipt = runtime.environment_vault.execute(principal, "pwd", str(tmp_path))
    return grant, receipt


def captured(runtime, receipt, *, source="codex", native="native-one", context=None, username="synthetic"):
    payload = sample_session(source=source, session_id=f"{source}_{native}", content="Check API access")
    payload["username"] = username
    payload["session_context"] = context or {}
    payload["chat_history"][1]["tools"] = [{
        "tool_name": "mcp__adr__adr_run_command",
        "arguments": {"command": "pwd"},
        "result": json.dumps(receipt),
    }]
    runtime.store.ingest(payload)
    identifier = runtime.store._identity(source, username, payload["session_id"])
    return identifier, payload


def activity(runtime, run_id):
    return next(row for row in recent_runs(runtime.store) if row["id"] == run_id)


@pytest.mark.parametrize("wrapper", [
    lambda value: value,
    lambda value: json.dumps(value),
    lambda value: {"structuredContent": value, "content": [{"type": "text", "text": json.dumps(value)}]},
    lambda value: {"Ok": {"content": [{"type": "text", "text": json.dumps(value)}]}},
    lambda value: {"output": json.dumps(value), "metadata": {}},
    lambda value: [{"type": "text", "text": json.dumps(value)}],
    lambda value: json.dumps(value)[:-1] + "…[truncated]",
])
def test_known_harness_result_envelopes_keep_the_receipt(wrapper):
    assert result_run_ids(wrapper({"run_id": RUN, "exit_code": 0, "stdout": "synthetic"})) == {RUN}


@pytest.mark.parametrize("value", [
    {"stdout": json.dumps({"run_id": RUN})},
    {"stderr": {"run_id": RUN}},
    {"arguments": {"run_id": RUN}},
    "User mentioned " + json.dumps({"run_id": RUN}),
    [{"type": "image", "text": json.dumps({"run_id": RUN})}],
    {"run_id": "../sessions/other"},
    {"run_id": [RUN]},
    None,
])
def test_embedded_or_malformed_ids_are_not_receipts(value):
    assert result_run_ids(value) == set()


def test_concurrent_same_agent_same_directory_uses_distinct_receipts(runtime, tmp_path):
    first_grant, first = command(runtime, tmp_path)
    second_grant, second = command(runtime, tmp_path)
    # Completion/capture order must not affect attribution.
    second_id, _ = captured(runtime, second, native="second")
    first_id, _ = captured(runtime, first, native="first")
    assert record_session(runtime.store, first["run_id"], first_grant["id"], "codex", "first")
    assert record_session(runtime.store, second["run_id"], second_grant["id"], "codex", "second")
    assert activity(runtime, first["run_id"])["session"]["id"] == first_id
    assert activity(runtime, second["run_id"])["session"]["id"] == second_id


@pytest.mark.parametrize("harness,reported,native", [
    ("codex", "native-one", "native-one"),
    ("claude", "native-one", "native-one"),
    ("opencode", "ses_native-one", "native-one"),
])
def test_hook_id_is_visible_before_capture_and_link_resolves_later(
    client, owner, runtime, tmp_path, harness, reported, native,
):
    grant, receipt = command(runtime, tmp_path)
    response = client.post(
        "/api/hooks/credential-use", headers={"Authorization": "Bearer " + runtime.hook_token},
        json={"run_id": receipt["run_id"], "grant_id": grant["id"],
              "harness": harness, "session_id": reported},
    )
    assert response.json() == {"recorded": True}
    pending = client.get("/api/environment-credentials", headers=owner).json()["recent_runs"][0]
    assert pending["session"] is None and pending["session_status"] == "not_captured"
    assert pending["session_id"] == f"{harness}_{native}"
    identifier, _ = captured(runtime, receipt, source=harness, native=native)
    linked = client.get("/api/environment-credentials", headers=owner).json()["recent_runs"][0]
    assert linked["session"]["id"] == identifier and linked["session_status"] == "captured"
    assert client.get(f"/api/sessions/{identifier}", headers=owner).status_code == 200


def test_historical_run_can_link_without_a_hook_report(runtime, tmp_path):
    _, receipt = command(runtime, tmp_path)
    assert activity(runtime, receipt["run_id"])["session_status"] == "unavailable"
    identifier, _ = captured(runtime, receipt)
    assert activity(runtime, receipt["run_id"])["session"]["id"] == identifier


def test_user_messages_other_tools_and_wrong_servers_do_not_claim_a_run(runtime, tmp_path):
    _, receipt = command(runtime, tmp_path)
    for index, tool in enumerate([
        {"tool_name": "Bash", "result": canonical(receipt)},
        {"tool_name": "mcp__other__adr_run_command", "result": canonical(receipt)},
        {"tool_name": "adr_run_command", "server_name": "other", "result": canonical(receipt)},
        {"tool_name": {"unexpected": "shape"}, "result": canonical(receipt)},
    ]):
        payload = sample_session(session_id=str(index), content=canonical(receipt))
        payload["chat_history"][1]["tools"] = [tool]
        runtime.store.ingest(payload)
    assert activity(runtime, receipt["run_id"])["session_status"] == "unavailable"


@pytest.mark.parametrize("name,server", [
    ("adr_run_command", "adr"),
    ("adr_adr_run_command", "adr"),
    ("adr_vault_env_adr_run_command", "adr_vault_env"),
    ("mcp__plugin_adr-agent_adr__adr_run_command", None),
    ("mcp__plugin_adr_agent_adr__adr_run_command", None),
])
def test_packaged_and_legacy_credential_tools_are_indexed(runtime, tmp_path, name, server):
    _, receipt = command(runtime, tmp_path)
    identifier, payload = captured(runtime, receipt)
    payload["chat_history"][1]["tools"][0].update(tool_name=name, server_name=server)
    runtime.store.ingest(payload)
    assert activity(runtime, receipt["run_id"])["session"]["id"] == identifier


def test_mismatched_result_envelopes_do_not_link(runtime, tmp_path):
    _, receipt = command(runtime, tmp_path)
    _, payload = captured(runtime, receipt)
    payload["chat_history"][1]["tools"][0]["result"] = {
        "structuredContent": receipt,
        "content": [{"type": "text", "text": canonical({"run_id": "a" * 32})}],
    }
    runtime.store.ingest(payload)
    assert activity(runtime, receipt["run_id"])["session_status"] == "unavailable"


def test_fork_copy_resolves_to_original_even_if_fork_is_captured_first(runtime, tmp_path):
    _, receipt = command(runtime, tmp_path)
    captured(runtime, receipt, native="fork", context={"forked_from_session_id": "codex_original"})
    assert activity(runtime, receipt["run_id"])["session"] is None
    original, _ = captured(runtime, receipt, native="original")
    assert activity(runtime, receipt["run_id"])["session"]["id"] == original


def test_subagent_own_command_links_to_child_not_hook_parent(runtime, tmp_path):
    grant, receipt = command(runtime, tmp_path)
    _, parent = captured(runtime, {"run_id": "c" * 32}, native="parent")
    child, _ = captured(runtime, receipt, native="child", context={
        "parent_session_id": parent["session_id"],
    })
    record_session(runtime.store, receipt["run_id"], grant["id"], "codex", "parent")
    assert activity(runtime, receipt["run_id"])["session"]["id"] == child


def test_independent_duplicate_receipts_stay_ambiguous_not_newest_wins(runtime, tmp_path):
    _, receipt = command(runtime, tmp_path)
    captured(runtime, receipt, native="one")
    captured(runtime, receipt, native="two")
    row = activity(runtime, receipt["run_id"])
    assert row["session"] is None and row["session_status"] == "ambiguous"


def test_superseded_and_purged_transcripts_do_not_leave_broken_links(runtime, tmp_path):
    _, receipt = command(runtime, tmp_path)
    _, payload = captured(runtime, receipt)
    original = copy.deepcopy(payload)
    payload["chat_history"][1]["tools"] = []
    runtime.store.ingest(payload)
    assert activity(runtime, receipt["run_id"])["session"] is None
    # Make a new current revision; replaying a historical digest doesn't select it.
    original["chat_history"][0]["content"] += " again"
    runtime.store.ingest(original)
    assert activity(runtime, receipt["run_id"])["session"]
    runtime.store.purge_history()
    assert activity(runtime, receipt["run_id"])["session"] is None
    assert runtime.store.one("SELECT id FROM environment_runs WHERE id=?", (receipt["run_id"],))


def test_hook_endpoint_does_not_expand_authority_or_accept_command_text(client, owner, runtime, tmp_path):
    grant, receipt = command(runtime, tmp_path)
    other = runtime.create_grant("Other", kind="agent", confirm_agent=True)
    body = {"run_id": receipt["run_id"], "grant_id": grant["id"], "harness": "codex", "session_id": "one"}
    agent = {"Authorization": "Bearer " + grant_token(runtime, grant)}
    for headers in ({}, owner, agent):
        assert client.post("/api/hooks/credential-use", headers=headers, json=body).status_code == 401
    hooks = {"Authorization": "Bearer " + runtime.hook_token}
    assert client.get("/api/environment-credentials", headers=hooks).status_code == 401
    assert client.get("/api/environment-credentials", headers=agent).status_code == 401
    assert client.post(
        "/api/hooks/credential-use", headers=hooks, json={**body, "grant_id": other["id"]},
    ).json() == {"recorded": False}
    assert client.post(
        "/api/hooks/credential-use", headers=hooks, json={**body, "command": "synthetic-private-command"},
    ).status_code == 422
    assert not runtime.store.rows("SELECT * FROM environment_run_context")


def test_conflicting_hook_reports_are_not_silently_overwritten(runtime, tmp_path):
    grant, receipt = command(runtime, tmp_path)
    captured(runtime, receipt, native="first")
    for native in ("first", "first", "second"):
        record_session(runtime.store, receipt["run_id"], grant["id"], "codex", native)
    row = activity(runtime, receipt["run_id"])
    assert row["session_status"] == "ambiguous" and row["session"] is None
    assert row["session_id"] == "codex_first"


def test_legacy_index_backfill_preserves_original_snapshots(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    store = Store(state)
    payload = sample_session(session_id="codex_native", source="codex")
    payload["chat_history"][1]["tools"] = [{
        "tool_name": "mcp__adr__adr_run_command", "result": canonical({"run_id": RUN, "exit_code": 0}),
    }]
    store.ingest(payload)
    snapshots = store.rows("SELECT * FROM snapshots")
    store.execute("DELETE FROM credential_session_receipts")
    store.execute("UPDATE session_retrieval SET index_version=1")
    store.close()
    migrated = Store(state)
    try:
        assert migrated.rows("SELECT * FROM snapshots") == snapshots
        assert migrated.one("SELECT run_id FROM credential_session_receipts")["run_id"] == RUN
        assert len(migrated.rows("PRAGMA table_info(environment_runs)")) == 5
        assert migrated.one("PRAGMA user_version")["user_version"] == 3
    finally:
        migrated.close()


@pytest.mark.parametrize("trusted", [True, False])
def test_post_hook_reports_only_identifiers_from_verified_mcp_result(
    runtime, tmp_path, client, monkeypatch, capsys, trusted,
):
    grant, receipt = command(runtime, tmp_path)
    event = {
        "tool_name": "mcp__adr__adr_run_command",
        "tool_input": {"command": "synthetic-private-command"},
        "tool_response": {"structuredContent": receipt},
        "cwd": str(tmp_path), "session_id": "native-one",
    }
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(canonical(event).encode())))
    monkeypatch.setattr(
        "adr_desktop.hooks.trusted_grant_id", lambda *_args: grant["id"] if trusted else False,
    )
    sent = []

    def send(_state, method, path, *, token, payload, **_kwargs):
        sent.append((path, payload))
        return client.request(
            method, path, headers={"Authorization": "Bearer " + token}, json=payload,
        ).json()

    monkeypatch.setattr("adr_desktop.hooks.request", send)
    assert run_hook(runtime.state_dir, "codex", phase="post") == 0
    assert json.loads(capsys.readouterr().out) == {}
    reports = [body for path, body in sent if path == "/api/hooks/credential-use"]
    assert reports == ([{
        "run_id": receipt["run_id"], "grant_id": grant["id"],
        "harness": "codex", "session_id": "native-one",
    }] if trusted else [])
    assert "synthetic-private-command" not in canonical(runtime.store.rows("SELECT * FROM hook_events"))
    contexts = runtime.store.rows("SELECT * FROM environment_run_context")
    assert "synthetic-private-command" not in canonical(contexts)


def test_failed_execution_keeps_run_receipt_without_changing_http_failure(client, runtime, tmp_path):
    grant, _ = command(runtime, tmp_path)
    runtime.change_policy(add={"path": str(tmp_path / "private"), "action": "block", "kind": "file"})
    response = client.post(
        "/api/agent/environment/run", headers={"Authorization": "Bearer " + grant_token(runtime, grant)},
        json={"command": "cat private", "cwd": str(tmp_path)},
    )
    assert response.status_code == 403
    run_id = response.json()["run_id"]
    assert runtime.store.one("SELECT state FROM environment_runs WHERE id=?", (run_id,))["state"] == "failed"
    captured(runtime, {"run_id": run_id, "error": "ADR rejected the request (HTTP 403)"})
    assert activity(runtime, run_id)["session"]


def test_mcp_error_receipt_remains_an_error_and_has_no_secret(runtime, monkeypatch, capsys):
    grant = runtime.create_grant("Agent", kind="agent", confirm_agent=True)
    access_file = runtime.state_dir / "agents" / f"{grant['id']}.json"
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "adr_run_command", "arguments": {"command": "pwd", "cwd": "/synthetic"}}},
    ]
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(
        "".join(canonical(message) + "\n" for message in messages).encode()
    )))

    def fail(*_args, **_kwargs):
        raise LocalUnavailable("ADR rejected the request (HTTP 403)", run_id=RUN)

    monkeypatch.setattr("adr_desktop.mcp_server.request", fail)
    serve(access_file)
    reply = json.loads(capsys.readouterr().out.splitlines()[-1])["result"]
    assert reply["isError"] is True
    assert reply["structuredContent"]["run_id"] == RUN
    assert result_run_ids(reply) == {RUN}
