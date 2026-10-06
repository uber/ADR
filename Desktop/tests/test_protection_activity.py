import io
import json
import sqlite3
import sys

import pytest

from adr_desktop.config import canonical, prepare_state_dir
from adr_desktop.hooks import run_hook
from adr_desktop.policy import Decision
from adr_desktop.store import SCHEMA, Store


def post_event(client, runtime, **changes):
    body = {
        "harness": "codex", "decision": "pass", "tool": "Read",
        "reason": "No protected path matched", "paths": [],
    }
    body.update(changes)
    return client.post(
        "/api/hooks/events", headers={"Authorization": "Bearer " + runtime.hook_token}, json=body,
    )


def test_interventions_are_filtered_before_limit_and_routine_events_are_retained(client, runtime, owner):
    assert post_event(client, runtime, decision="deny", reason="Protected synthetic file").status_code == 200
    for _ in range(125):
        assert post_event(client, runtime).status_code == 200
    result = client.get("/api/protection/events?interventions_only=true&limit=20", headers=owner)
    assert result.status_code == 200
    assert [row["decision"] for row in result.json()["items"]] == ["deny"]
    assert len(client.get("/api/protection/events", headers=owner).json()["items"]) == 100
    assert runtime.store.one("SELECT count(*) AS n FROM hook_events")["n"] == 126
    assert runtime.status()["protection"]["latest_intervention_id"] == 1
    # Routine events still prove a hook is alive; filtering is a view, not deletion.
    codex = next(hook for hook in runtime.status()["hooks"] if hook["harness"] == "codex")
    assert codex["last_event"] is not None


def test_successful_approvals_stay_visible_but_normal_successes_do_not(client, runtime, owner):
    assert post_event(client, runtime, decision="ask", reason="Needs approval").status_code == 200
    assert post_event(
        client, runtime, decision="pass", reason="An approved operation", approval_requested=True,
    ).status_code == 200
    assert post_event(client, runtime, reason="Allowed once in ADR").status_code == 200
    assert post_event(client, runtime, reason="A filename containing the word approval").status_code == 200
    rows = client.get("/api/protection/events?interventions_only=true", headers=owner).json()["items"]
    assert len(rows) == 3
    assert all(row["approval_requested"] is True for row in rows)
    assert {row["decision"] for row in rows} == {"pass", "ask"}


def test_activity_filters_require_owner_and_validate_inputs(client, runtime, owner):
    assert client.get("/api/protection/events?interventions_only=true").status_code == 401
    assert client.get("/api/protection/events?limit=0", headers=owner).status_code == 422
    assert client.get("/api/protection/events?limit=101", headers=owner).status_code == 422
    assert post_event(client, runtime, approval_requested="yes").status_code == 422
    assert client.get("/api/protection/events?interventions_only=true", headers=owner).json() == {"items": []}


def test_approval_marker_is_audit_only_and_compatible_with_ordinary_events():
    assert "approval_requested" not in Decision().as_dict()
    assert Decision("ask").as_dict()["approval_requested"] is True
    assert Decision("pass", approval_requested=True).as_dict()["approval_requested"] is True
    assert Decision("pass", approval_requested=True).decision == "pass"


@pytest.mark.parametrize("code,was_asked", [("approved", True), ("no_match", False)])
def test_hook_audit_distinguishes_approval_from_a_policy_change(runtime, monkeypatch, capfd, code, was_asked):
    runtime.change_policy(add={"path": "/example/private", "action": "ask", "kind": "directory"})
    payload = {
        "tool_name": "Read", "tool_input": {"file_path": "/example/private/file"},
        "cwd": "/example", "session_id": "synthetic",
    }
    monkeypatch.setattr(
        sys, "stdin", io.TextIOWrapper(io.BytesIO(json.dumps(payload).encode()), encoding="utf-8"),
    )
    recorded = []

    def respond(_state, _method, path, **arguments):
        if path == "/api/hooks/approve":
            if code == "no_match":
                # The daemon's automatic pass means the Ask rule really was
                # removed while queued; the final hook now verifies that state.
                runtime.change_policy(delete=runtime.policy["rules"][0]["id"])
            return {"allowed": True, "reason_code": code}
        recorded.append(arguments["payload"])
        return {"recorded": True}

    monkeypatch.setattr("adr_desktop.hooks.request", respond)
    assert run_hook(runtime.state_dir, "codex", guard_protocol=True) == 0
    assert capfd.readouterr().out.splitlines() == ["waiting", "pass"]
    assert recorded[0].get("approval_requested", False) is was_asked
    assert (recorded[0]["reason"] == "Allowed once in ADR") is was_asked


def test_old_activity_is_preserved_and_only_exact_legacy_approvals_are_recognized(tmp_path):
    directory = prepare_state_dir(tmp_path / "old-profile")
    database = sqlite3.connect(directory / "desktop.sqlite3")
    database.executescript(SCHEMA)
    samples = [
        ("pass", "Allowed once in ADR"),
        ("ask", "A rule asks"),
        ("pass", "Unrelated approved-looking text"),
        ("deny", "Protected file"),
    ]
    for decision, reason in samples:
        database.execute(
            """INSERT INTO hook_events(timestamp,harness,session_id,tool,decision,reason,paths)
               VALUES (?,?,?,?,?,?,?)""",
            ("2026-10-01T12:00:00Z", "codex", "synthetic", "Read", decision, reason, canonical([])),
        )
    database.execute("PRAGMA user_version=3")
    database.commit()
    database.close()
    store = Store(directory)
    try:
        rows = store.rows("SELECT decision,reason,approval_requested FROM hook_events ORDER BY id")
        assert [(row["decision"], row["reason"]) for row in rows] == samples
        assert [row["approval_requested"] for row in rows] == [1, 1, 0, 0]
    finally:
        store.close()
