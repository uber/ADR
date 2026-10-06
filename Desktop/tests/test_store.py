import copy

import pytest
from conftest import sample_session

from adr_desktop.store import Store


def test_capture_defaults_to_five_minutes(runtime):
    assert runtime.store.settings()["interval_seconds"] == 300
    assert runtime.store.settings()["recording"] is False


@pytest.mark.parametrize("seconds", [15, 30, 60, 120, 300, 900, 1800, 3600])
def test_saved_capture_intervals_migrate_without_resetting_other_settings(runtime, seconds):
    runtime.store.setting("interval_seconds", seconds)
    runtime.store.setting("recording", True)
    runtime.store.setting("history_days", 7)
    runtime.store.ingest(sample_session())
    reopened = Store(runtime.state_dir)
    try:
        assert reopened.settings()["interval_seconds"] == max(300, seconds)
        assert reopened.settings()["recording"] is True
        assert reopened.settings()["history_days"] == 7
        assert reopened.sessions()["total"] == 1
    finally:
        reopened.close()


def test_session_snapshots_are_deduplicated(runtime):
    payload = sample_session()
    assert runtime.store.ingest(payload)
    assert not runtime.store.ingest(payload)
    result = runtime.store.sessions()
    assert result["total"] == 1
    assert result["items"][0]["message_count"] == 2
    assert result["items"][0]["tool_count"] == 1
    assert runtime.store.session(result["items"][0]["id"])["revisions"] == 1


def test_changed_tool_result_with_same_uuid_is_not_lost(runtime):
    original = sample_session()
    changed = copy.deepcopy(original)
    changed["chat_history"][1]["tools"][0]["result"] = "updated full tool result"
    runtime.store.ingest(original)
    runtime.store.ingest(changed)
    record = runtime.store.session(runtime.store.sessions()["items"][0]["id"])
    assert record["revisions"] == 2
    assert record["payload"] == changed
    assert runtime.store.overview()["totals"]["tools"] == 1


def test_no_additional_redaction_or_content_clipping(runtime):
    content = "Synthetic token=test_fixture_value\n" + "full content " * 5000
    payload = sample_session(content=content)
    runtime.store.ingest(payload)
    record = runtime.store.session(runtime.store.sessions()["items"][0]["id"])
    assert record["payload"]["chat_history"][0]["content"] == content
    assert len(record["title"]) <= 120


def test_older_snapshot_does_not_replace_recent_session(runtime):
    recent = sample_session(content="new")
    runtime.store.ingest(recent)
    older = sample_session(content="old")
    older["timestamp"] = "2026-09-29T10:00:00Z"
    runtime.store.ingest(older)
    record = runtime.store.session(runtime.store.sessions()["items"][0]["id"])
    assert record["payload"]["chat_history"][0]["content"] == "new"
    assert record["revisions"] == 2


def test_project_scope_is_exact_not_a_prefix(runtime):
    runtime.store.ingest(sample_session(project="/work/a"))
    runtime.store.ingest(sample_session(project="/work/attacker", session_id="two"))
    allowed = runtime.store.sessions(project="/work/a")
    assert allowed["total"] == 1
    other = runtime.store.sessions(project="/work/attacker")["items"][0]
    assert runtime.store.session(other["id"], project="/work/a") is None


def test_purge_history_keeps_policies_and_access_grants(runtime):
    runtime.store.ingest(sample_session())
    runtime.change_policy(add={"path": "/private/example", "kind": "directory", "action": "block"})
    runtime.create_grant("Test", "/workspace/sample", [])
    runtime.store.purge_history()
    assert runtime.store.sessions()["total"] == 0
    assert len(runtime.policy["rules"]) == 1
    assert len(runtime.store.rows("SELECT * FROM grants")) == 1


@pytest.mark.parametrize(
    "payload", [{}, {"source": "x"}, {"source": "x", "session_id": "y", "chat_history": "bad"}]
)
def test_invalid_sessions_do_not_become_empty_successes(runtime, payload):
    with pytest.raises(ValueError):
        runtime.store.ingest(payload)
    assert runtime.store.sessions()["total"] == 0
