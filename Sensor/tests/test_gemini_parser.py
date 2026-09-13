"""Synthetic fixtures matching Google's persisted ConversationRecord contract."""

import json
import os
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

import pytest

from adr_sensor.observer import AgentObserver
from adr_sensor.parsers.gemini_parser import GeminiParser


def records(session_id="main-session"):
    return [
        {"sessionId": session_id, "projectHash": "hash", "startTime": "2026-01-01T00:00:00Z", "kind": "main"},
        {"id": "user1", "type": "user", "timestamp": "2026-01-01T00:00:01Z", "content": "Inspect this project"},
        {
            "id": "assistant1",
            "type": "gemini",
            "timestamp": "2026-01-01T00:00:02Z",
            "content": [{"text": "Reading"}],
            "model": "gemini-test",
            "thoughts": [{"subject": "Plan", "description": "Inspect files"}],
            "tokens": {"input": 10, "output": 2, "cached": 3, "total": 12},
            "toolCalls": [
                {
                    "id": "call1",
                    "name": "mcp_test_server__read",
                    "args": {"path": "config.json"},
                    "timestamp": "2026-01-01T00:00:02Z",
                    "status": "awaiting_approval",
                }
            ],
        },
    ]


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(row) for row in data) + "\n", encoding="utf-8")
    return path


@pytest.mark.parametrize("host", ["Darwin", "Linux", "Windows"])
@pytest.mark.parametrize("override", [False, True])
def test_home_resolution(tmp_path, monkeypatch, host, override):
    monkeypatch.setattr("adr_sensor.parsers.gemini_parser.platform.system", lambda: host)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("GEMINI_CLI_HOME", str(tmp_path / "custom") if override else "")
    home = tmp_path / "custom" if override else tmp_path
    parser = GeminiParser()
    assert parser.base_paths[0] == home / ".gemini/tmp"
    assert len(parser.base_paths) == (2 if host == "Darwin" else 1)
    if host == "Darwin":
        assert parser.base_paths[1] == home / ".cache/.gemini/tmp"


def test_journal_updates_keep_results_permissions_and_metadata(tmp_path):
    rows = records()
    finished = deepcopy(rows[-1])
    finished["toolCalls"][0].update(
        status="success",
        result=[
            {"functionResponse": {"id": "call1", "name": "read", "response": {"output": "secret-value-" + "x" * 4000}}}
        ],
    )
    rows.extend([finished, {"$set": {"lastUpdated": "2026-01-01T00:00:03Z"}}])
    path = write(tmp_path / "project/chats/session-test.jsonl", rows)
    (tmp_path / "project/.project_root").write_text("C:\\work\\project", encoding="utf-8")
    before = path.read_bytes(), path.stat().st_mtime_ns
    event = GeminiParser(base_path=tmp_path).parse_all()[0]
    assert len(event.chat_history) == 2
    assert event.project_path == "C:\\work\\project"
    tool = event.chat_history[-1].tools[0]
    assert tool.server_name == "test_server"
    assert tool.status == "success"
    assert "secret-value-" + "x" * 4000 in tool.result
    assert tool.arguments == {"path": "config.json"}
    assert event.model == "gemini-test"
    assert event.token_usage["cumulative"]["input_tokens"] == 10  # Upserts must not double count.
    assert event.session_context["permission_requests"][0]["tool_call"]["id"] == "call1"
    assert event.session_context["message_metadata"]["assistant1"]["thoughts"][0]["subject"] == "Plan"
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before


def test_legacy_snapshot_and_jsonl_migration_deduplicate(tmp_path):
    rows = records()
    legacy = dict(rows[0], messages=rows[1:])
    path = tmp_path / "project/chats/session-old.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(legacy, indent=2), encoding="utf-8")
    parser = GeminiParser(base_path=tmp_path)
    assert len(parser.parse_all()[0].chat_history) == 2
    journal = write(path.with_suffix(".jsonl"), rows)
    events = parser.parse_all()
    assert len(events) == 1
    assert events[0].raw_log_path == str(journal)


def test_rewind_checkpoint_subagent_and_non_chat_files(tmp_path):
    rows = records()
    rows += [
        {"$rewindTo": "assistant1"},
        {"$set": {"messages": [rows[1]]}},
        {"id": "user2", "type": "user", "content": "Try another approach"},
    ]
    write(tmp_path / "project/chats/session-main.jsonl", rows)
    child = records("child-session")
    child[0]["kind"] = "subagent"
    write(tmp_path / "project/chats/main-session/child-session.jsonl", child)
    write(tmp_path / "project/logs/unrelated.jsonl", records("ignore"))
    events = {event.session_id: event for event in GeminiParser(base_path=tmp_path).parse_all()}
    assert set(events) == {"gemini_main-session", "gemini_child-session"}
    assert len(events["gemini_main-session"].chat_history) == 3
    assert events["gemini_main-session"].chat_history[1].tools  # Abandoned actions survive.
    assert events["gemini_child-session"].session_context["parent_session_id"] == "main-session"


def test_missing_malformed_and_age_filtering(tmp_path):
    parser = GeminiParser(base_path=tmp_path)
    assert parser.parse_all() == []
    path = write(tmp_path / "project/chats/session-old.jsonl", records())
    with path.open("a", encoding="utf-8") as handle:
        handle.write('[]\n{"$set": null}\n{"unfinished":')
    event = parser.parse_all()[0]
    assert event.session_context["malformed_records"] == 3
    os.utime(path, (1, 1))
    assert parser.parse_all() == []
    assert len(GeminiParser(max_age_days=0, base_path=tmp_path).parse_all()) == 1
    path.write_text("{}", encoding="utf-8")
    assert parser.parse_all() == []


def test_resumed_export_updates_same_file_and_skips_unchanged(tmp_path):
    path = write(tmp_path / "input/project/chats/session.jsonl", records())
    parser = GeminiParser(base_path=tmp_path / "input")
    observer = AgentObserver(output_dir=tmp_path / "output", max_age_days=0)
    observer.gemini_parser = parser
    event = observer.ingest_all("gemini")[0][0]
    assert observer.gemini_parser.max_age_days == 14
    output = observer.save_sessions_to_individual_files([event], tmp_path / "output")[0]
    assert observer.filter_entries_by_existing_files([event], tmp_path / "output") == []
    resumed = {"id": "user2", "type": "user", "timestamp": "2026-01-02T00:00:00Z", "content": "Continue work"}
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(resumed) + "\n")
    updated = parser.parse_all()[0]
    assert updated.timestamp == datetime(2026, 1, 1, tzinfo=timezone.utc)
    selected = observer.filter_entries_by_existing_files([updated], tmp_path / "output")
    assert len(selected) == 1
    assert observer.save_sessions_to_individual_files(selected, tmp_path / "output") == [output]
    assert len(json.loads(output.read_text(encoding="utf-8"))["chat_history"]) == 3


def test_status_and_structured_content_are_preserved(tmp_path):
    rows = records()
    rows[1]["content"] = [{"text": "Inspect image"}, {"inlineData": {"mimeType": "image/png", "data": "abc"}}]
    rows[-1]["toolCalls"] = [
        {
            "id": "fail",
            "name": "run_shell_command",
            "args": {"command": "false"},
            "status": "error",
            "result": [{"functionResponse": {"response": {"error": "denied"}}}],
        },
        {"id": "cancel", "name": "read_file", "args": {}, "status": "cancelled"},
        {"id": "pending", "name": "custom", "args": {}, "status": "executing"},
    ]
    event = GeminiParser().parse_file(write(tmp_path / "session.jsonl", rows))
    tools = event.chat_history[-1].tools
    assert tools[0].status == "error" and "denied" in tools[0].error
    assert tools[1].status == "cancelled" and tools[1].result is None
    assert tools[2].status == "executing" and tools[2].result is None
    assert event.session_context["message_metadata"]["user1"]["content_parts"][1]["inlineData"]["data"] == "abc"


def test_project_registry_and_corrupt_optional_metadata(tmp_path):
    path = write(tmp_path / "tmp/project/chats/session.jsonl", records())
    registry = tmp_path / "projects.json"
    registry.write_text(json.dumps({"projects": {"/work/repo": "project"}}), encoding="utf-8")
    parser = GeminiParser(base_path=tmp_path / "tmp")
    assert parser.parse_all()[0].project_path == "/work/repo"
    registry.write_text("{", encoding="utf-8")
    assert parser.parse_all()[0].project_path is None
    assert path.exists()
