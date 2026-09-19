"""Regression tests for public Claude Code transcript formats using synthetic data."""

import json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from adr_sensor.parsers.claude_parser import ClaudeParser


def _record(
    role: str,
    content: Any,
    *,
    session_id: str = "session-1",
    timestamp: str = "2026-09-01T10:00:00Z",
    **fields: Any,
) -> dict:
    return {
        "type": role,
        "sessionId": session_id,
        "timestamp": timestamp,
        "cwd": "/synthetic/project",
        "message": {"content": content},
        **fields,
    }


def _write_records(path: Path, records: list) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(record) for record in records) + "\n", encoding="utf-8")
    return path


def _contents(entries: list) -> list:
    return [message.content for entry in entries for message in entry.chat_history]


@pytest.mark.parametrize("malformed", [None, True, 42, "not an object", []])
def test_nonobject_records_do_not_discard_surrounding_messages(tmp_path, malformed):
    path = _write_records(
        tmp_path / "session.jsonl",
        [_record("user", "Before malformed record"), malformed, _record("assistant", "After malformed record")],
    )

    entries = ClaudeParser().parse_jsonl_file(path)

    assert len(entries) == 1
    assert _contents(entries) == ["Before malformed record", "After malformed record"]


@pytest.mark.parametrize("role", ["user", "assistant"])
@pytest.mark.parametrize("message", [None, [], "not an object", 42])
def test_malformed_message_objects_do_not_discard_surrounding_messages(tmp_path, role, message):
    path = _write_records(
        tmp_path / "session.jsonl",
        [
            _record("user", "Before malformed message"),
            _record(role, "unused", message=message),
            _record("assistant", "After malformed message"),
        ],
    )

    entries = ClaudeParser().parse_jsonl_file(path)

    assert len(entries) == 1
    assert _contents(entries) == ["Before malformed message", "After malformed message"]


@pytest.mark.parametrize("session_id", [None, "", [], {}, 42, True])
def test_invalid_session_identifiers_are_isolated(tmp_path, session_id):
    path = _write_records(
        tmp_path / "session.jsonl",
        [
            _record("user", "Before invalid identifier"),
            _record("user", "Invalid session must be ignored", session_id=session_id),
            _record("assistant", "After invalid identifier"),
        ],
    )

    entries = ClaudeParser().parse_jsonl_file(path)

    assert [entry.session_id for entry in entries] == ["claude_session-1"]
    assert _contents(entries) == ["Before invalid identifier", "After invalid identifier"]


@pytest.mark.parametrize("role", ["user", "assistant"])
@pytest.mark.parametrize(
    "content",
    [
        "First paragraph.\nSecond paragraph.",
        [{"type": "text", "text": "First paragraph.\n"}, {"type": "text", "text": "Second paragraph."}],
    ],
    ids=["string", "text-blocks"],
)
def test_preserves_string_and_text_block_messages(tmp_path, role, content):
    path = _write_records(tmp_path / "session.jsonl", [_record(role, content, uuid="message-uuid")])

    entries = ClaudeParser().parse_jsonl_file(path)

    assert len(entries) == 1
    assert len(entries[0].chat_history) == 1
    message = entries[0].chat_history[0]
    assert message.role == role
    assert message.content == "First paragraph.\nSecond paragraph."
    assert message.sequence_id == "message-uuid"


@pytest.mark.parametrize("role", ["user", "assistant"])
def test_malformed_content_blocks_do_not_hide_valid_text(tmp_path, role):
    content = [
        None,
        42,
        "not a block",
        {"type": "text", "text": None},
        {"type": "text", "text": ["not text"]},
        {"type": "text", "text": "Visible text survives."},
        {"type": "image", "source": {"type": "base64", "data": "synthetic"}},
    ]
    path = _write_records(tmp_path / "session.jsonl", [_record(role, content)])

    entries = ClaudeParser().parse_jsonl_file(path)

    assert _contents(entries) == ["Visible text survives."]


def test_user_text_is_preserved_alongside_tool_results(tmp_path):
    path = _write_records(
        tmp_path / "session.jsonl",
        [
            _record(
                "assistant",
                [{"type": "tool_use", "id": "read-1", "name": "Read", "input": {"file_path": "file.txt"}}],
            ),
            _record(
                "user",
                [
                    {"type": "text", "text": "The file is ready. "},
                    {
                        "type": "tool_result",
                        "tool_use_id": "read-1",
                        "content": [{"type": "text", "text": "first line"}, {"type": "text", "text": "second line"}],
                    },
                    {"type": "text", "text": "Please continue."},
                ],
                uuid="user-with-result",
            ),
        ],
    )

    entries = ClaudeParser().parse_jsonl_file(path)

    assert len(entries) == 1
    assistant, user = entries[0].chat_history
    assert assistant.tools[0].result == "first line\nsecond line"
    assert user.role == "user"
    assert user.content == "The file is ready. Please continue."
    assert user.sequence_id == "user-with-result"


@pytest.mark.parametrize("same_message", [True, False], ids=["same-assistant-message", "separate-assistant-messages"])
def test_identical_tool_calls_keep_results_with_their_exact_call(tmp_path, same_message):
    calls = [
        {"type": "tool_use", "id": tool_id, "name": "Read", "input": {"file_path": "same.txt"}}
        for tool_id in ("first-call", "second-call")
    ]
    records = [_record("assistant", calls)] if same_message else [_record("assistant", [call]) for call in calls]
    records.append(
        _record(
            "user",
            [
                {"type": "tool_result", "tool_use_id": "second-call", "content": "Second call output"},
                {"type": "tool_result", "tool_use_id": "first-call", "content": "First call output"},
            ],
        )
    )
    path = _write_records(tmp_path / "session.jsonl", records)

    entries = ClaudeParser().parse_jsonl_file(path)

    assert len(entries) == 1
    tools = [tool for message in entries[0].chat_history for tool in message.tools]
    assert [tool.result for tool in tools] == ["First call output", "Second call output"]
    assert [message.role for message in entries[0].chat_history] == ["assistant"] * (1 if same_message else 2)


def test_malformed_tool_result_blocks_do_not_discard_valid_results(tmp_path):
    path = _write_records(
        tmp_path / "session.jsonl",
        [
            _record("assistant", [{"type": "tool_use", "id": "read-1", "name": "Read", "input": {}}]),
            _record(
                "user",
                [
                    {"type": "tool_result", "tool_use_id": [], "content": "Malformed identifier"},
                    {
                        "type": "tool_result",
                        "tool_use_id": "read-1",
                        "content": [None, {"type": "text", "text": None}, {"type": "text", "text": "Valid result"}],
                    },
                    {"type": "text", "text": "Visible user follow-up"},
                ],
            ),
        ],
    )

    entries = ClaudeParser().parse_jsonl_file(path)

    assert len(entries) == 1
    assert entries[0].chat_history[0].tools[0].result == "Valid result"
    assert entries[0].chat_history[1].content == "Visible user follow-up"


def test_large_tool_arguments_and_results_remain_truncated(tmp_path):
    long_text = "start-" + "x" * 2000 + "-finish"
    path = _write_records(
        tmp_path / "session.jsonl",
        [
            _record(
                "assistant",
                [{"type": "tool_use", "id": "write-1", "name": "Write", "input": {"content": long_text}}],
            ),
            _record("user", [{"type": "tool_result", "tool_use_id": "write-1", "content": long_text}]),
        ],
    )

    entries = ClaudeParser().parse_jsonl_file(path)

    tool = entries[0].chat_history[0].tools[0]
    for text in (tool.arguments["content"], tool.result):
        assert len(text) < len(long_text)
        assert "[truncated" in text
        assert text.startswith("start-")
        assert text.endswith("-finish")


def test_parent_direct_child_and_nested_workflow_have_distinct_identities(tmp_path):
    paths = {
        "claude_parent": tmp_path / "project" / "parent.jsonl",
        "claude_parent_agent_direct": tmp_path / "project" / "parent" / "subagents" / "agent-direct.jsonl",
        "claude_parent_agent_nested": (
            tmp_path / "project" / "parent" / "subagents" / "workflows" / "run-1" / "agent-nested.jsonl"
        ),
    }
    _write_records(paths["claude_parent"], [_record("user", "Parent conversation", session_id="parent")])
    _write_records(
        paths["claude_parent_agent_direct"],
        [_record("assistant", "Direct child conversation", session_id="parent", agentId="direct", isSidechain=True)],
    )
    _write_records(
        paths["claude_parent_agent_nested"],
        [_record("assistant", "Nested workflow conversation", session_id="parent", isSidechain=True)],
    )
    parser = ClaudeParser()
    parser.base_path = tmp_path

    entries = parser.parse_all()

    assert {entry.session_id for entry in entries} == set(paths)
    assert len({entry.uuid for entry in entries}) == 3
    for entry in entries:
        assert entry.raw_log_path == str(paths[entry.session_id])
        if entry.session_id != "claude_parent":
            assert entry.session_context["parent_session_id"] == "claude_parent"
            assert entry.session_context["agent_id"] == entry.session_id.rsplit("_", 1)[-1]


def test_session_metadata_uses_earliest_and_latest_valid_timestamps(tmp_path):
    path = _write_records(
        tmp_path / "session.jsonl",
        [
            _record("assistant", "First physical record", timestamp="2026-09-01T10:05:00Z"),
            _record("user", "Earlier session start", timestamp="2026-09-01T10:00:00Z"),
            {
                "type": "system",
                "sessionId": "session-1",
                "timestamp": "2026-09-01T10:10:00Z",
                "subtype": "turn_duration",
            },
            _record("assistant", "Bad timestamp is isolated", timestamp="not-a-timestamp"),
        ],
    )

    entries = ClaudeParser().parse_jsonl_file(path)

    assert len(entries) == 1
    entry = entries[0]
    assert entry.timestamp == datetime(2026, 9, 1, 10, tzinfo=timezone.utc)
    assert entry.session_context["last_event_at"] == "2026-09-01T10:10:00+00:00"
    assert entry.session_context["event_count"] == 4
    assert entry.raw_log_path == str(path)
    assert entry.project_path == "/synthetic/project"


def test_growing_session_keeps_start_and_updates_latest_event_metadata(tmp_path):
    path = tmp_path / "session.jsonl"
    records = [_record("user", "Initial user message")]
    _write_records(path, records)
    parser = ClaudeParser()
    first = parser.parse_jsonl_file(path)[0]
    records.append(_record("assistant", "Later assistant response", timestamp="2026-09-01T10:20:00Z"))
    _write_records(path, records)

    grown = parser.parse_jsonl_file(path)[0]

    assert grown.timestamp == first.timestamp
    assert grown.session_id == first.session_id
    assert first.session_context["last_event_at"] == "2026-09-01T10:00:00+00:00"
    assert grown.session_context["last_event_at"] == "2026-09-01T10:20:00+00:00"
    assert first.session_context["event_count"] == 1
    assert grown.session_context["event_count"] == 2
    assert _contents([grown]) == ["Initial user message", "Later assistant response"]


def test_event_identity_is_built_from_completed_chat_history(tmp_path):
    path = _write_records(
        tmp_path / "session.jsonl",
        [
            _record("user", "Inspect the project"),
            _record("assistant", [{"type": "tool_use", "id": "call", "name": "Read", "input": {}}]),
            _record("user", [{"type": "tool_result", "tool_use_id": "call", "content": "Tool output"}]),
        ],
    )
    entry = ClaudeParser().parse_jsonl_file(path)[0]

    assert entry.uuid == replace(entry).uuid
    assert entry.uuid != replace(entry, chat_history=[]).uuid


@pytest.mark.parametrize("separator", ["", "   ", "\x00", "\x00  \x00"])
def test_decodes_concatenated_objects_and_nul_padding_on_one_physical_line(tmp_path, separator):
    path = tmp_path / "session.jsonl"
    records = [
        _record("user", 'A message with braces { } and an escaped quote: "hello"'),
        _record("assistant", "Second concatenated message"),
    ]
    path.write_text("\x00 " + separator.join(json.dumps(record) for record in records) + " \x00\n", encoding="utf-8")

    entries = ClaudeParser().parse_jsonl_file(path)

    assert _contents(entries) == [record["message"]["content"] for record in records]
    assert entries[0].session_context["event_count"] == 2


def test_complete_prefix_survives_incomplete_suffix_and_next_line_is_independent(tmp_path):
    path = tmp_path / "session.jsonl"
    path.write_text(
        json.dumps(_record("user", "Complete prefix survives"))
        + '{"type":"assistant","sessionId":"session-1","message":\n'
        + json.dumps(_record("assistant", "Next physical line survives"))
        + "\n",
        encoding="utf-8",
    )

    entries = ClaudeParser().parse_jsonl_file(path)

    assert _contents(entries) == ["Complete prefix survives", "Next physical line survives"]
    assert entries[0].session_context["event_count"] == 2


def test_incomplete_records_are_never_joined_across_physical_lines(tmp_path):
    path = tmp_path / "session.jsonl"
    split_record = json.dumps(_record("user", "This split record must not become a message"))
    path.write_text(
        split_record.replace('"content": ', '"content": \n', 1)
        + "\n"
        + json.dumps(_record("assistant", "Independent complete message"))
        + "\n",
        encoding="utf-8",
    )

    entries = ClaudeParser().parse_jsonl_file(path)

    assert _contents(entries) == ["Independent complete message"]
    assert entries[0].session_context["event_count"] == 1
