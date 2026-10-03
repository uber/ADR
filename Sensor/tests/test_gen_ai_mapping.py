"""gen_ai.conversation.id carries each harness's own session ID, taken from real parser output."""

import json
import sqlite3
from datetime import datetime, timezone

import pytest
from opentelemetry.sdk._logs.export import InMemoryLogRecordExporter, SimpleLogRecordProcessor

from adr_sensor import parsers
from adr_sensor.exporters.config import OpenTelemetryConfig
from adr_sensor.exporters.opentelemetry import _CONVERSATION_ID_BY_SOURCE, OpenTelemetryLogExporter
from adr_sensor.parsers import (
    AntigravityParser,
    ClaudeDesktopParser,
    ClaudeParser,
    ClineParser,
    CodexParser,
    CopilotParser,
    CursorParser,
    DshParser,
    GeminiParser,
    OpencodeParser,
    WarpParser,
)
from adr_sensor.schemas.agent_event_schema import AgentEvent
from tests.test_antigravity_parser import _write_transcript
from tests.test_claude_parser import _record, _write_records
from tests.test_dsh_parser import write_session
from tests.test_gemini_parser import records as gemini_records
from tests.test_gemini_parser import write as write_gemini
from tests.test_parsers import (
    NOW_MS,
    _build_opencode_db,
    _build_warp_db,
    _make_opencode_parser,
    _write_agent_mode_session,
)

PARSER_SOURCES = {
    AntigravityParser: "antigravity",
    ClaudeDesktopParser: "claude_desktop",
    ClaudeParser: "claude",
    ClineParser: "cline",
    CodexParser: "codex",
    CopilotParser: "copilot",
    CursorParser: "cursor",
    DshParser: "dsh",
    GeminiParser: "gemini",
    OpencodeParser: "opencode",
    WarpParser: "warp",
}


def _attributes(entry: AgentEvent) -> dict:
    memory_exporter = InMemoryLogRecordExporter()
    exporter = OpenTelemetryLogExporter(
        OpenTelemetryConfig(endpoint="http://localhost:4318/v1/logs", gen_ai_attributes=True),
        service_version="1.2.3",
        _log_record_exporter=memory_exporter,
        _processor_factory=SimpleLogRecordProcessor,
    )
    try:
        assert exporter.export([entry], []) == 1
        record = memory_exporter.get_finished_logs()[0].log_record
        assert record.body == entry.get_non_null_fields()
        assert record.attributes["adr.session.id"] == entry.session_id
        assert record.attributes["adr.source"] == entry.source
        assert record.attributes["gen_ai.agent.name"] == entry.source
        return dict(record.attributes)
    finally:
        exporter.shutdown()


def _only(entries: list) -> AgentEvent:
    assert len(entries) == 1
    return entries[0]


def test_every_parser_has_a_conversation_id_mapping():
    exported = {getattr(parsers, name) for name in parsers.__all__} - {parsers.BaseParser}

    assert set(PARSER_SOURCES) == exported
    assert set(PARSER_SOURCES.values()) == set(_CONVERSATION_ID_BY_SOURCE)


def test_claude_uses_transcript_session_id(tmp_path):
    path = _write_records(
        tmp_path / "session.jsonl", [_record("user", "Help me write a function", session_id="session1")]
    )
    entry = _only(ClaudeParser().parse_jsonl_file(path))

    assert entry.session_id == "claude_session1"
    assert _attributes(entry)["gen_ai.conversation.id"] == "session1"


def test_claude_subagents_use_parent_session_id(tmp_path):
    direct = tmp_path / "project" / "parent" / "subagents" / "agent-direct.jsonl"
    nested = tmp_path / "project" / "parent" / "subagents" / "workflows" / "run-1" / "agent-nested.jsonl"
    _write_records(tmp_path / "project" / "parent.jsonl", [_record("user", "parent", session_id="parent")])
    _write_records(direct, [_record("assistant", "direct", session_id="parent", agentId="direct", isSidechain=True)])
    _write_records(nested, [_record("assistant", "nested", session_id="parent", isSidechain=True)])
    parser = ClaudeParser()
    parser.base_path = tmp_path

    entries = parser.parse_all()

    assert {entry.session_id for entry in entries} == {
        "claude_parent",
        "claude_parent_agent_direct",
        "claude_parent_agent_nested",
    }
    assert {_attributes(entry)["gen_ai.conversation.id"] for entry in entries} == {"parent"}


def test_claude_desktop_uses_cli_session_id(tmp_path):
    _write_agent_mode_session(
        tmp_path / "user-1" / "org-1" / "agent",
        "local_ditto_aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        audit_lines=[{"type": "user", "uuid": "u1", "message": {"content": "run the nightly checks"}}],
        metadata={
            "sessionId": "local_ditto_aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "lastActivityAt": NOW_MS,
            "cliSessionId": "cli-99",
        },
    )
    entry = _only(ClaudeDesktopParser(base_path=str(tmp_path)).parse_all())

    assert entry.session_id == "claude_desktop_dispatch_aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    assert _attributes(entry)["gen_ai.conversation.id"] == "cli-99"


def test_claude_desktop_without_cli_session_id_omits_conversation_id(tmp_path):
    _write_agent_mode_session(
        tmp_path / "user-1" / "org-1",
        "local_11111111-2222-3333-4444-555555555555",
        audit_lines=[{"type": "user", "uuid": "u1", "message": {"content": "read the config"}}],
        metadata={"sessionId": "local_11111111-2222-3333-4444-555555555555", "lastActivityAt": NOW_MS},
    )
    entry = _only(ClaudeDesktopParser(base_path=str(tmp_path)).parse_all())

    attributes = _attributes(entry)
    assert "gen_ai.conversation.id" not in attributes
    assert attributes["adr.session.id"] == "claude_desktop_11111111-2222-3333-4444-555555555555"


def test_codex_uses_session_meta_id(tmp_path):
    path = tmp_path / "rollout-001.jsonl"
    events = [
        {"type": "session_meta", "payload": {"id": "sess1", "timestamp": "2025-06-15T10:00:00Z", "cwd": "/tmp"}},
        {
            "type": "response_item",
            "payload": {
                "type": "message",
                "role": "user",
                "content": [{"type": "input_text", "text": "List all Python files"}],
            },
        },
    ]
    path.write_text("".join(f"{json.dumps(event)}\n" for event in events), encoding="utf-8")
    entry = CodexParser().parse_jsonl_file(path)

    assert entry.session_id == "codex_sess1"
    assert _attributes(entry)["gen_ai.conversation.id"] == "sess1"


@pytest.mark.parametrize(("event_type", "directory"), [("session.start", "state-dir"), (None, "abc-session")])
def test_copilot_uses_event_session_id_or_session_directory(tmp_path, event_type, directory):
    session_dir = tmp_path / directory
    session_dir.mkdir()
    events = [
        {"type": "user.message", "timestamp": "2026-08-10T10:00:01.000Z", "data": {"content": "inspect the repo"}}
    ]
    if event_type:
        events.insert(
            0,
            {
                "type": event_type,
                "timestamp": "2026-08-10T10:00:00.000Z",
                "data": {"sessionId": "abc-session", "startTime": "2026-08-10T10:00:00.000Z"},
            },
        )
    (session_dir / "events.jsonl").write_text("\n".join(json.dumps(event) for event in events) + "\n")
    entry = CopilotParser().parse_session_dir(session_dir)

    assert entry.session_id == "copilot_abc-session"
    assert _attributes(entry)["gen_ai.conversation.id"] == "abc-session"


def test_cursor_uses_composer_id(tmp_path):
    db_path = tmp_path / "state.vscdb"
    connection = sqlite3.connect(db_path)
    connection.execute("CREATE TABLE cursorDiskKV (key TEXT, value TEXT)")
    connection.executemany(
        "INSERT INTO cursorDiskKV VALUES (?, ?)",
        [
            ("composerData:composer-1", json.dumps({"lastUpdatedAt": NOW_MS})),
            ("bubbleId:composer-1:bubble-1", json.dumps({"type": 1, "text": "Explain this function"})),
        ],
    )
    connection.commit()
    connection.close()
    parser = CursorParser()
    parser.db_path = db_path
    entry = _only(parser.parse_conversations_from_bubbles())

    assert entry.session_id == "cursor_composer-1"
    assert _attributes(entry)["gen_ai.conversation.id"] == "composer-1"


def test_cline_uses_task_id(tmp_path):
    task_dir = tmp_path / "1234567890"
    task_dir.mkdir()
    (task_dir / "api_conversation_history.json").write_text(
        json.dumps([{"role": "user", "content": [{"type": "text", "text": "Create a hello world script"}]}])
    )
    entry = ClineParser().parse_cline_log(task_dir)

    assert entry.session_id == "cline_1234567890"
    assert _attributes(entry)["gen_ai.conversation.id"] == "1234567890"


def test_dsh_uses_session_header_id(tmp_path):
    path = write_session(
        tmp_path,
        [
            {"type": "session", "version": 3, "id": "header-id", "createdAt": 1750000000000, "cwd": "/work"},
            {
                "type": "user/message",
                "seq": 1,
                "time": 1750000001000,
                "data": {"id": "u1", "role": "user", "content": [{"type": "text", "text": "inspect"}]},
            },
        ],
    )
    entry = DshParser(base_path=tmp_path).parse_session_file(path)

    assert entry.session_id == "dsh_header-id"
    assert _attributes(entry)["gen_ai.conversation.id"] == "header-id"


def test_gemini_main_and_subagent_use_their_own_session_ids(tmp_path):
    write_gemini(tmp_path / "project/chats/session-main.jsonl", gemini_records())
    child = gemini_records("child-session")
    child[0]["kind"] = "subagent"
    write_gemini(tmp_path / "project/chats/main-session/child-session.jsonl", child)
    events = {event.session_id: event for event in GeminiParser(base_path=tmp_path).parse_all()}

    assert set(events) == {"gemini_main-session", "gemini_child-session"}
    assert _attributes(events["gemini_main-session"])["gen_ai.conversation.id"] == "main-session"
    assert _attributes(events["gemini_child-session"])["gen_ai.conversation.id"] == "child-session"


def test_opencode_restores_ses_prefix(tmp_path):
    _build_opencode_db(
        tmp_path / "opencode.db",
        sessions=[{"id": "ses_abc123", "directory": "/home/dev/project"}],
        messages=[{"id": "msg_1", "session_id": "ses_abc123", "data": {"role": "user"}}],
        parts=[
            {
                "id": "prt_1",
                "message_id": "msg_1",
                "session_id": "ses_abc123",
                "data": {"type": "text", "text": "list the files"},
            }
        ],
    )
    entry = _only(_make_opencode_parser(tmp_path).parse_all())

    assert entry.session_id == "opencode_abc123"
    assert _attributes(entry)["gen_ai.conversation.id"] == "ses_abc123"


def test_warp_uses_conversation_id(tmp_path):
    now = datetime.now(timezone.utc).isoformat()
    exchange = (
        "exchange-1",
        now,
        json.dumps([{"Query": {"text": "hello from exchange-1"}}]),
        json.dumps({"Received": {"output": [{"Text": {"text": "reply"}}]}}),
    )
    _build_warp_db(
        tmp_path / "warp.sqlite",
        [{"conversation_id": "conv-1", "last_modified_at": now, "exchanges": [exchange]}],
    )
    parser = WarpParser()
    parser.base_path = tmp_path
    parser.db_path = tmp_path / "warp.sqlite"
    entry = _only(parser.parse_all())

    assert entry.session_id == "warp_conv-1"
    assert _attributes(entry)["gen_ai.conversation.id"] == "conv-1"


def test_antigravity_uses_conversation_id(tmp_path):
    path = _write_transcript(
        tmp_path / "conv-uuid-123", [{"type": "USER_INPUT", "content": "Add unit tests for the auth service"}]
    )
    entry = AntigravityParser(base_path=tmp_path).parse_transcript_file(path)

    assert entry.session_id == "antigravity_conv-uuid-123"
    assert _attributes(entry)["gen_ai.conversation.id"] == "conv-uuid-123"


@pytest.mark.parametrize(
    ("source", "session_id", "session_context"),
    [
        ("unknown", "unknown_session-1", None),
        ("codex", "session-1", None),
        ("codex", "codex_", None),
        ("claude", "claude_session-1_agent_a1", {"agent_id": "a1"}),
    ],
    ids=["unknown-source", "wrong-prefix", "empty-native-id", "subagent-without-parent"],
)
def test_unavailable_conversation_id_is_omitted(source, session_id, session_context):
    entry = AgentEvent(
        timestamp=datetime(2026, 9, 9, tzinfo=timezone.utc),
        source=source,
        session_id=session_id,
        model="m",
        session_context=session_context,
    )

    attributes = _attributes(entry)

    assert "gen_ai.conversation.id" not in attributes
    assert attributes == {
        "adr.event.type": "agent_session",
        "adr.event.uuid": entry.uuid,
        "adr.schema.version": "1",
        "adr.source": source,
        "adr.session.id": session_id,
        "adr.model": "m",
        "gen_ai.agent.name": source,
    }
