"""Unit tests for Google Antigravity transcript parser."""

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from adr_sensor.observer import AgentObserver
from adr_sensor.parsers.antigravity_parser import AntigravityParser


def _write_transcript(conv_dir: Path, steps: list, filename: str = "transcript.jsonl") -> Path:
    logs_dir = conv_dir / ".system_generated" / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    transcript_file = logs_dir / filename
    with open(transcript_file, "w", encoding="utf-8") as f:
        for step in steps:
            f.write(json.dumps(step) + "\n")
    return transcript_file


@pytest.fixture(autouse=True)
def clear_storage_overrides(monkeypatch):
    monkeypatch.delenv("ANTIGRAVITY_HOME", raising=False)
    monkeypatch.delenv("AGY_HOME", raising=False)


class TestAntigravityParser:
    def test_init_defaults_and_custom_base_path(self, tmp_path):
        parser = AntigravityParser()
        assert parser.max_age_days == 14
        assert len(parser.base_paths) > 0

        custom = AntigravityParser(base_path=tmp_path, max_age_days=7)
        assert custom.base_path == tmp_path
        assert custom.max_age_days == 7

        custom.base_path = tmp_path / "other"
        assert custom.base_path == tmp_path / "other"

    @pytest.mark.parametrize("product", ["antigravity-cli", "antigravity2", "antigravity-ide"])
    def test_discovers_documented_default_roots(self, tmp_path, monkeypatch, product):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        monkeypatch.setenv("APPDATA", str(tmp_path / "AppData" / "Roaming"))
        _write_transcript(
            tmp_path / ".gemini" / product / "brain" / "default-session",
            [{"type": "USER_INPUT", "content": "Find this session without any override."}],
        )

        entries = AntigravityParser().parse_all()

        assert len(entries) == 1
        assert entries[0].session_id == "antigravity_default-session"

    @pytest.mark.parametrize("variable", ["ANTIGRAVITY_HOME", "AGY_HOME"])
    def test_storage_override_and_explicit_base_path(self, tmp_path, monkeypatch, variable):
        storage = tmp_path / "custom-storage"
        (storage / "brain").mkdir(parents=True)
        monkeypatch.setenv(variable, str(storage))
        assert AntigravityParser().base_path == storage / "brain"
        assert AntigravityParser(base_path=tmp_path).base_path == tmp_path

    def test_parse_valid_transcript(self, tmp_path):
        conv_dir = tmp_path / "conv-uuid-123"
        steps = [
            {
                "step_index": 0,
                "source": "USER_EXPLICIT",
                "type": "USER_INPUT",
                "status": "DONE",
                "content": "Add unit tests for the authentication service",
            },
            {
                "step_index": 1,
                "source": "MODEL",
                "type": "PLANNER_RESPONSE",
                "status": "DONE",
                "content": "I will examine the auth routes and run pytest.",
                "tool_calls": [
                    {
                        "name": "view_file",
                        "toolAction": "Viewing file",
                        "parameters": {"AbsolutePath": "/src/auth.py"},
                    },
                    {
                        "name": "mcp_postgres_query",
                        "toolAction": "Query database",
                        "parameters": {"sql": "SELECT 1"},
                    },
                ],
            },
        ]
        transcript_path = _write_transcript(conv_dir, steps)

        parser = AntigravityParser(base_path=tmp_path)
        entry = parser.parse_transcript_file(transcript_path, conversation_id="conv-uuid-123")

        assert entry is not None
        assert entry.source == "antigravity"
        assert entry.session_id == "antigravity_conv-uuid-123"
        assert len(entry.chat_history) == 2

        user_msg = entry.chat_history[0]
        assert user_msg.role == "user"
        assert "authentication service" in user_msg.content

        assistant_msg = entry.chat_history[1]
        assert assistant_msg.role == "assistant"
        assert len(assistant_msg.tools) == 2

        tool1 = assistant_msg.tools[0]
        assert tool1.tool_name == "view_file"
        assert tool1.tool_type == "tool_use"
        assert tool1.server_name is None
        assert tool1.arguments == {"AbsolutePath": "/src/auth.py"}

        tool2 = assistant_msg.tools[1]
        assert tool2.tool_name == "mcp_postgres_query"
        assert tool2.tool_type == "mcp_tool"
        assert tool2.server_name == "postgres"
        assert tool2.arguments == {"sql": "SELECT 1"}

        assert entry.session_context["conversation_id"] == "conv-uuid-123"
        assert entry.session_context["step_count"] == 2
        assert entry.session_context["tool_call_count"] == 2

    def test_parse_all_discovers_multiple_conversations(self, tmp_path):
        conv1 = tmp_path / "conv-alpha"
        conv2 = tmp_path / "conv-beta"

        _write_transcript(
            conv1,
            [
                {"step_index": 0, "type": "USER_INPUT", "content": "hello alpha"},
                {"step_index": 1, "type": "PLANNER_RESPONSE", "content": "hi from alpha"},
            ],
        )
        _write_transcript(
            conv2,
            [
                {"step_index": 0, "type": "USER_INPUT", "content": "hello beta"},
                {"step_index": 1, "type": "PLANNER_RESPONSE", "content": "hi from beta"},
            ],
        )

        parser = AntigravityParser(base_path=tmp_path)
        entries = parser.parse_all()

        session_ids = {e.session_id for e in entries}
        assert session_ids == {"antigravity_conv-alpha", "antigravity_conv-beta"}

    def test_parse_all_respects_max_age_days(self, tmp_path):
        recent_conv = tmp_path / "recent"
        old_conv = tmp_path / "old"

        _write_transcript(
            recent_conv,
            [
                {"step_index": 0, "type": "USER_INPUT", "content": "recent task"},
                {"step_index": 1, "type": "PLANNER_RESPONSE", "content": "recent reply"},
            ],
        )
        old_file = _write_transcript(
            old_conv,
            [
                {"step_index": 0, "type": "USER_INPUT", "content": "old task"},
                {"step_index": 1, "type": "PLANNER_RESPONSE", "content": "old reply"},
            ],
        )

        old_ts = (datetime.now(timezone.utc) - timedelta(days=30)).timestamp()
        os.utime(old_file, (old_ts, old_ts))

        parser = AntigravityParser(base_path=tmp_path, max_age_days=14)
        entries = parser.parse_all()

        assert [e.session_id for e in entries] == ["antigravity_recent"]
        assert parser.get_diagnostics() == {"file_age_skipped": 1}

    def test_nonexistent_base_path_records_input_missing(self, tmp_path):
        parser = AntigravityParser(base_path=tmp_path / "does_not_exist")
        entries = parser.parse_all()
        assert entries == []
        assert parser.get_diagnostics() == {"input_missing": 1}

    def test_malformed_json_lines_skipped_resiliently(self, tmp_path):
        conv_dir = tmp_path / "corrupt-conv"
        logs_dir = conv_dir / ".system_generated" / "logs"
        logs_dir.mkdir(parents=True)
        transcript = logs_dir / "transcript.jsonl"
        with open(transcript, "w", encoding="utf-8") as f:
            f.write('{"step_index": 0, "type": "USER_INPUT", "content": "hello"}\n')
            f.write("THIS_IS_NOT_VALID_JSON\n")
            f.write('{"step_index": 1, "type": "PLANNER_RESPONSE", "content": "world"}\n')

        parser = AntigravityParser(base_path=tmp_path)
        entry = parser.parse_transcript_file(transcript, conversation_id="corrupt-conv")

        assert entry is not None
        assert len(entry.chat_history) == 2
        assert parser.get_diagnostics() == {"record_decode_error": 1}

    @pytest.mark.parametrize("argument_field", ["parameters", "arguments", "args"])
    def test_preserves_full_typed_parameters(self, tmp_path, argument_field):
        conv_dir = tmp_path / "large-args"
        arguments = {
            "payload": "A" * 5000 + "\nimportant trailing command",
            "count": 42,
            "enabled": False,
            "optional": None,
            "nested": {"files": ["one.py", "two.py"], "limit": 0},
        }
        _write_transcript(
            conv_dir,
            [
                {"step_index": 0, "type": "USER_INPUT", "content": "Process big input"},
                {
                    "step_index": 1,
                    "type": "PLANNER_RESPONSE",
                    "content": "Running tool",
                    "tool_calls": [
                        {
                            "name": "generate_code",
                            argument_field: arguments,
                        }
                    ],
                },
            ],
        )

        parser = AntigravityParser(base_path=tmp_path)
        entries = parser.parse_all()
        assert len(entries) == 1
        tool = entries[0].chat_history[1].tools[0]
        assert tool.arguments == arguments
        assert entries[0].to_dict()["chat_history"][1]["tools"][0]["arguments"] == arguments
        assert not entries[0].is_truncated

    @pytest.mark.parametrize("value", [0, False, [], "", ["one", {"two": 2}]])
    def test_non_mapping_arguments_are_preserved(self, value):
        tool = AntigravityParser._normalize_tool_call({"name": "example", "args": value})
        assert tool.arguments == {"input": value}

    def test_json_encoded_arguments_are_decoded_without_clipping(self):
        arguments = {"command": "A" * 5000, "timeout": 0, "enabled": False}
        tool = AntigravityParser._normalize_tool_call({"name": "run_command", "arguments": json.dumps(arguments)})
        assert tool.arguments == arguments

    def test_invalid_tool_name_does_not_drop_the_session(self, tmp_path):
        transcript = _write_transcript(
            tmp_path / "invalid-tool",
            [
                {"type": "USER_INPUT", "content": "Keep the valid conversation."},
                {
                    "type": "PLANNER_RESPONSE",
                    "tool_calls": [{"name": ["invalid"], "args": {"value": 1}}],
                },
            ],
        )
        entry = AntigravityParser(base_path=tmp_path).parse_transcript_file(transcript)
        assert entry is not None
        assert entry.chat_history[1].tools[0].tool_name == "unknown_tool"
        assert entry.chat_history[1].tools[0].arguments == {"value": 1}

    @pytest.mark.parametrize("failed_name", ["transcript.jsonl", "transcript_full.jsonl"])
    @pytest.mark.parametrize(
        "unusable_content",
        [b"", b"\xff", b"invalid JSON\n", b"[]\n", b'{"type":"SYSTEM_MESSAGE","content":"setup"}\n'],
        ids=["empty", "invalid-encoding", "invalid-json", "invalid-shape", "no-conversation"],
    )
    def test_unusable_transcript_does_not_hide_fallback(self, tmp_path, failed_name, unusable_content):
        conv_dir = tmp_path / "fallback"
        usable_name = "transcript_full.jsonl" if failed_name == "transcript.jsonl" else "transcript.jsonl"
        usable = _write_transcript(
            conv_dir,
            [{"type": "USER_INPUT", "content": "This fallback must be captured."}],
            filename=usable_name,
        )
        (usable.parent / failed_name).write_bytes(unusable_content)

        entries = AntigravityParser(base_path=tmp_path).parse_all()

        assert len(entries) == 1
        assert entries[0].raw_log_path == str(usable)
        assert entries[0].chat_history[0].content == "This fallback must be captured."

    def test_unreadable_transcript_does_not_hide_fallback(self, tmp_path, monkeypatch):
        conv_dir = tmp_path / "unreadable"
        steps = [{"type": "USER_INPUT", "content": "Capture the readable copy."}]
        unreadable = _write_transcript(conv_dir, steps)
        usable = _write_transcript(conv_dir, steps, filename="transcript_full.jsonl")
        original_open = open

        def read_with_permission_error(path, *args, **kwargs):
            if Path(path) == unreadable:
                raise PermissionError("synthetic permission error")
            return original_open(path, *args, **kwargs)

        monkeypatch.setattr("builtins.open", read_with_permission_error)
        parser = AntigravityParser(base_path=tmp_path)
        entries = parser.parse_all()

        assert len(entries) == 1
        assert entries[0].raw_log_path == str(usable)
        assert parser.get_diagnostics() == {"file_read_error": 1}

    def test_prefers_full_snapshot_over_compact_copy(self, tmp_path):
        conv_dir = tmp_path / "full-snapshot"
        full_content = "Full tool output.\n" * 500 + "Important final evidence."
        common = {"type": "PLANNER_RESPONSE", "created_at": "2026-01-01T00:00:00Z"}
        compact = _write_transcript(
            conv_dir,
            [{**common, "content": "Full tool output...[truncated]", "truncated_fields": ["content"]}],
        )
        full = _write_transcript(conv_dir, [{**common, "content": full_content}], filename="transcript_full.jsonl")
        # File-copy/write order must not make the abbreviated copy authoritative.
        os.utime(full, (compact.stat().st_mtime - 1, compact.stat().st_mtime - 1))

        entries = AntigravityParser(base_path=tmp_path).parse_all()

        assert len(entries) == 1
        assert entries[0].raw_log_path == str(full)
        assert entries[0].chat_history[0].content == full_content
        assert not entries[0].is_truncated

    def test_newer_compact_snapshot_is_not_hidden_by_stale_full_copy(self, tmp_path):
        conv_dir = tmp_path / "newer-snapshot"
        old = {"type": "USER_INPUT", "created_at": "2026-01-01T00:00:00Z", "content": "Start a task."}
        _write_transcript(conv_dir, [old], filename="transcript_full.jsonl")
        compact = _write_transcript(
            conv_dir,
            [
                old,
                {
                    "type": "PLANNER_RESPONSE",
                    "created_at": "2026-01-01T00:00:01Z",
                    "content": "More recent output...[truncated]",
                    "truncated_fields": ["content"],
                },
            ],
        )

        entries = AntigravityParser(base_path=tmp_path).parse_all()

        assert len(entries) == 1
        assert entries[0].raw_log_path == str(compact)
        assert len(entries[0].chat_history) == 2
        assert entries[0].is_truncated

    def test_cli_created_at_thinking_and_generic_output(self, tmp_path):
        thinking = "Consider the security implications before proceeding."
        transcript = _write_transcript(
            tmp_path / "cli-shape",
            [
                {
                    "step_index": 0,
                    "type": "USER_INPUT",
                    "source": "USER_EXPLICIT",
                    "created_at": "2026-01-01T10:00:00Z",
                    "content": "Inspect the example.",
                },
                {
                    "step_index": 1,
                    "type": "PLANNER_RESPONSE",
                    "source": "MODEL",
                    "created_at": "2026-01-01T10:00:01Z",
                    "thinking": thinking,
                    "tool_calls": [{"name": "view_file", "args": {"AbsolutePath": "/example/README.md"}}],
                },
                {
                    "step_index": 2,
                    "type": "GENERIC",
                    "source": "MODEL",
                    "created_at": "2026-01-01T10:00:02Z",
                    "content": "Complete tool output.",
                },
                {
                    "step_index": 3,
                    "type": "PLANNER_RESPONSE",
                    "source": "MODEL",
                    "created_at": "2026-01-01T10:00:03Z",
                    "thinking": "A final reasoning step.",
                    "content": "Inspection complete.",
                },
            ],
        )

        entry = AntigravityParser(base_path=tmp_path).parse_transcript_file(transcript)

        assert entry is not None
        assert entry.timestamp == datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
        assert entry.session_context["last_event_at"] == "2026-01-01T10:00:03+00:00"
        assert entry.session_context["event_count"] == 4
        assert entry.chat_history[1].content == f"[Thinking]\n{thinking}"
        assert entry.chat_history[1].tools[0].arguments == {"AbsolutePath": "/example/README.md"}
        assert entry.chat_history[2].content == "Complete tool output."
        assert entry.chat_history[3].content == "[Thinking]\nA final reasoning step.\n\nInspection complete."

    @pytest.mark.parametrize("invalid_timestamp", ["not-a-date", True, {}, 1e300])
    def test_invalid_cli_timestamp_does_not_drop_session(self, tmp_path, invalid_timestamp):
        transcript = _write_transcript(
            tmp_path / "invalid-time",
            [
                {"type": "USER_INPUT", "created_at": invalid_timestamp, "content": "Keep this prompt."},
                {"type": "PLANNER_RESPONSE", "timestamp": "2026-01-01T00:00:00Z", "content": "A reply."},
            ],
        )
        parser = AntigravityParser(base_path=tmp_path)

        entry = parser.parse_transcript_file(transcript)

        assert entry is not None
        assert len(entry.chat_history) == 2
        assert entry.timestamp == datetime(2026, 1, 1, tzinfo=timezone.utc)
        assert entry.session_context["last_event_at"] == "2026-01-01T00:00:00+00:00"
        assert parser.get_diagnostics() == {"invalid_timestamp": 1}

    def test_antigravity_through_observer(self, tmp_path):
        conv_dir = tmp_path / "brain" / "obs-conv"
        _write_transcript(
            conv_dir,
            [
                {"step_index": 0, "type": "USER_INPUT", "content": "Observe me"},
                {"step_index": 1, "type": "PLANNER_RESPONSE", "content": "Done observing"},
            ],
        )

        observer = AgentObserver(output_dir=tmp_path / "output")
        observer.antigravity_parser = AntigravityParser(base_path=tmp_path / "brain")

        events, _ = observer.ingest_all("antigravity")
        assert len(events) == 1
        assert events[0].source == "antigravity"
        assert events[0].session_id == "antigravity_obs-conv"

        records = [r for r in observer.get_diagnostic_records() if r.get("source") == "antigravity"]
        assert len(records) == 1
        assert records[0]["counts"]["events_emitted"] == 1
