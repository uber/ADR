"""Unit tests for Google Antigravity transcript parser."""

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from adr_sensor.observer import AgentObserver
from adr_sensor.parsers.antigravity_parser import AntigravityParser


def _write_transcript(conv_dir: Path, steps: list) -> Path:
    logs_dir = conv_dir / ".system_generated" / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    transcript_file = logs_dir / "transcript.jsonl"
    with open(transcript_file, "w", encoding="utf-8") as f:
        for step in steps:
            f.write(json.dumps(step) + "\n")
    return transcript_file


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

    def test_large_parameters_are_truncated(self, tmp_path):
        conv_dir = tmp_path / "large-args"
        large_text = "A" * 5000
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
                            "parameters": {"payload": large_text},
                        }
                    ],
                },
            ],
        )

        parser = AntigravityParser(base_path=tmp_path)
        entries = parser.parse_all()
        assert len(entries) == 1
        tool = entries[0].chat_history[1].tools[0]
        assert len(tool.arguments["payload"]) < 1100
        assert "[truncated]" in tool.arguments["payload"]

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
