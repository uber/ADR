"""Tests for ADR Sensor parsers."""

import json
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from adr_sensor.parsers.claude_parser import ClaudeParser
from adr_sensor.parsers.cline_parser import ClineParser
from adr_sensor.parsers.codex_parser import CodexParser
from adr_sensor.parsers.warp_parser import WarpParser


class TestClaudeParser:
    def test_parse_jsonl_file(self, tmp_path):
        """Test parsing a JSONL file with Claude Code format."""
        jsonl_file = tmp_path / "test.jsonl"
        messages = [
            {
                "type": "user",
                "sessionId": "session1",
                "timestamp": "2025-06-15T10:00:00Z",
                "message": {"content": "Help me write a function"},
            },
            {
                "type": "assistant",
                "sessionId": "session1",
                "timestamp": "2025-06-15T10:00:01Z",
                "message": {
                    "model": "claude-sonnet-4-20250514",
                    "content": [
                        {"type": "text", "text": "Sure! Here's a function:"},
                        {
                            "type": "tool_use",
                            "id": "tool1",
                            "name": "write_file",
                            "input": {"path": "main.py", "content": "def hello(): pass"},
                        },
                    ],
                },
            },
            {
                "type": "user",
                "sessionId": "session1",
                "timestamp": "2025-06-15T10:00:02Z",
                "message": {
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "tool1",
                            "content": "File written successfully",
                        }
                    ]
                },
            },
        ]
        with open(jsonl_file, "w") as f:
            for msg in messages:
                f.write(json.dumps(msg) + "\n")

        parser = ClaudeParser()
        entries = parser.parse_jsonl_file(jsonl_file)

        assert len(entries) == 1
        entry = entries[0]
        assert entry.source == "claude"
        assert entry.session_id == "claude_session1"
        assert entry.model == "claude-sonnet-4-20250514"
        assert len(entry.chat_history) >= 1

    def test_parse_empty_file(self, tmp_path):
        """Test parsing an empty file."""
        jsonl_file = tmp_path / "empty.jsonl"
        jsonl_file.write_text("")

        parser = ClaudeParser()
        entries = parser.parse_jsonl_file(jsonl_file)
        assert len(entries) == 0

    def test_parse_all_no_directory(self):
        """Test parse_all when directory doesn't exist."""
        parser = ClaudeParser()
        parser.base_path = Path("/nonexistent/path")
        entries = parser.parse_all()
        assert entries == []

    def test_truncate_large_arguments(self):
        """Test that large arguments are truncated."""
        parser = ClaudeParser()
        args = {"short": "hello", "long": "x" * 2000}
        result = parser._truncate_large_arguments(args)
        assert result["short"] == "hello"
        assert len(result["long"]) < 2000
        assert "[truncated" in result["long"]


class TestClineParser:
    def test_parse_cline_log(self, tmp_path):
        """Test parsing a Cline task directory."""
        task_dir = tmp_path / "1234567890"
        task_dir.mkdir()

        conversation = [
            {
                "role": "user",
                "content": [{"type": "text", "text": "Create a hello world script"}],
            },
            {
                "role": "assistant",
                "content": [
                    {"type": "text", "text": "I'll create that for you."},
                ],
            },
        ]

        api_file = task_dir / "api_conversation_history.json"
        with open(api_file, "w") as f:
            json.dump(conversation, f)

        parser = ClineParser()
        entry = parser.parse_cline_log(task_dir)

        assert entry is not None
        assert entry.source == "cline"
        assert len(entry.chat_history) == 2

    def test_extract_mcp_tools(self):
        """Test MCP tool extraction from text."""
        parser = ClineParser()
        text = """
        <use_mcp_tool>
        <server_name>my-server</server_name>
        <tool_name>query_database</tool_name>
        <arguments>{"query": "SELECT * FROM users"}</arguments>
        </use_mcp_tool>
        """
        tools = parser.extract_mcp_tools(text)
        assert len(tools) == 1
        assert tools[0].tool_name == "query_database"
        assert tools[0].server_name == "my-server"
        assert tools[0].tool_type == "mcp_tool"

    def test_parse_no_directory(self):
        """Test parse_all when directory doesn't exist."""
        parser = ClineParser()
        parser.base_path = Path("/nonexistent/path")
        entries = parser.parse_all()
        assert entries == []


class TestCodexParser:
    def test_parse_jsonl_file(self, tmp_path):
        """Test parsing a Codex CLI JSONL file."""
        jsonl_file = tmp_path / "rollout-001.jsonl"
        events = [
            {"type": "session_meta", "payload": {"id": "sess1", "timestamp": "2025-06-15T10:00:00Z", "cwd": "/tmp"}},
            {"type": "turn_context", "payload": {"model": "o3-mini"}},
            {
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "user",
                    "content": [{"type": "input_text", "text": "List all Python files"}],
                },
            },
            {
                "type": "response_item",
                "payload": {
                    "type": "function_call",
                    "call_id": "call1",
                    "name": "shell",
                    "arguments": '{"command": "find . -name \\"*.py\\""}',
                },
            },
            {
                "type": "response_item",
                "payload": {"type": "function_call_output", "call_id": "call1", "output": "main.py\ntest.py"},
            },
            {
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": "Found 2 Python files."}],
                },
            },
        ]
        with open(jsonl_file, "w") as f:
            for event in events:
                f.write(json.dumps(event) + "\n")

        parser = CodexParser()
        entry = parser.parse_jsonl_file(jsonl_file)

        assert entry is not None
        assert entry.source == "codex"
        assert entry.session_id == "codex_sess1"
        assert entry.model == "o3-mini"
        assert len(entry.chat_history) >= 2

        # Check that tool was parsed
        assistant_msgs = [m for m in entry.chat_history if m.role == "assistant"]
        has_tools = any(len(m.tools) > 0 for m in assistant_msgs)
        assert has_tools

    def test_parse_no_directory(self):
        """Test parse_all when directory doesn't exist."""
        parser = CodexParser()
        parser.base_path = Path("/nonexistent/path")
        entries = parser.parse_all()
        assert entries == []


def _build_warp_db(db_path: Path, conversations: list) -> None:
    """Create a synthetic warp.sqlite matching the schema WarpParser queries.

    Each item in `conversations` is a dict with keys:
        conversation_id, last_modified_at, exchanges
    where `exchanges` is a list of (exchange_id, start_ts, input_json, llm_output_json).
    """
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE agent_conversations (
            conversation_id TEXT PRIMARY KEY,
            conversation_data TEXT,
            last_modified_at TEXT
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE ai_queries (
            exchange_id TEXT,
            conversation_id TEXT,
            start_ts TEXT,
            input TEXT,
            working_directory TEXT,
            output_status TEXT,
            model_id TEXT
        )
        """
    )
    cursor.execute("CREATE TABLE ai_blocks (exchange_id TEXT, output TEXT)")

    for conv in conversations:
        cursor.execute(
            "INSERT INTO agent_conversations VALUES (?, ?, ?)",
            (conv["conversation_id"], "unused_blob", conv["last_modified_at"]),
        )
        for exchange_id, start_ts, input_json, llm_output_json in conv.get("exchanges", []):
            cursor.execute(
                "INSERT INTO ai_queries VALUES (?, ?, ?, ?, ?, ?, ?)",
                (exchange_id, conv["conversation_id"], start_ts, input_json, "/tmp/project", "success", "claude"),
            )
            if llm_output_json is not None:
                cursor.execute("INSERT INTO ai_blocks VALUES (?, ?)", (exchange_id, llm_output_json))

    conn.commit()
    conn.close()


class TestWarpParser:
    def _make_parser(self, tmp_path: Path, max_age_days: int = 14) -> WarpParser:
        parser = WarpParser(max_age_days=max_age_days)
        parser.base_path = tmp_path
        parser.db_path = tmp_path / "warp.sqlite"
        return parser

    def _query_exchange(self, exchange_id: str, timestamp: str) -> tuple:
        input_json = json.dumps([{"Query": {"text": f"hello from {exchange_id}"}}])
        llm_output_json = json.dumps({"Received": {"output": [{"Text": {"text": f"reply for {exchange_id}"}}]}})
        return (exchange_id, timestamp, input_json, llm_output_json)

    def test_skips_conversations_older_than_max_age(self, tmp_path):
        """Old conversations should be filtered out before the expensive per-conversation query runs."""
        now = datetime.now(timezone.utc)
        recent_ts = now.isoformat()
        old_ts = (now - timedelta(days=30)).isoformat()

        conversations = [
            {
                "conversation_id": "recent-conv",
                "last_modified_at": recent_ts,
                "exchanges": [self._query_exchange("ex-recent", recent_ts)],
            },
            {
                "conversation_id": "old-conv",
                "last_modified_at": old_ts,
                "exchanges": [self._query_exchange("ex-old", old_ts)],
            },
        ]
        db_path = tmp_path / "warp.sqlite"
        _build_warp_db(db_path, conversations)

        parser = self._make_parser(tmp_path, max_age_days=14)
        entries = parser.parse_all()

        session_ids = {e.session_id for e in entries}
        assert "warp_recent-conv" in session_ids
        assert "warp_old-conv" not in session_ids

    def test_all_history_via_large_max_age_days(self, tmp_path):
        """A larger max_age_days should include conversations that would otherwise be skipped."""
        now = datetime.now(timezone.utc)
        old_ts = (now - timedelta(days=30)).isoformat()

        conversations = [
            {
                "conversation_id": "old-conv",
                "last_modified_at": old_ts,
                "exchanges": [self._query_exchange("ex-old", old_ts)],
            }
        ]
        db_path = tmp_path / "warp.sqlite"
        _build_warp_db(db_path, conversations)

        parser = self._make_parser(tmp_path, max_age_days=10000)
        entries = parser.parse_all()

        assert {e.session_id for e in entries} == {"warp_old-conv"}

    def test_parses_conversation_content(self, tmp_path):
        """Recent conversations should still be parsed into chat history correctly."""
        now = datetime.now(timezone.utc)
        ts1 = now.isoformat()
        ts2 = (now + timedelta(seconds=1)).isoformat()

        action_result_input = json.dumps(
            [
                {
                    "ActionResult": {
                        "id": "tool-1",
                        "result": {
                            "RequestCommandOutput": {
                                "result": {"Success": {"command": "ls", "output": "file.txt", "exit_code": 0}}
                            }
                        },
                    }
                }
            ]
        )

        conversations = [
            {
                "conversation_id": "conv-1",
                "last_modified_at": ts2,
                "exchanges": [
                    self._query_exchange("ex-1", ts1),
                    ("ex-2", ts2, action_result_input, None),
                ],
            }
        ]
        db_path = tmp_path / "warp.sqlite"
        _build_warp_db(db_path, conversations)

        parser = self._make_parser(tmp_path)
        entries = parser.parse_all()

        assert len(entries) == 1
        entry = entries[0]
        assert entry.source == "warp"
        assert entry.session_id == "warp_conv-1"
        assert len(entry.chat_history) == 2

        user_msg = entry.chat_history[0]
        assert user_msg.role == "user"
        assert "hello from ex-1" in user_msg.content

        assistant_msg = entry.chat_history[1]
        assert assistant_msg.role == "assistant"
        assert len(assistant_msg.tools) == 1
        assert assistant_msg.tools[0].tool_name == "execute_command"
        assert assistant_msg.tools[0].status == "success"

    def test_parse_all_no_database(self, tmp_path):
        """Test parse_all when the database file doesn't exist."""
        parser = self._make_parser(tmp_path)
        entries = parser.parse_all()
        assert entries == []

    def test_default_max_age_days(self):
        """Constructor should default to the module-level constant when unset."""
        parser = WarpParser()
        assert parser.max_age_days == 14
