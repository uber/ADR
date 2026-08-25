"""Tests for ADR Sensor parsers."""

import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from adr_sensor.parsers.claude_desktop_parser import ClaudeDesktopParser
from adr_sensor.parsers.claude_parser import ClaudeParser
from adr_sensor.parsers.cline_parser import ClineParser
from adr_sensor.parsers.codex_parser import CodexParser
from adr_sensor.parsers.cursor_parser import CursorParser
from adr_sensor.parsers.opencode_parser import OpencodeParser
from adr_sensor.parsers.warp_parser import WarpParser
from adr_sensor.utils.platform_paths import windows_appdata, windows_local_appdata


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

    def test_parses_custom_tool_call(self, tmp_path):
        """custom_tool_call records must yield tools with their arguments intact.

        Shapes taken from a real Codex Desktop session: the call carries a raw,
        non-JSON string under "input" (not a JSON string under "arguments"), and
        the output is a list of content items rather than a plain string.
        """
        jsonl_file = tmp_path / "rollout-custom.jsonl"
        events = [
            {"type": "session_meta", "payload": {"id": "s-custom", "timestamp": "2026-08-08T17:17:28.774Z",
                                                 "cwd": "/tmp/project"}},
            {"type": "turn_context", "payload": {"model": "gpt-5.6-sol"}},
            {"type": "response_item", "payload": {"type": "message", "role": "user",
                                                  "content": [{"type": "input_text", "text": "check the repo"}]}},
            {"type": "response_item", "payload": {
                "type": "custom_tool_call", "call_id": "call_1", "name": "exec",
                "status": "completed",
                "input": 'bash -lc "git status --short"'}},
            {"type": "response_item", "payload": {
                "type": "custom_tool_call_output", "call_id": "call_1",
                "output": [{"type": "input_text", "text": "M  README.md"},
                           {"type": "input_text", "text": "exit code 0"}]}},
        ]
        with open(jsonl_file, "w") as f:
            for e in events:
                f.write(json.dumps(e) + "\n")

        entry = CodexParser().parse_jsonl_file(jsonl_file)

        tools = [t for m in entry.chat_history for t in m.tools]
        assert len(tools) == 1
        tool = tools[0]
        assert tool.tool_name == "exec"
        assert tool.tool_type == "custom_tool_call"
        # The command string is the security signal - it must survive.
        assert tool.arguments == {"raw": 'bash -lc "git status --short"'}
        assert tool.result == "M  README.md\nexit code 0"
        assert tool.status == "success"

    def test_custom_tool_call_json_input_is_parsed(self, tmp_path):
        """A custom_tool_call whose input IS valid JSON should parse as a dict."""
        jsonl_file = tmp_path / "rollout-json-input.jsonl"
        events = [
            {"type": "session_meta", "payload": {"id": "s-json", "timestamp": "2026-08-08T17:00:00.000Z"}},
            {"type": "response_item", "payload": {"type": "message", "role": "user",
                                                  "content": [{"type": "input_text", "text": "hello there"}]}},
            {"type": "response_item", "payload": {
                "type": "custom_tool_call", "call_id": "c2", "name": "fetch",
                "input": '{"url": "https://example.com"}'}},
        ]
        with open(jsonl_file, "w") as f:
            for e in events:
                f.write(json.dumps(e) + "\n")

        entry = CodexParser().parse_jsonl_file(jsonl_file)
        tool = [t for m in entry.chat_history for t in m.tools][0]
        assert tool.arguments == {"url": "https://example.com"}
        assert tool.status == "pending"  # no status field, no output -> unchanged

    def test_custom_tool_call_output_is_truncated(self, tmp_path):
        """A large list-shaped output must be normalized AND truncated."""
        jsonl_file = tmp_path / "rollout-big.jsonl"
        events = [
            {"type": "session_meta", "payload": {"id": "s-big", "timestamp": "2026-08-08T17:00:00.000Z"}},
            {"type": "response_item", "payload": {"type": "message", "role": "user",
                                                  "content": [{"type": "input_text", "text": "dump the file"}]}},
            {"type": "response_item", "payload": {"type": "custom_tool_call", "call_id": "c3",
                                                  "name": "exec", "input": "cat big.txt"}},
            {"type": "response_item", "payload": {"type": "custom_tool_call_output", "call_id": "c3",
                                                  "output": [{"type": "input_text", "text": "A" * 5000}]}},
        ]
        with open(jsonl_file, "w") as f:
            for e in events:
                f.write(json.dumps(e) + "\n")

        entry = CodexParser().parse_jsonl_file(jsonl_file)
        tool = [t for m in entry.chat_history for t in m.tools][0]
        assert isinstance(tool.result, str)
        assert len(tool.result) < 1200
        assert "[truncated" in tool.result

    def test_function_call_still_works(self, tmp_path):
        """The classic function_call path must be unaffected by the new branch."""
        jsonl_file = tmp_path / "rollout-fn.jsonl"
        events = [
            {"type": "session_meta", "payload": {"id": "s-fn", "timestamp": "2026-08-08T17:00:00.000Z"}},
            {"type": "response_item", "payload": {"type": "message", "role": "user",
                                                  "content": [{"type": "input_text", "text": "read the file"}]}},
            {"type": "response_item", "payload": {"type": "function_call", "call_id": "c4",
                                                  "name": "read_file",
                                                  "arguments": '{"path": "main.py"}'}},
            {"type": "response_item", "payload": {"type": "function_call_output", "call_id": "c4",
                                                  "output": "def main(): pass"}},
        ]
        with open(jsonl_file, "w") as f:
            for e in events:
                f.write(json.dumps(e) + "\n")

        entry = CodexParser().parse_jsonl_file(jsonl_file)
        tool = [t for m in entry.chat_history for t in m.tools][0]
        assert tool.tool_name == "read_file"
        assert tool.tool_type == "function_call"
        assert tool.arguments == {"path": "main.py"}
        assert tool.result == "def main(): pass"

    def test_mixed_tool_types_in_one_session(self, tmp_path):
        """Both record shapes can appear in the same session and must both survive."""
        jsonl_file = tmp_path / "rollout-mixed.jsonl"
        events = [
            {"type": "session_meta", "payload": {"id": "s-mix", "timestamp": "2026-08-08T17:00:00.000Z"}},
            {"type": "response_item", "payload": {"type": "message", "role": "user",
                                                  "content": [{"type": "input_text", "text": "do both things"}]}},
            {"type": "response_item", "payload": {"type": "function_call", "call_id": "f1",
                                                  "name": "apply_patch", "arguments": '{"path": "a.py"}'}},
            {"type": "response_item", "payload": {"type": "function_call_output", "call_id": "f1",
                                                  "output": "patched"}},
            {"type": "response_item", "payload": {"type": "custom_tool_call", "call_id": "c1",
                                                  "name": "exec", "input": "ls -la"}},
            {"type": "response_item", "payload": {"type": "custom_tool_call_output", "call_id": "c1",
                                                  "output": [{"type": "input_text", "text": "total 0"}]}},
        ]
        with open(jsonl_file, "w") as f:
            for e in events:
                f.write(json.dumps(e) + "\n")

        entry = CodexParser().parse_jsonl_file(jsonl_file)
        tools = {t.tool_name: t for m in entry.chat_history for t in m.tools}
        assert set(tools) == {"apply_patch", "exec"}
        assert tools["apply_patch"].tool_type == "function_call"
        assert tools["apply_patch"].arguments == {"path": "a.py"}
        assert tools["exec"].tool_type == "custom_tool_call"
        assert tools["exec"].arguments == {"raw": "ls -la"}
        assert tools["exec"].result == "total 0"

    def test_custom_tool_call_without_output(self, tmp_path):
        """An orphaned call (no matching output) keeps its arguments and stays pending."""
        jsonl_file = tmp_path / "rollout-orphan.jsonl"
        events = [
            {"type": "session_meta", "payload": {"id": "s-orphan", "timestamp": "2026-08-08T17:00:00.000Z"}},
            {"type": "response_item", "payload": {"type": "message", "role": "user",
                                                  "content": [{"type": "input_text", "text": "run something"}]}},
            {"type": "response_item", "payload": {"type": "custom_tool_call", "call_id": "orphan",
                                                  "name": "exec", "input": "sleep 60"}},
        ]
        with open(jsonl_file, "w") as f:
            for e in events:
                f.write(json.dumps(e) + "\n")

        tool = [t for m in CodexParser().parse_jsonl_file(jsonl_file).chat_history for t in m.tools][0]
        assert tool.arguments == {"raw": "sleep 60"}
        assert tool.result is None
        assert tool.status == "pending"

    def test_output_without_matching_call_is_ignored(self, tmp_path):
        """An output whose call_id was never seen must not raise or invent a tool."""
        jsonl_file = tmp_path / "rollout-stray.jsonl"
        events = [
            {"type": "session_meta", "payload": {"id": "s-stray", "timestamp": "2026-08-08T17:00:00.000Z"}},
            {"type": "response_item", "payload": {"type": "message", "role": "user",
                                                  "content": [{"type": "input_text", "text": "a question here"}]}},
            {"type": "response_item", "payload": {"type": "custom_tool_call_output", "call_id": "never-seen",
                                                  "output": [{"type": "input_text", "text": "orphan output"}]}},
        ]
        with open(jsonl_file, "w") as f:
            for e in events:
                f.write(json.dumps(e) + "\n")

        entry = CodexParser().parse_jsonl_file(jsonl_file)
        assert [t for m in entry.chat_history for t in m.tools] == []

    def test_output_list_with_unexpected_items(self, tmp_path):
        """Non-dict and text-less items in the output list are skipped, not fatal."""
        jsonl_file = tmp_path / "rollout-odd.jsonl"
        events = [
            {"type": "session_meta", "payload": {"id": "s-odd", "timestamp": "2026-08-08T17:00:00.000Z"}},
            {"type": "response_item", "payload": {"type": "message", "role": "user",
                                                  "content": [{"type": "input_text", "text": "mixed output"}]}},
            {"type": "response_item", "payload": {"type": "custom_tool_call", "call_id": "c9",
                                                  "name": "exec", "input": "echo hi"}},
            {"type": "response_item", "payload": {"type": "custom_tool_call_output", "call_id": "c9",
                                                  "output": ["bare string", 42, None,
                                                             {"type": "image", "url": "x"},
                                                             {"type": "input_text", "text": "kept"}]}},
        ]
        with open(jsonl_file, "w") as f:
            for e in events:
                f.write(json.dumps(e) + "\n")

        tool = [t for m in CodexParser().parse_jsonl_file(jsonl_file).chat_history for t in m.tools][0]
        assert tool.result == "bare string\nkept"

    def test_event_msg_records_are_ignored(self, tmp_path):
        """event_msg records (token_count, web_search_end, ...) must not break parsing.

        They are currently unparsed; this pins that they are skipped cleanly rather
        than raising or polluting chat_history.
        """
        jsonl_file = tmp_path / "rollout-eventmsg.jsonl"
        events = [
            {"type": "session_meta", "payload": {"id": "s-em", "timestamp": "2026-08-08T17:00:00.000Z"}},
            {"type": "event_msg", "payload": {"type": "token_count",
                                              "info": {"total_token_usage": {"input_tokens": 10}}}},
            {"type": "event_msg", "payload": {"type": "web_search_end", "call_id": "w1", "query": "anything"}},
            {"type": "response_item", "payload": {"type": "message", "role": "user",
                                                  "content": [{"type": "input_text", "text": "hello there"}]}},
            {"type": "response_item", "payload": {"type": "custom_tool_call", "call_id": "c1",
                                                  "name": "exec", "input": "true"}},
        ]
        with open(jsonl_file, "w") as f:
            for e in events:
                f.write(json.dumps(e) + "\n")

        entry = CodexParser().parse_jsonl_file(jsonl_file)
        assert len(entry.chat_history) == 2  # user message + assistant tool turn
        assert len([t for m in entry.chat_history for t in m.tools]) == 1

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


NOW_MS = int(datetime.now(timezone.utc).timestamp() * 1000)
OLD_MS = NOW_MS - int(40 * 86400 * 1000)  # 40 days ago


def _build_opencode_db(db_path, sessions, messages, parts):
    """Create an opencode-shaped SQLite database with the given rows."""
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "CREATE TABLE session (id TEXT PRIMARY KEY, directory TEXT, title TEXT, version TEXT, "
        "model TEXT, time_created INTEGER, time_updated INTEGER)"
    )
    conn.execute(
        "CREATE TABLE message (id TEXT PRIMARY KEY, session_id TEXT, time_created INTEGER, data TEXT)"
    )
    conn.execute(
        "CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT, session_id TEXT, "
        "time_created INTEGER, data TEXT)"
    )
    for s in sessions:
        conn.execute(
            "INSERT INTO session VALUES (?,?,?,?,?,?,?)",
            (
                s["id"],
                s.get("directory"),
                s.get("title"),
                s.get("version"),
                s.get("model"),
                s.get("time_created", NOW_MS),
                s.get("time_updated", NOW_MS),
            ),
        )
    for m in messages:
        conn.execute(
            "INSERT INTO message VALUES (?,?,?,?)",
            (m["id"], m["session_id"], m.get("time_created", NOW_MS), json.dumps(m["data"])),
        )
    for p in parts:
        conn.execute(
            "INSERT INTO part VALUES (?,?,?,?,?)",
            (
                p["id"],
                p["message_id"],
                p["session_id"],
                p.get("time_created", NOW_MS),
                json.dumps(p["data"]),
            ),
        )
    conn.commit()
    conn.close()


def _make_opencode_parser(base_dir, max_age_days=0):
    """Build an OpencodeParser whose backend detection points at base_dir."""
    with patch.object(OpencodeParser, "_candidate_base_dirs", return_value=[base_dir]):
        return OpencodeParser(max_age_days=max_age_days)


class TestOpencodeParserBackendDetection:
    def test_no_backend_found(self, tmp_path):
        parser = _make_opencode_parser(tmp_path)
        assert parser.backend is None
        assert parser.parse_all() == []

    def test_sqlite_backend_detected(self, tmp_path):
        (tmp_path / "opencode.db").touch()
        parser = _make_opencode_parser(tmp_path)
        assert parser.backend == "sqlite"

    def test_json_backend_detected(self, tmp_path):
        (tmp_path / "storage").mkdir()
        parser = _make_opencode_parser(tmp_path)
        assert parser.backend == "json"

    def test_sqlite_takes_priority_over_json(self, tmp_path):
        (tmp_path / "opencode.db").touch()
        (tmp_path / "storage").mkdir()
        parser = _make_opencode_parser(tmp_path)
        assert parser.backend == "sqlite"

    def test_channel_suffixed_db_detected(self, tmp_path):
        """Non-stable channels write opencode-<channel>.db instead."""
        (tmp_path / "opencode-nightly.db").touch()
        parser = _make_opencode_parser(tmp_path)
        assert parser.backend == "sqlite"
        assert parser.db_path.name == "opencode-nightly.db"

    def test_default_db_preferred_over_channel_suffixed(self, tmp_path):
        (tmp_path / "opencode.db").touch()
        (tmp_path / "opencode-dev.db").touch()
        parser = _make_opencode_parser(tmp_path)
        assert parser.db_path.name == "opencode.db"

    def test_opencode_db_env_override(self, tmp_path, monkeypatch):
        custom = tmp_path / "custom.db"
        custom.touch()
        monkeypatch.setenv("OPENCODE_DB", str(custom))
        parser = _make_opencode_parser(tmp_path)
        assert parser.db_path == custom

    def test_opencode_db_memory_value_ignored(self, tmp_path, monkeypatch):
        monkeypatch.setenv("OPENCODE_DB", ":memory:")
        (tmp_path / "opencode.db").touch()
        parser = _make_opencode_parser(tmp_path)
        assert parser.db_path.name == "opencode.db"

    def test_xdg_data_home_is_first_candidate(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
        assert OpencodeParser._candidate_base_dirs()[0] == tmp_path / "opencode"

    def test_default_max_age_days(self):
        assert OpencodeParser().max_age_days == 14


class TestOpencodeParserSqlite:
    def test_parses_conversation_with_tool(self, tmp_path):
        db_path = tmp_path / "opencode.db"
        _build_opencode_db(
            db_path,
            sessions=[
                {
                    "id": "ses_abc123",
                    "directory": "/home/dev/project",
                    "version": "1.17.14",
                    "model": json.dumps({"id": "claude-sonnet-4", "providerID": "anthropic"}),
                }
            ],
            messages=[
                {"id": "msg_1", "session_id": "ses_abc123", "data": {"role": "user"}},
                {
                    "id": "msg_2",
                    "session_id": "ses_abc123",
                    "data": {"role": "assistant", "providerID": "anthropic", "modelID": "claude-sonnet-4"},
                },
            ],
            parts=[
                {
                    "id": "prt_1",
                    "message_id": "msg_1",
                    "session_id": "ses_abc123",
                    "data": {"type": "text", "text": "list the files"},
                },
                {
                    "id": "prt_2",
                    "message_id": "msg_2",
                    "session_id": "ses_abc123",
                    "data": {
                        "type": "tool",
                        "tool": "bash",
                        "state": {"status": "completed", "input": {"command": "ls"}, "output": "a.py\nb.py"},
                    },
                },
            ],
        )

        entries = _make_opencode_parser(tmp_path).parse_all()

        assert len(entries) == 1
        entry = entries[0]
        assert entry.source == "opencode"
        # The agent's own "ses_" prefix is stripped in favour of our source prefix.
        assert entry.session_id == "opencode_abc123"
        assert entry.project_path == "/home/dev/project"
        assert entry.model == "claude-sonnet-4"
        assert entry.user_id == "anthropic opencode/1.17.14"

        assert [m.role for m in entry.chat_history] == ["user", "assistant"]
        assert entry.chat_history[0].content == "list the files"

        tool = entry.chat_history[1].tools[0]
        assert tool.tool_name == "bash"
        assert tool.tool_type == "function_call"
        assert tool.server_name is None
        assert tool.status == "success"
        assert tool.result == "a.py\nb.py"

    def test_mcp_tool_is_classified_with_server_name(self, tmp_path):
        db_path = tmp_path / "opencode.db"
        _build_opencode_db(
            db_path,
            sessions=[{"id": "ses_mcp"}],
            messages=[{"id": "msg_1", "session_id": "ses_mcp", "data": {"role": "assistant"}}],
            parts=[
                {
                    "id": "prt_1",
                    "message_id": "msg_1",
                    "session_id": "ses_mcp",
                    "data": {
                        "type": "tool",
                        "tool": "github_create_issue",
                        "state": {"status": "completed", "input": {"title": "bug"}, "output": "#42"},
                    },
                }
            ],
        )

        entries = _make_opencode_parser(tmp_path).parse_all()

        tool = entries[0].chat_history[0].tools[0]
        assert tool.tool_type == "mcp_tool"
        assert tool.server_name == "github"

    def test_tool_error_is_captured(self, tmp_path):
        db_path = tmp_path / "opencode.db"
        _build_opencode_db(
            db_path,
            sessions=[{"id": "ses_err"}],
            messages=[{"id": "msg_1", "session_id": "ses_err", "data": {"role": "assistant"}}],
            parts=[
                {
                    "id": "prt_1",
                    "message_id": "msg_1",
                    "session_id": "ses_err",
                    "data": {
                        "type": "tool",
                        "tool": "read",
                        "state": {"status": "error", "input": {"filePath": "/nope"}, "error": "ENOENT"},
                    },
                }
            ],
        )

        tool = _make_opencode_parser(tmp_path).parse_all()[0].chat_history[0].tools[0]
        assert tool.status == "error"
        assert tool.error == "ENOENT"
        assert tool.result == "ENOENT"

    def test_reasoning_subtask_and_file_parts(self, tmp_path):
        db_path = tmp_path / "opencode.db"
        _build_opencode_db(
            db_path,
            sessions=[{"id": "ses_parts"}],
            messages=[
                {"id": "msg_1", "session_id": "ses_parts", "data": {"role": "user"}},
                {"id": "msg_2", "session_id": "ses_parts", "data": {"role": "assistant"}},
            ],
            parts=[
                {
                    "id": "prt_1",
                    "message_id": "msg_1",
                    "session_id": "ses_parts",
                    "data": {"type": "subtask", "agent": "reviewer", "prompt": "review the diff"},
                },
                {
                    "id": "prt_2",
                    "message_id": "msg_1",
                    "session_id": "ses_parts",
                    "data": {"type": "file", "filename": "diff.patch"},
                },
                {
                    "id": "prt_3",
                    "message_id": "msg_2",
                    "session_id": "ses_parts",
                    "data": {"type": "reasoning", "text": "thinking it through"},
                },
            ],
        )

        entry = _make_opencode_parser(tmp_path).parse_all()[0]

        assert "[Subtask: reviewer]\nreview the diff" in entry.chat_history[0].content
        assert "[Attached file: diff.patch]" in entry.chat_history[0].content
        assert entry.chat_history[1].content == "[Reasoning]\nthinking it through"

    def test_structural_only_message_is_skipped(self, tmp_path):
        db_path = tmp_path / "opencode.db"
        _build_opencode_db(
            db_path,
            sessions=[{"id": "ses_struct"}],
            messages=[
                {"id": "msg_1", "session_id": "ses_struct", "data": {"role": "user"}},
                {"id": "msg_2", "session_id": "ses_struct", "data": {"role": "assistant"}},
            ],
            parts=[
                {
                    "id": "prt_1",
                    "message_id": "msg_1",
                    "session_id": "ses_struct",
                    "data": {"type": "text", "text": "a real question"},
                },
                {
                    "id": "prt_2",
                    "message_id": "msg_2",
                    "session_id": "ses_struct",
                    "data": {"type": "step-start"},
                },
            ],
        )

        entry = _make_opencode_parser(tmp_path).parse_all()[0]
        assert len(entry.chat_history) == 1

    def test_age_filter_excludes_old_sessions(self, tmp_path):
        db_path = tmp_path / "opencode.db"
        _build_opencode_db(
            db_path,
            sessions=[{"id": "ses_old", "time_created": OLD_MS, "time_updated": OLD_MS}],
            messages=[{"id": "msg_1", "session_id": "ses_old", "data": {"role": "user"}}],
            parts=[
                {
                    "id": "prt_1",
                    "message_id": "msg_1",
                    "session_id": "ses_old",
                    "data": {"type": "text", "text": "an old conversation"},
                }
            ],
        )

        assert _make_opencode_parser(tmp_path, max_age_days=14).parse_all() == []
        assert len(_make_opencode_parser(tmp_path, max_age_days=0).parse_all()) == 1

    def test_large_tool_output_is_truncated(self, tmp_path):
        db_path = tmp_path / "opencode.db"
        _build_opencode_db(
            db_path,
            sessions=[{"id": "ses_big"}],
            messages=[{"id": "msg_1", "session_id": "ses_big", "data": {"role": "assistant"}}],
            parts=[
                {
                    "id": "prt_1",
                    "message_id": "msg_1",
                    "session_id": "ses_big",
                    "data": {
                        "type": "tool",
                        "tool": "bash",
                        "state": {
                            "status": "completed",
                            "input": {"command": "x" * 2000},
                            "output": "y" * 5000,
                        },
                    },
                }
            ],
        )

        tool = _make_opencode_parser(tmp_path).parse_all()[0].chat_history[0].tools[0]
        assert "[truncated" in tool.result
        assert "[truncated" in tool.arguments["command"]


class TestOpencodeParserJsonStorage:
    def test_project_scoped_layout(self, tmp_path):
        storage = tmp_path / "storage"
        (storage / "session" / "proj1").mkdir(parents=True)
        (storage / "session" / "proj1" / "ses_json1.json").write_text(
            json.dumps(
                {
                    "id": "ses_json1",
                    "directory": "/home/dev/legacy",
                    "version": "0.9.0",
                    "time": {"created": NOW_MS, "updated": NOW_MS},
                }
            )
        )
        (storage / "message" / "ses_json1").mkdir(parents=True)
        (storage / "message" / "ses_json1" / "msg_1.json").write_text(json.dumps({"id": "msg_1", "role": "user"}))
        (storage / "part" / "msg_1").mkdir(parents=True)
        (storage / "part" / "msg_1" / "prt_1.json").write_text(
            json.dumps({"type": "text", "text": "hello from the json backend"})
        )

        entries = _make_opencode_parser(tmp_path).parse_all()

        assert len(entries) == 1
        assert entries[0].session_id == "opencode_json1"
        assert entries[0].project_path == "/home/dev/legacy"
        assert entries[0].chat_history[0].content == "hello from the json backend"

    def test_legacy_layout_with_embedded_parts(self, tmp_path):
        storage = tmp_path / "storage"
        (storage / "session" / "info").mkdir(parents=True)
        (storage / "session" / "info" / "ses_json2.json").write_text(
            json.dumps({"id": "ses_json2", "time": {"created": NOW_MS, "updated": NOW_MS}})
        )
        (storage / "session" / "message" / "ses_json2").mkdir(parents=True)
        (storage / "session" / "message" / "ses_json2" / "msg_1.json").write_text(
            json.dumps(
                {
                    "id": "msg_1",
                    "role": "assistant",
                    "parts": [
                        {"type": "text", "text": "running a command"},
                        {
                            "type": "tool-invocation",
                            "toolInvocation": {
                                "toolName": "bash",
                                "args": {"command": "pwd"},
                                "result": "/home/dev",
                                "state": "result",
                            },
                        },
                    ],
                }
            )
        )

        entry = _make_opencode_parser(tmp_path).parse_all()[0]

        assert entry.chat_history[0].content == "running a command"
        tool = entry.chat_history[0].tools[0]
        assert tool.tool_name == "bash"
        assert tool.status == "success"
        assert tool.result == "/home/dev"

    def test_json_age_filter(self, tmp_path):
        storage = tmp_path / "storage"
        (storage / "session" / "info").mkdir(parents=True)
        session_file = storage / "session" / "info" / "ses_old.json"
        session_file.write_text(json.dumps({"id": "ses_old"}))
        (storage / "session" / "message" / "ses_old").mkdir(parents=True)
        (storage / "session" / "message" / "ses_old" / "msg_1.json").write_text(
            json.dumps({"id": "msg_1", "role": "user", "parts": [{"type": "text", "text": "stale chatter"}]})
        )

        old_epoch = OLD_MS / 1000
        os.utime(session_file, (old_epoch, old_epoch))

        assert _make_opencode_parser(tmp_path, max_age_days=14).parse_all() == []
        assert len(_make_opencode_parser(tmp_path, max_age_days=0).parse_all()) == 1


class TestOpencodeToolClassification:
    @pytest.mark.parametrize("name", ["bash", "read", "web_search", "apply_patch", "todowrite"])
    def test_builtin_tools_are_function_calls(self, name):
        assert OpencodeParser._classify_tool(name) == ("function_call", None)

    def test_underscored_unknown_tool_is_mcp(self):
        assert OpencodeParser._classify_tool("linear_list_issues") == ("mcp_tool", "linear")

    def test_unknown_tool_without_underscore_is_function_call(self):
        assert OpencodeParser._classify_tool("mystery") == ("function_call", None)


def _write_agent_mode_session(org_dir, session_dir_name, audit_lines, metadata):
    """Write an agent-mode session directory plus its sibling metadata file."""
    org_dir.mkdir(parents=True, exist_ok=True)
    session_dir = org_dir / session_dir_name
    session_dir.mkdir()
    (session_dir / "audit.jsonl").write_text("\n".join(json.dumps(line) for line in audit_lines))
    (org_dir / f"{session_dir_name}.json").write_text(json.dumps(metadata))
    return session_dir


class TestClaudeDesktopParser:
    def test_parses_interactive_session(self, tmp_path):
        org_dir = tmp_path / "user-1" / "org-1"
        _write_agent_mode_session(
            org_dir,
            "local_11111111-2222-3333-4444-555555555555",
            audit_lines=[
                {
                    "type": "system",
                    "subtype": "init",
                    "tools": ["Bash", "Read"],
                    "mcp_servers": [{"name": "github"}],
                    "permissionMode": "acceptEdits",
                    "model": "claude-sonnet-4",
                    "claude_code_version": "2.1.0",
                    "plugins": ["reviewer"],
                    "skills": ["pdf"],
                },
                {"type": "user", "uuid": "u1", "message": {"content": "read the config"}},
                {
                    "type": "assistant",
                    "uuid": "a1",
                    "message": {
                        "content": [
                            {"type": "thinking", "thinking": "should be dropped"},
                            {"type": "text", "text": "Reading it now."},
                            {"type": "tool_use", "id": "t1", "name": "Read", "input": {"path": "config.yaml"}},
                        ]
                    },
                },
                {
                    "type": "user",
                    "uuid": "u2",
                    "message": {"content": [{"type": "tool_result", "tool_use_id": "t1", "content": "port: 8080"}]},
                },
            ],
            metadata={
                "sessionId": "local_11111111-2222-3333-4444-555555555555",
                "cwd": "/home/dev/project",
                "model": "claude-sonnet-4",
                "title": "Config review",
                "lastActivityAt": NOW_MS,
                "memoryEnabled": True,
                "skillsEnabled": False,
                "slashCommands": [{"name": "review"}, "deploy"],
            },
        )

        entries = ClaudeDesktopParser(base_path=str(tmp_path)).parse_all()

        assert len(entries) == 1
        entry = entries[0]
        assert entry.source == "claude_desktop"
        assert entry.session_id == "claude_desktop_11111111-2222-3333-4444-555555555555"
        assert entry.project_path == "/home/dev/project"

        assert [m.role for m in entry.chat_history] == ["user", "assistant"]
        assistant = entry.chat_history[1]
        # Thinking blocks are dropped; text and tool_use are kept.
        assert assistant.content == "Reading it now."
        assert assistant.tools[0].tool_name == "Read"
        # The later tool_result is back-filled onto the originating tool call.
        assert assistant.tools[0].result == "port: 8080"
        assert assistant.tools[0].status == "success"

        context = entry.session_context
        assert context["title"] == "Config review"
        assert context["init"]["claude_code_version"] == "2.1.0"
        assert context["init"]["plugins"] == ["reviewer"]
        assert context["memory_enabled"] is True
        assert context["skills_enabled"] is False
        assert context["available_slash_commands"] == ["review", "deploy"]
        assert "is_dispatch" not in context

    def test_parses_dispatch_session(self, tmp_path):
        org_dir = tmp_path / "user-1" / "org-1"
        _write_agent_mode_session(
            org_dir / "agent",
            "local_ditto_aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            audit_lines=[
                {"type": "user", "uuid": "u1", "message": {"content": "run the nightly checks"}},
                {"type": "assistant", "uuid": "a1", "message": {"content": [{"type": "text", "text": "On it."}]}},
            ],
            metadata={
                "sessionId": "local_ditto_aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "lastActivityAt": NOW_MS,
                "sessionType": "dispatch",
                "cliSessionId": "cli-99",
            },
        )

        entries = ClaudeDesktopParser(base_path=str(tmp_path)).parse_all()

        assert len(entries) == 1
        entry = entries[0]
        assert entry.source == "claude_desktop"
        assert entry.session_id == "claude_desktop_dispatch_aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        assert entry.session_context["is_dispatch"] is True
        assert entry.session_context["session_type"] == "dispatch"
        assert entry.session_context["cli_session_id"] == "cli-99"

    def test_discovers_interactive_and_dispatch_together(self, tmp_path):
        org_dir = tmp_path / "user-1" / "org-1"
        conversation = [
            {"type": "user", "uuid": "u1", "message": {"content": "a question worth keeping"}},
            {"type": "assistant", "uuid": "a1", "message": {"content": [{"type": "text", "text": "an answer"}]}},
        ]
        _write_agent_mode_session(
            org_dir, "local_aaaa", conversation, {"sessionId": "local_aaaa", "lastActivityAt": NOW_MS}
        )
        _write_agent_mode_session(
            org_dir / "agent",
            "local_ditto_bbbb",
            conversation,
            {"sessionId": "local_ditto_bbbb", "lastActivityAt": NOW_MS},
        )

        session_ids = {e.session_id for e in ClaudeDesktopParser(base_path=str(tmp_path)).parse_all()}
        assert session_ids == {"claude_desktop_aaaa", "claude_desktop_dispatch_bbbb"}

    def test_skips_sessions_older_than_max_age(self, tmp_path):
        org_dir = tmp_path / "user-1" / "org-1"
        _write_agent_mode_session(
            org_dir,
            "local_stale",
            audit_lines=[
                {"type": "user", "uuid": "u1", "message": {"content": "an ancient question"}},
                {"type": "assistant", "uuid": "a1", "message": {"content": [{"type": "text", "text": "reply"}]}},
            ],
            metadata={"sessionId": "local_stale", "lastActivityAt": OLD_MS},
        )

        assert ClaudeDesktopParser(base_path=str(tmp_path)).parse_all() == []
        assert len(ClaudeDesktopParser(base_path=str(tmp_path), max_age_days=100).parse_all()) == 1

    def test_missing_metadata_still_parses_audit_log(self, tmp_path):
        org_dir = tmp_path / "user-1" / "org-1"
        org_dir.mkdir(parents=True)
        session_dir = org_dir / "local_nometa"
        session_dir.mkdir()
        (session_dir / "audit.jsonl").write_text(
            "\n".join(
                json.dumps(line)
                for line in [
                    {"type": "user", "uuid": "u1", "message": {"content": "no metadata here"}},
                    {"type": "assistant", "uuid": "a1", "message": {"content": [{"type": "text", "text": "ok"}]}},
                ]
            )
        )

        entries = ClaudeDesktopParser(base_path=str(tmp_path)).parse_all()

        assert len(entries) == 1
        assert entries[0].session_id == "claude_desktop_nometa"
        assert entries[0].session_context is None

    def test_malformed_lines_are_skipped(self, tmp_path):
        org_dir = tmp_path / "user-1" / "org-1"
        org_dir.mkdir(parents=True)
        session_dir = org_dir / "local_broken"
        session_dir.mkdir()
        (session_dir / "audit.jsonl").write_text(
            "not json\n"
            + json.dumps({"type": "user", "uuid": "u1", "message": {"content": "a valid question"}})
            + "\n\n"
            + json.dumps({"type": "rate_limit_event", "uuid": "r1"})
            + "\n"
            + json.dumps({"type": "assistant", "uuid": "a1", "message": {"content": [{"type": "text", "text": "y"}]}})
        )
        (org_dir / "local_broken.json").write_text("{ not valid json")

        entries = ClaudeDesktopParser(base_path=str(tmp_path)).parse_all()

        assert len(entries) == 1
        assert len(entries[0].chat_history) == 2

    def test_parse_all_no_base_path(self, tmp_path):
        assert ClaudeDesktopParser(base_path=str(tmp_path / "missing")).parse_all() == []

    def test_default_max_age_days(self):
        assert ClaudeDesktopParser().max_age_days == 14



class TestPlatformPathCoverage:
    """Each parser must probe every platform its agent ships on.

    These agents are installed at different locations per OS, and a missing
    candidate path means the source is silently invisible on that platform.
    """

    def test_cursor_covers_macos_linux_and_windows(self):
        paths = [str(p) for p in CursorParser.DB_PATHS]
        assert any("Library/Application Support" in p for p in paths)  # macOS
        assert any("/.config/" in p for p in paths)  # Linux
        # Windows root comes from %APPDATA% (redirected-profile safe), not a hardcoded guess.
        assert windows_appdata() / "Cursor/User/globalStorage/state.vscdb" in CursorParser.DB_PATHS
        assert all(p.endswith("Cursor/User/globalStorage/state.vscdb") for p in paths)

    def test_cline_covers_macos_linux_and_windows(self):
        paths = [str(p) for p in ClineParser.BASE_PATHS]
        assert any("Library/Application Support" in p for p in paths)  # macOS
        assert any("/.config/" in p for p in paths)  # Linux
        assert (
            windows_appdata() / "Cursor/User/globalStorage/saoudrizwan.claude-dev/tasks"
            in ClineParser.BASE_PATHS
        )
        assert all(p.endswith("saoudrizwan.claude-dev/tasks") for p in paths)

    def test_warp_covers_both_macos_locations_and_windows(self):
        paths = [str(p) for p in WarpParser.DB_PATHS]
        assert any("Group Containers/2BBY89MBSN.dev.warp" in p for p in paths)  # macOS sandboxed
        assert any(p.endswith("Library/Application Support/dev.warp.Warp-Stable/warp.sqlite") for p in paths)
        assert windows_local_appdata() / "warp/Warp/data/warp.sqlite" in WarpParser.DB_PATHS
        assert all(p.endswith("warp.sqlite") for p in paths)

    def test_claude_desktop_covers_macos_and_windows(self):
        from adr_sensor.parsers.claude_desktop_parser import DEFAULT_BASE_PATHS

        assert any("Library/Application Support" in str(p) for p in DEFAULT_BASE_PATHS)  # macOS
        assert windows_appdata() / "Claude/local-agent-mode-sessions" in DEFAULT_BASE_PATHS

    def test_opencode_covers_xdg_and_macos(self, monkeypatch):
        monkeypatch.delenv("XDG_DATA_HOME", raising=False)
        paths = [str(p) for p in OpencodeParser._candidate_base_dirs()]
        assert any(p.endswith(".local/share/opencode") for p in paths)  # Linux + macOS default
        assert any("Library/Application Support/opencode" in p for p in paths)  # macOS fallback

    @pytest.mark.parametrize(
        ("parser_cls", "attr"),
        [(CursorParser, "DB_PATHS"), (ClineParser, "BASE_PATHS"), (WarpParser, "DB_PATHS")],
    )
    def test_first_candidate_used_when_none_exist(self, parser_cls, attr):
        """With no agent installed the parser reports the primary path, not a crash."""
        parser = parser_cls()
        resolved = getattr(parser, "db_path", None) or parser.base_path
        assert resolved == getattr(parser_cls, attr)[0]

    def test_existing_path_wins_over_earlier_candidates(self, tmp_path, monkeypatch):
        """A later candidate is selected when it is the one that exists on disk."""
        windows_db = tmp_path / "AppData/Roaming/Cursor/User/globalStorage/state.vscdb"
        windows_db.parent.mkdir(parents=True)
        windows_db.touch()
        monkeypatch.setattr(
            CursorParser,
            "DB_PATHS",
            [tmp_path / "nonexistent/state.vscdb", windows_db],
        )
        assert CursorParser().db_path == windows_db


class TestWindowsAppDataResolution:
    """%APPDATA% / %LOCALAPPDATA% must win over the profile-relative default.

    On roaming-profile and redirected-folder setups these roots live outside
    the user profile, so hardcoding ~/AppData/... silently finds nothing
    (the failure mode reported in issue #21; env-first fix adopted from #25).
    """

    def test_appdata_env_var_wins(self, monkeypatch, tmp_path):
        monkeypatch.setenv("APPDATA", str(tmp_path / "Redirected/Roaming"))
        assert windows_appdata() == tmp_path / "Redirected/Roaming"

    def test_appdata_falls_back_to_profile_default(self, monkeypatch):
        monkeypatch.delenv("APPDATA", raising=False)
        assert windows_appdata() == Path.home() / "AppData/Roaming"

    def test_empty_appdata_treated_as_unset(self, monkeypatch):
        monkeypatch.setenv("APPDATA", "")
        assert windows_appdata() == Path.home() / "AppData/Roaming"

    def test_localappdata_env_var_wins(self, monkeypatch, tmp_path):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "Redirected/Local"))
        assert windows_local_appdata() == tmp_path / "Redirected/Local"

    def test_localappdata_falls_back_to_profile_default(self, monkeypatch):
        monkeypatch.delenv("LOCALAPPDATA", raising=False)
        assert windows_local_appdata() == Path.home() / "AppData/Local"

    def test_redirected_appdata_end_to_end(self, tmp_path, monkeypatch):
        """A Cursor DB under a redirected %APPDATA% (outside the profile) is found."""
        redirected = tmp_path / "fileserver/profiles$/alice/AppData/Roaming"
        db = redirected / "Cursor/User/globalStorage/state.vscdb"
        db.parent.mkdir(parents=True)
        db.touch()

        monkeypatch.setenv("APPDATA", str(redirected))

        windows_db = windows_appdata() / "Cursor/User/globalStorage/state.vscdb"
        assert windows_db == db

        # Isolate this Windows-path test from real Cursor installations on the host.
        monkeypatch.setattr(
            CursorParser,
            "DB_PATHS",
            [
                tmp_path / "missing-macos/state.vscdb",
                tmp_path / "missing-linux/state.vscdb",
                windows_db,
            ],
        )

        assert CursorParser().db_path == db
