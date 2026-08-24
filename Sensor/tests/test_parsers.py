"""Tests for ADR Sensor parsers."""

import hashlib
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
    @staticmethod
    def _parse_events(tmp_path, events):
        jsonl_file = tmp_path / "rollout-rich.jsonl"
        records = [{"type": "session_meta", "payload": {"id": "rich-session"}}, *events]
        jsonl_file.write_text("\n".join(json.dumps(record) for record in records), encoding="utf-8")
        entry = CodexParser().parse_jsonl_file(jsonl_file)
        assert entry is not None
        return entry

    @staticmethod
    def _tools(entry):
        return [tool for message in entry.chat_history for tool in message.tools]

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

    def test_standalone_rich_command_is_normalized(self, tmp_path):
        entry = self._parse_events(
            tmp_path,
            [
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "item_completed",
                        "turn_id": "turn-a",
                        "item": {
                            "type": "CommandExecution",
                            "command": ["sh", "-lc", "printf ready"],
                            "cwd": "/workspace/sample",
                            "status": "completed",
                            "aggregated_output": "ready",
                            "formatted_output": "secondary output",
                            "stdout": "fallback output",
                            "exit_code": 0,
                            "duration": {"secs": 1, "nanos": 250_000_000},
                        },
                    },
                }
            ],
        )

        tool = self._tools(entry)[0]
        assert tool.tool_name == "exec_command"
        assert tool.tool_type == "function_call"
        assert tool.arguments == {
            "command": ["sh", "-lc", "printf ready"],
            "cwd": "/workspace/sample",
            "_codex": {"duration": {"secs": 1, "nanos": 250_000_000}},
        }
        assert tool.result == "ready"
        assert tool.status == "success"
        assert tool.error is None

    @pytest.mark.parametrize(
        ("item", "expected_result", "expected_status", "expected_error", "expected_duration"),
        [
            (
                {
                    "type": "command_execution",
                    "cmd": "printf waiting",
                    "workdir": "/workspace/alias",
                    "state": "inProgress",
                    "aggregatedOutput": "waiting",
                    "durationMs": 25,
                },
                "waiting",
                "pending",
                None,
                25,
            ),
            (
                {
                    "type": "commandExecution",
                    "argv": ["sample-command", "--check"],
                    "workingDirectory": "/workspace/alias",
                    "standardOutput": "partial output",
                    "standardError": "failure detail",
                    "exitCode": 2,
                    "duration": "short",
                },
                "partial output\nfailure detail",
                "error",
                "Exit code: 2",
                "short",
            ),
            (
                {
                    "type": "command-execution",
                    "command": "sample-command --approve",
                    "status": "declined",
                    "errorMessage": "approval declined",
                },
                None,
                "error",
                "approval declined",
                None,
            ),
        ],
    )
    def test_rich_command_aliases_outputs_status_and_duration(
        self,
        tmp_path,
        item,
        expected_result,
        expected_status,
        expected_error,
        expected_duration,
    ):
        entry = self._parse_events(
            tmp_path,
            [{"type": "eventMsg", "payload": {"type": "itemCompleted", "item": item}}],
        )

        tool = self._tools(entry)[0]
        assert tool.result == expected_result
        assert tool.status == expected_status
        assert tool.error == expected_error
        if expected_duration is None:
            assert "_codex" not in tool.arguments
        else:
            assert tool.arguments["_codex"]["duration"] == expected_duration

    def test_standalone_file_change_hashes_private_bodies(self, tmp_path):
        content = "private body\nwith unicode: café"
        unified_diff = "@@ -1 +1 @@\n-old\n+new\n"
        entry = self._parse_events(
            tmp_path,
            [
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "item_completed",
                        "item": {
                            "type": "FileChange",
                            "changes": {
                                "src/added.txt": {"type": "add", "content": content},
                                "src/current.txt": {
                                    "type": "update",
                                    "move_path": "src/moved.txt",
                                    "unified_diff": unified_diff,
                                },
                            },
                            "status": "completed",
                            "stdout": "changes applied",
                        },
                    },
                }
            ],
        )

        tool = self._tools(entry)[0]
        assert tool.tool_name == "file_change"
        assert tool.tool_type == "function_call"
        assert tool.arguments == {
            "changes": [
                {
                    "path": "src/added.txt",
                    "type": "add",
                    "content": {
                        "utf8_bytes": len(content.encode("utf-8")),
                        "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
                    },
                },
                {
                    "path": "src/current.txt",
                    "type": "update",
                    "move_path": "src/moved.txt",
                    "unified_diff": {
                        "utf8_bytes": len(unified_diff.encode("utf-8")),
                        "sha256": hashlib.sha256(unified_diff.encode("utf-8")).hexdigest(),
                    },
                },
            ]
        }
        serialized_arguments = json.dumps(tool.arguments)
        assert content not in serialized_arguments
        assert unified_diff not in serialized_arguments
        assert tool.result == "changes applied"
        assert tool.status == "success"

    def test_file_change_aliases_are_canonicalized(self, tmp_path):
        unified_diff = "@@ sample @@"
        entry = self._parse_events(
            tmp_path,
            [
                {
                    "type": "event-msg",
                    "payload": {
                        "type": "item-completed",
                        "item": {
                            "type": "file_change",
                            "fileChanges": [
                                {
                                    "filePath": "src/original.txt",
                                    "changeType": "Modified",
                                    "newPath": "src/renamed.txt",
                                    "unifiedDiff": unified_diff,
                                }
                            ],
                            "status": "failed",
                            "standardError": "change rejected",
                        },
                    },
                }
            ],
        )

        tool = self._tools(entry)[0]
        assert tool.arguments["changes"] == [
            {
                "path": "src/original.txt",
                "type": "update",
                "move_path": "src/renamed.txt",
                "unified_diff": {
                    "utf8_bytes": len(unified_diff.encode("utf-8")),
                    "sha256": hashlib.sha256(unified_diff.encode("utf-8")).hexdigest(),
                },
            }
        ]
        assert tool.result == "change rejected"
        assert tool.status == "error"
        assert tool.error == "change rejected"

    def test_rich_action_collections_and_text_are_bounded(self, tmp_path):
        long_path = "src/" + "p" * 5000 + ".txt"
        changes = {
            long_path: {
                "type": "update",
                "move_path": "dst/" + "m" * 5000 + ".txt",
                "unified_diff": "private diff",
            }
        }
        changes.update(
            {
                f"src/file-{index}.txt": {"type": "add", "content": f"body-{index}"}
                for index in range(104)
            }
        )
        entry = self._parse_events(
            tmp_path,
            [
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "item_completed",
                        "item": {
                            "type": "CommandExecution",
                            "command": ["x" * 5000, *[f"arg-{index}" for index in range(104)]],
                            "cwd": "/workspace/" + "c" * 5000,
                            "status": "completed",
                        },
                    },
                },
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "item_completed",
                        "item": {
                            "type": "FileChange",
                            "changes": changes,
                            "status": "completed",
                        },
                    },
                },
            ],
        )

        command, file_change = self._tools(entry)
        assert len(command.arguments["command"]) == 100
        assert "[truncated" in command.arguments["command"][0]
        assert "[truncated" in command.arguments["cwd"]
        assert len(file_change.arguments["changes"]) == 100
        assert file_change.arguments["_codex"]["truncated_changes"] == 5
        assert "[truncated" in file_change.arguments["changes"][0]["path"]
        assert "[truncated" in file_change.arguments["changes"][0]["move_path"]

    def test_malformed_and_unsupported_rich_records_are_skipped(self, tmp_path):
        entry = self._parse_events(
            tmp_path,
            [
                {"type": "event_msg", "payload": {"type": "item_completed", "item": None}},
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "item_completed",
                        "item": {"type": "CommandExecution", "command": {"unexpected": "value"}},
                    },
                },
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "item_completed",
                        "item": {"type": "FileChange", "changes": [None, "unsupported"]},
                    },
                },
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "item_completed",
                        "item": {"type": "McpToolCall", "tool": "lookup"},
                    },
                },
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "item_completed",
                        "item": {"type": "CollabAgentToolCall", "tool": "delegate"},
                    },
                },
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "item_completed",
                        "item": {
                            "type": "CommandExecution",
                            "command": "printf valid",
                            "status": "completed",
                        },
                    },
                },
            ],
        )

        tools = self._tools(entry)
        assert len(tools) == 1
        assert tools[0].arguments["command"] == "printf valid"

    def test_agent_messages_capture_adjacent_trigger_and_plaintext_only(self, tmp_path):
        def agent_message(text, encrypted_text=None):
            content = []
            if text is not None:
                content.extend(
                    [
                        {"type": "input_text", "text": text[0]},
                        {"type": "output_text", "text": "ignored output"},
                        {"type": "input_text", "text": text[1]},
                    ]
                )
            if encrypted_text is not None:
                content.append(
                    {"type": "encrypted_content", "encrypted_content": encrypted_text}
                )
            return {
                "type": "response_item",
                "payload": {
                    "type": "agent_message",
                    "author": "worker-a",
                    "recipient": "worker-b",
                    "content": content,
                },
            }

        entry = self._parse_events(
            tmp_path,
            [
                {"type": "inter_agent_communication_metadata", "payload": {"trigger_turn": True}},
                agent_message(("triggered ", "message"), "encrypted-triggered"),
                {"type": "inter_agent_communication_metadata", "payload": {"trigger_turn": False}},
                agent_message(("untriggered ", "message"), "encrypted-untriggered"),
                {"type": "inter_agent_communication_metadata", "payload": {"trigger_turn": True}},
                {"type": "event_msg", "payload": {"type": "token_count"}},
                agent_message(("nonadjacent ", "message")),
                {"type": "inter_agent_communication_metadata", "payload": {"trigger_turn": True}},
                "malformed record",
                agent_message(("after malformed ", "message")),
                {"type": "inter_agent_communication_metadata", "payload": {"trigger_turn": True}},
                agent_message(None, "opaque-cipher-only"),
                agent_message(("after encrypted-only ", "message")),
            ],
        )

        assert [(message.role, message.content) for message in entry.chat_history] == [
            (
                "user",
                '[agent_message author="worker-a" recipient="worker-b" trigger_turn=true]\n'
                "triggered message",
            ),
            (
                "user",
                '[agent_message author="worker-a" recipient="worker-b" trigger_turn=false]\n'
                "untriggered message",
            ),
            (
                "user",
                '[agent_message author="worker-a" recipient="worker-b" trigger_turn=false]\n'
                "nonadjacent message",
            ),
            (
                "user",
                '[agent_message author="worker-a" recipient="worker-b" trigger_turn=false]\n'
                "after malformed message",
            ),
            (
                "user",
                '[agent_message author="worker-a" recipient="worker-b" trigger_turn=false]\n'
                "after encrypted-only message",
            ),
        ]
        serialized = entry.to_json()
        assert "encrypted-triggered" not in serialized
        assert "encrypted-untriggered" not in serialized
        assert "opaque-cipher-only" not in serialized
        assert "ignored output" not in serialized

    def test_agent_message_parties_are_bounded_and_malformed_values_use_null(self, tmp_path):
        long_author = "a" * 5000
        long_recipient = "r" * 5000
        entry = self._parse_events(
            tmp_path,
            [
                {
                    "type": "response_item",
                    "payload": {
                        "type": "agent_message",
                        "author": long_author,
                        "recipient": long_recipient,
                        "content": [{"type": "input_text", "text": "bounded parties"}],
                    },
                },
                {
                    "type": "response_item",
                    "payload": {
                        "type": "agent_message",
                        "author": {"unexpected": "mapping"},
                        "recipient": ["unexpected", "list"],
                        "content": [{"type": "input_text", "text": "malformed parties"}],
                    },
                },
            ],
        )

        prefix = entry.chat_history[0].content.split("\n", 1)[0]
        author_json = prefix[len("[agent_message author=") : prefix.index(" recipient=")]
        recipient_start = prefix.index(" recipient=") + len(" recipient=")
        recipient_json = prefix[recipient_start : prefix.index(" trigger_turn=")]
        assert len(json.loads(author_json)) <= 100
        assert len(json.loads(recipient_json)) <= 100
        assert "[truncated" in json.loads(author_json)
        assert "[truncated" in json.loads(recipient_json)
        assert entry.chat_history[1].content == (
            "[agent_message author=null recipient=null trigger_turn=false]\nmalformed parties"
        )

    def test_subagent_activity_enriches_pending_function_call_without_duplicate(self, tmp_path):
        entry = self._parse_events(
            tmp_path,
            [
                {
                    "type": "response_item",
                    "payload": {
                        "type": "function_call",
                        "toolCallID": "activity-call",
                        "name": "delegate_work",
                        "arguments": {"task": "inspect sample"},
                    },
                },
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "item_completed",
                        "item": {
                            "type": "SubAgentActivity",
                            "call_id": "activity-call",
                            "kind": "started",
                            "agent_thread_id": "thread-child",
                            "agent_path": "/worker/child",
                            "encrypted_content": "not-retained",
                        },
                    },
                },
            ],
        )

        tools = self._tools(entry)
        assert len(tools) == 1
        assert tools[0].tool_name == "delegate_work"
        assert tools[0].status == "success"
        assert tools[0].arguments == {
            "task": "inspect sample",
            "_codex": {
                "subagent_activity": {
                    "kind": "started",
                    "agent_thread_id": "thread-child",
                    "agent_path": "/worker/child",
                }
            },
        }
        assert "not-retained" not in entry.to_json()

    def test_legacy_top_level_subagent_activity_uses_event_id(self, tmp_path):
        entry = self._parse_events(
            tmp_path,
            [
                {
                    "type": "response_item",
                    "payload": {
                        "type": "function_call",
                        "call_id": "legacy-activity",
                        "name": "delegate_work",
                        "arguments": {"task": "inspect sample"},
                    },
                },
                {
                    "type": "sub_agent_activity",
                    "event_id": "legacy-activity",
                    "payload": {
                        "kind": "started",
                        "agent_thread_id": "thread-child",
                        "agent_path": "/worker/child",
                    },
                },
            ],
        )

        tools = self._tools(entry)

        assert len(tools) == 1
        assert tools[0].tool_name == "delegate_work"
        assert tools[0].status == "success"
        assert tools[0].arguments["_codex"]["subagent_activity"] == {
            "kind": "started",
            "agent_thread_id": "thread-child",
            "agent_path": "/worker/child",
        }

    def test_unmatched_subagent_activity_emits_standalone_tool(self, tmp_path):
        entry = self._parse_events(
            tmp_path,
            [
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "item_completed",
                        "item": {
                            "type": "sub_agent_activity",
                            "itemId": "standalone-activity",
                            "kind": "interacted",
                            "agent_thread_id": "thread-standalone",
                            "agent_path": "/worker/standalone",
                        },
                    },
                }
            ],
        )

        assert entry.source == "codex"
        assert entry.session_id == "codex_rich-session"
        tool = self._tools(entry)[0]
        assert tool.tool_name == "subagent_activity"
        assert tool.tool_type == "function_call"
        assert tool.status == "success"
        assert tool.result is None
        assert tool.error is None
        assert tool.arguments == {
            "_codex": {
                "subagent_activity": {
                    "kind": "interacted",
                    "agent_thread_id": "thread-standalone",
                    "agent_path": "/worker/standalone",
                }
            }
        }

    def test_top_level_rich_mcp_success_preserves_metadata(self, tmp_path):
        entry = self._parse_events(
            tmp_path,
            [
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "mcp_tool_call_end",
                        "call_id": "direct-call",
                        "invocation": {
                            "server": "catalog-server",
                            "tool": "lookup_record",
                            "arguments": {"record_id": "record-1"},
                        },
                        "connector_id": "connector-1",
                        "link_id": "link-1",
                        "app_name": "Catalog",
                        "action_name": "Lookup",
                        "read_only_hint": True,
                        "duration": {"secs": 1, "nanos": 5},
                        "result": {
                            "Ok": {
                                "content": [{"type": "text", "text": '{"found":true}'}],
                                "isError": False,
                            }
                        },
                    },
                }
            ],
        )

        tool = self._tools(entry)[0]
        assert (tool.server_name, tool.tool_name, tool.tool_type) == (
            "catalog-server",
            "lookup_record",
            "mcp_tool",
        )
        assert tool.arguments == {
            "record_id": "record-1",
            "_codex": {
                "duration": {"secs": 1, "nanos": 5},
                "read_only_hint": True,
                "connector": {
                    "connector_id": "connector-1",
                    "link_id": "link-1",
                    "app_name": "Catalog",
                    "action_name": "Lookup",
                },
            },
        }
        assert tool.result == '{"found":true}'
        assert tool.status == "success"
        assert tool.error is None

    def test_item_completed_rich_mcp_structured_error(self, tmp_path):
        entry = self._parse_events(
            tmp_path,
            [
                {
                    "type": "eventMsg",
                    "payload": {
                        "type": "itemCompleted",
                        "item": {
                            "type": "McpToolCallEnd",
                            "id": "failed-call",
                            "toolCall": {
                                "serverName": "records-server",
                                "toolName": "update_record",
                                "args": '{"record_id":"record-2"}',
                            },
                            "status": "failed",
                            "result": {
                                "content": [{"type": "text", "text": "request rejected"}],
                                "isError": True,
                            },
                            "error": {"message": "request rejected", "code": "denied"},
                        },
                    },
                }
            ],
        )

        tool = self._tools(entry)[0]
        assert (tool.server_name, tool.tool_name) == ("records-server", "update_record")
        assert tool.arguments == {"record_id": "record-2"}
        assert tool.result == "request rejected"
        assert tool.status == "error"
        assert tool.error == "request rejected"

    @pytest.mark.parametrize(
        ("argument_key", "raw_arguments", "expected"),
        [
            ("arguments", {"record_id": "record-3"}, {"record_id": "record-3"}),
            ("args", '{"record_id":"record-4"}', {"record_id": "record-4"}),
            ("input", ["record-5", 5], {"raw": ["record-5", 5]}),
            ("params", "opaque input", {"raw": "opaque input"}),
            ("parameters", None, {}),
        ],
    )
    def test_rich_mcp_argument_shapes_are_normalized(
        self, tmp_path, argument_key, raw_arguments, expected
    ):
        invocation = {
            "server_name": "shape-server",
            "tool_name": "inspect_record",
            argument_key: raw_arguments,
        }
        entry = self._parse_events(
            tmp_path,
            [
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "mcp_tool_call_end",
                        "call": invocation,
                        "result": {"Ok": {"content": []}},
                    },
                }
            ],
        )

        assert self._tools(entry)[0].arguments == expected

    def test_rich_mcp_metadata_is_scalar_only_and_bounded(self, tmp_path):
        entry = self._parse_events(
            tmp_path,
            [
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "item_completed",
                        "item": {
                            "type": "McpToolCall",
                            "id": "bounded-call",
                            "server": "metadata-server",
                            "tool": "inspect_record",
                            "arguments": {},
                            "connectorId": "c" * 5000,
                            "linkId": {"unsupported": "mapping"},
                            "appName": 7,
                            "actionName": False,
                            "readOnlyHint": False,
                            "durationMs": {
                                "samples": list(range(150)),
                                "detail": "d" * 5000,
                            },
                            "status": "completed",
                            "result": {
                                "content": [{"type": "text", "text": "inspection complete"}],
                                "isError": False,
                            },
                        },
                    },
                }
            ],
        )

        tool = self._tools(entry)[0]
        metadata = tool.arguments["_codex"]
        assert len(metadata["duration"]["samples"]) == 100
        assert "[truncated" in metadata["duration"]["detail"]
        assert metadata["read_only_hint"] is False
        assert "[truncated" in metadata["connector"]["connector_id"]
        assert metadata["connector"]["app_name"] == 7
        assert metadata["connector"]["action_name"] is False
        assert "link_id" not in metadata["connector"]
        assert tool.result == "inspection complete"
        assert tool.status == "success"
        assert tool.error is None

    @pytest.mark.parametrize("wrapper_server", ["bridge-alpha", "bridge-beta"])
    def test_rich_mcp_structural_wrapper_reports_effective_target(
        self, tmp_path, wrapper_server
    ):
        entry = self._parse_events(
            tmp_path,
            [
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "mcp_tool_call_end",
                        "call_id": "wrapped-call",
                        "invocation": {
                            "server": wrapper_server,
                            "tool": "invokeTool",
                            "arguments": {
                                "targetServer": "effective-server",
                                "targetTool": "inspect_record",
                                "params": '{"record_id":"record-6"}',
                            },
                        },
                        "result": {"Err": {"message": "inspection denied"}},
                    },
                }
            ],
        )

        tool = self._tools(entry)[0]
        assert (tool.server_name, tool.tool_name) == ("effective-server", "inspect_record")
        assert tool.arguments == {
            "record_id": "record-6",
            "_codex_mcp_wrapper": {
                "server_name": wrapper_server,
                "tool_name": "invokeTool",
            },
        }
        assert tool.status == "error"
        assert tool.error == "inspection denied"

    def test_invoke_tool_without_nested_arguments_is_not_unwrapped(self, tmp_path):
        entry = self._parse_events(
            tmp_path,
            [
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "mcp_tool_call_end",
                        "invocation": {
                            "server": "bridge-server",
                            "tool": "invoke_tool",
                            "arguments": {
                                "target_server": "effective-server",
                                "target_tool": "inspect_record",
                            },
                        },
                        "result": {"Ok": {"content": []}},
                    },
                }
            ],
        )

        tool = self._tools(entry)[0]
        assert (tool.server_name, tool.tool_name) == ("bridge-server", "invoke_tool")
        assert "_codex_mcp_wrapper" not in tool.arguments

    def test_malformed_rich_mcp_records_are_skipped(self, tmp_path):
        entry = self._parse_events(
            tmp_path,
            [
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "mcp_tool_call_end",
                        "invocation": {"server": " ", "tool": "inspect_record"},
                    },
                },
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "mcp_tool_call_end",
                        "server": "records-server",
                        "tool": "",
                    },
                },
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "item_completed",
                        "item": {
                            "type": "McpToolCall",
                            "server": "records-server",
                            "tool": ["unsupported"],
                        },
                    },
                },
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "item_completed",
                        "item": {
                            "type": "CollabAgentToolCall",
                            "server": "ignored-server",
                            "tool": "ignored_tool",
                        },
                    },
                },
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "mcp_tool_call_end",
                        "serverName": "valid-server",
                        "toolName": "valid_tool",
                        "arguments": {},
                        "result": {"Ok": {"content": []}},
                    },
                },
            ],
        )

        tools = self._tools(entry)
        assert len(tools) == 1
        assert (tools[0].server_name, tools[0].tool_name) == ("valid-server", "valid_tool")

    def test_shared_call_id_reconciles_classic_mcp_in_place(self, tmp_path):
        entry = self._parse_events(
            tmp_path,
            [
                {
                    "type": "response_item",
                    "payload": {
                        "type": "function_call",
                        "call_id": "before-call",
                        "name": "before_tool",
                        "arguments": {},
                    },
                },
                {
                    "type": "response_item",
                    "payload": {
                        "type": "function_call",
                        "toolCallID": "shared-call",
                        "name": "mcp__legacy-server__lookup_record",
                        "arguments": {"record_id": "classic"},
                    },
                },
                {
                    "type": "response_item",
                    "payload": {
                        "type": "function_call",
                        "call_id": "after-call",
                        "name": "after_tool",
                        "arguments": {},
                    },
                },
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "mcp_tool_call_end",
                        "id": "shared-call",
                        "invocation": {
                            "server": "effective-server",
                            "tool": "lookup_record",
                            "arguments": {"record_id": "rich"},
                        },
                        "result": {"Ok": {"content": [{"type": "text", "text": "found"}]}},
                    },
                },
            ],
        )

        tools = self._tools(entry)
        assert [tool.tool_name for tool in tools] == [
            "before_tool",
            "lookup_record",
            "after_tool",
        ]
        assert tools[1].server_name == "effective-server"
        assert tools[1].arguments == {"record_id": "rich"}
        assert tools[1].result == "found"
        assert tools[1].status == "success"

    def test_exact_signature_reconciles_rich_mcp_without_call_id(self, tmp_path):
        entry = self._parse_events(
            tmp_path,
            [
                {
                    "type": "response_item",
                    "payload": {
                        "type": "function_call",
                        "call_id": "classic-only-id",
                        "name": "mcp__records-server__lookup_record",
                        "arguments": {"record_id": "sample"},
                    },
                },
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "mcp_tool_call_end",
                        "invocation": {
                            "server": "records-server",
                            "tool": "lookup_record",
                            "arguments": {"record_id": "sample"},
                        },
                        "result": {"Ok": {"content": [{"type": "text", "text": "found"}]}},
                    },
                },
            ],
        )

        tools = self._tools(entry)

        assert len(tools) == 1
        assert tools[0].tool_name == "lookup_record"
        assert tools[0].server_name == "records-server"
        assert tools[0].result == "found"

    def test_namespace_classic_mcp_reconciles_with_rich_record(self, tmp_path):
        entry = self._parse_events(
            tmp_path,
            [
                {
                    "type": "response_item",
                    "payload": {
                        "type": "function_call",
                        "call_id": "classic-only-id",
                        "namespace": "mcp__queryrunner_mcp",
                        "name": "run_query",
                        "arguments": {"query": "SELECT 1"},
                    },
                },
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "mcp_tool_call_end",
                        "invocation": {
                            "server": "queryrunner_mcp",
                            "tool": "run_query",
                            "arguments": {"query": "SELECT 1"},
                        },
                        "result": {"Ok": {"content": [{"type": "text", "text": "one"}]}},
                    },
                },
            ],
        )

        tools = self._tools(entry)

        assert len(tools) == 1
        assert (tools[0].server_name, tools[0].tool_name) == ("queryrunner_mcp", "run_query")
        assert tools[0].result == "one"

    def test_signature_fallback_does_not_cross_a_later_call_boundary(self, tmp_path):
        entry = self._parse_events(
            tmp_path,
            [
                {
                    "type": "response_item",
                    "payload": {
                        "type": "function_call",
                        "call_id": "classic-only-id",
                        "name": "mcp__records-server__lookup_record",
                        "arguments": {"record_id": "sample"},
                    },
                },
                {
                    "type": "response_item",
                    "payload": {
                        "type": "function_call",
                        "call_id": "later-call",
                        "name": "other_tool",
                        "arguments": {},
                    },
                },
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "mcp_tool_call_end",
                        "invocation": {
                            "server": "records-server",
                            "tool": "lookup_record",
                            "arguments": {"record_id": "sample"},
                        },
                        "result": {"Ok": {"content": []}},
                    },
                },
            ],
        )

        assert [tool.tool_name for tool in self._tools(entry)] == [
            "mcp__records-server__lookup_record",
            "other_tool",
            "lookup_record",
        ]

    def test_unrelated_classic_and_rich_mcp_calls_remain_separate(self, tmp_path):
        entry = self._parse_events(
            tmp_path,
            [
                {
                    "type": "response_item",
                    "payload": {
                        "type": "function_call",
                        "call_id": "classic-call",
                        "name": "mcp__records-server__lookup_record",
                        "arguments": {"record_id": "classic"},
                    },
                },
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "mcp_tool_call_end",
                        "call_id": "rich-call",
                        "invocation": {
                            "server": "records-server",
                            "tool": "lookup_record",
                            "arguments": {"record_id": "rich"},
                        },
                        "result": {"Ok": {"content": []}},
                    },
                },
            ],
        )

        tools = self._tools(entry)
        assert [tool.tool_name for tool in tools] == [
            "mcp__records-server__lookup_record",
            "lookup_record",
        ]
        assert [tool.arguments["record_id"] for tool in tools] == ["classic", "rich"]

    def test_signature_fallback_preserves_mcp_name_punctuation(self, tmp_path):
        entry = self._parse_events(
            tmp_path,
            [
                {
                    "type": "response_item",
                    "payload": {
                        "type": "function_call",
                        "call_id": "classic-only-id",
                        "name": "mcp__a-b__lookup_record",
                        "arguments": {"record_id": "sample"},
                    },
                },
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "mcp_tool_call_end",
                        "invocation": {
                            "server": "ab",
                            "tool": "lookup_record",
                            "arguments": {"record_id": "sample"},
                        },
                        "result": {"Ok": {"content": []}},
                    },
                },
            ],
        )

        tools = self._tools(entry)

        assert len(tools) == 2
        assert [tool.server_name for tool in tools] == ["a-b", "ab"]

    def test_rich_command_replaces_matching_custom_wrapper(self, tmp_path):
        entry = self._parse_events(
            tmp_path,
            [
                {
                    "type": "response_item",
                    "payload": {
                        "type": "custom_tool_call",
                        "call_id": "wrapper-call",
                        "name": "exec",
                        "input": "printf ready",
                        "internal_chat_message_metadata_passthrough": {"turn_id": "turn-a"},
                    },
                },
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "item_completed",
                        "turn_id": "turn-a",
                        "item": {
                            "type": "CommandExecution",
                            "command": ["sh", "-lc", "printf ready"],
                            "status": "completed",
                            "aggregated_output": "rich output",
                        },
                    },
                },
                {
                    "type": "response_item",
                    "payload": {
                        "type": "custom_tool_call_output",
                        "call_id": "wrapper-call",
                        "output": "wrapper output",
                    },
                },
            ],
        )

        tools = self._tools(entry)
        assert len(tools) == 1
        assert tools[0].tool_name == "exec_command"
        assert tools[0].result == "rich output"

    @pytest.mark.parametrize(
        ("wrapper_name", "wrapper_input", "wrapper_turn", "rich_turn", "rich_command"),
        [
            ("exec", "printf first", "turn-a", "turn-a", "printf second"),
            ("fetch", "printf same", "turn-a", "turn-a", "printf same"),
            ("exec", "printf same", "turn-a", "turn-b", "printf same"),
            ("apply_patch", "printf same", "turn-a", "turn-a", "printf same"),
        ],
    )
    def test_unrelated_wrappers_are_preserved(
        self,
        tmp_path,
        wrapper_name,
        wrapper_input,
        wrapper_turn,
        rich_turn,
        rich_command,
    ):
        entry = self._parse_events(
            tmp_path,
            [
                {
                    "type": "response_item",
                    "payload": {
                        "type": "custom_tool_call",
                        "call_id": "wrapper-call",
                        "name": wrapper_name,
                        "input": wrapper_input,
                        "internal_chat_message_metadata_passthrough": {"turn_id": wrapper_turn},
                    },
                },
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "item_completed",
                        "turn_id": rich_turn,
                        "item": {
                            "type": "CommandExecution",
                            "command": rich_command,
                            "status": "completed",
                        },
                    },
                },
            ],
        )

        assert [tool.tool_name for tool in self._tools(entry)] == [wrapper_name, "exec_command"]

    def test_command_wrapper_is_not_replaced_by_unrelated_file_change(self, tmp_path):
        entry = self._parse_events(
            tmp_path,
            [
                {
                    "type": "response_item",
                    "payload": {
                        "type": "custom_tool_call",
                        "call_id": "command-call",
                        "name": "exec",
                        "input": "printf unchanged",
                    },
                },
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "item_completed",
                        "item": {
                            "type": "FileChange",
                            "changes": {"src/sample.txt": {"type": "add", "content": "private"}},
                            "status": "completed",
                        },
                    },
                },
            ],
        )

        assert [tool.tool_name for tool in self._tools(entry)] == ["exec", "file_change"]

    def test_late_rich_command_replaces_completed_wrapper(self, tmp_path):
        entry = self._parse_events(
            tmp_path,
            [
                {
                    "type": "response_item",
                    "payload": {
                        "type": "custom_tool_call",
                        "call_id": "late-call",
                        "name": "exec_command",
                        "input": '{"command":"printf late"}',
                    },
                },
                {
                    "type": "response_item",
                    "payload": {
                        "type": "custom_tool_call_output",
                        "call_id": "late-call",
                        "output": "wrapper output",
                    },
                },
                {"type": "event_msg", "payload": {"type": "token_count", "info": {}}},
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "item_completed",
                        "item": {
                            "type": "CommandExecution",
                            "command": "printf late",
                            "status": "completed",
                            "aggregated_output": "late output",
                        },
                    },
                },
            ],
        )

        tools = self._tools(entry)
        assert len(tools) == 1
        assert tools[0].tool_name == "exec_command"
        assert tools[0].result == "late output"

    def test_identical_rich_command_does_not_cross_a_later_call_boundary(self, tmp_path):
        entry = self._parse_events(
            tmp_path,
            [
                {
                    "type": "response_item",
                    "payload": {
                        "type": "custom_tool_call",
                        "call_id": "first-call",
                        "name": "exec",
                        "input": "printf same",
                    },
                },
                {
                    "type": "response_item",
                    "payload": {
                        "type": "function_call",
                        "call_id": "later-call",
                        "name": "other_tool",
                        "arguments": {},
                    },
                },
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "item_completed",
                        "item": {
                            "type": "CommandExecution",
                            "command": "printf same",
                            "status": "completed",
                        },
                    },
                },
            ],
        )

        assert [tool.tool_name for tool in self._tools(entry)] == [
            "exec",
            "other_tool",
            "exec_command",
        ]

    def test_one_wrapper_can_expand_to_multiple_rich_actions(self, tmp_path):
        entry = self._parse_events(
            tmp_path,
            [
                {
                    "type": "response_item",
                    "payload": {
                        "type": "custom_tool_call",
                        "call_id": "multi-call",
                        "name": "exec",
                        "input": "const opaque = true;",
                    },
                },
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "item_completed",
                        "item": {
                            "type": "FileChange",
                            "changes": {"src/sample.txt": {"type": "add", "content": "private"}},
                            "status": "completed",
                        },
                    },
                },
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "item_completed",
                        "item": {
                            "type": "CommandExecution",
                            "command": "printf first",
                            "status": "completed",
                            "aggregated_output": "first",
                        },
                    },
                },
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "item_completed",
                        "item": {
                            "type": "CommandExecution",
                            "command": "printf second",
                            "status": "failed",
                            "stderr": "second failed",
                        },
                    },
                },
                {
                    "type": "response_item",
                    "payload": {
                        "type": "custom_tool_call_output",
                        "call_id": "multi-call",
                        "output": "wrapper output",
                    },
                },
            ],
        )

        assert len(entry.chat_history) == 1
        tools = self._tools(entry)
        assert [tool.tool_name for tool in tools] == [
            "file_change",
            "exec_command",
            "exec_command",
        ]
        assert [tool.status for tool in tools] == ["success", "success", "error"]
        assert [tool.result for tool in tools] == [None, "first", "second failed"]

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

    def test_mcp_function_call_is_strictly_classified(self, tmp_path):
        jsonl_file = tmp_path / "rollout-mcp.jsonl"
        events = [
            {"type": "session_meta", "payload": {"id": "mcp-session"}},
            {
                "type": "response_item",
                "payload": {
                    "type": "function_call",
                    "call_id": "mcp-call",
                    "name": "mcp__sample-server__lookup_item",
                    "arguments": {"item": "example"},
                },
            },
        ]
        jsonl_file.write_text("\n".join(json.dumps(event) for event in events))

        tool = CodexParser().parse_jsonl_file(jsonl_file).chat_history[0].tools[0]

        assert tool.tool_name == "mcp__sample-server__lookup_item"
        assert tool.tool_type == "mcp_tool"
        assert tool.server_name == "sample-server"

    @pytest.mark.parametrize(
        "name",
        [
            "mcp__sample-server",
            "mcp____lookup_item",
            "mcp__sample-server__",
            "mcp__sample-server__lookup_item__extra",
            "mcp__sample server__lookup_item",
            "prefix__sample-server__lookup_item",
        ],
    )
    def test_malformed_mcp_names_keep_their_classic_type(self, name):
        assert CodexParser._classify_tool(name, "custom_tool_call") == ("custom_tool_call", None)

    def test_tool_arguments_are_normalized_and_recursively_bounded(self):
        parser = CodexParser()
        nested = {"leaf": "kept"}
        for _ in range(12):
            nested = {"next": nested}

        arguments = parser._parse_tool_arguments(
            {
                "items": list(range(150)),
                "mapping": {f"key-{index}": index for index in range(150)},
                "long": "x" * 5000,
                "nested": nested,
            }
        )

        assert len(arguments["items"]) == 100
        assert len(arguments["mapping"]) == 100
        assert len(arguments["long"]) < 1200
        assert "[truncated" in arguments["long"]
        assert "maximum depth" in json.dumps(arguments["nested"])
        assert parser._parse_tool_arguments('[1, {"key": "value"}]') == {
            "raw": [1, {"key": "value"}]
        }
        assert parser._parse_tool_arguments("") == {}
        assert parser._parse_tool_arguments(None) == {}
        assert parser._parse_tool_arguments("false") == {"raw": False}
        assert parser._parse_tool_arguments(7) == {"raw": 7}
        assert parser._parse_tool_arguments('"text"') == {"raw": "text"}

    def test_oversized_json_arguments_are_not_decoded(self):
        raw_arguments = json.dumps({"value": "x" * 100_100})

        arguments = CodexParser()._parse_tool_arguments(raw_arguments)

        assert list(arguments) == ["raw"]
        assert isinstance(arguments["raw"], str)
        assert len(arguments["raw"]) < 1200
        assert "[truncated" in arguments["raw"]

    def test_output_correlates_across_id_aliases_and_flattens_content(self, tmp_path):
        jsonl_file = tmp_path / "rollout-alias.jsonl"
        events = [
            {"type": "session_meta", "payload": {"id": "alias-session"}},
            {
                "type": "response_item",
                "payload": {
                    "type": "function_call",
                    "id": "shared-id",
                    "name": "lookup",
                    "arguments": [],
                },
            },
            {
                "type": "response_item",
                "payload": {
                    "type": "function_call_output",
                    "toolCallId": "shared-id",
                    "output": {
                        "content": [
                            {"type": "text", "text": "first"},
                            {"content": "second"},
                        ]
                    },
                },
            },
        ]
        jsonl_file.write_text("\n".join(json.dumps(event) for event in events))

        tool = CodexParser().parse_jsonl_file(jsonl_file).chat_history[0].tools[0]

        assert tool.arguments == {"raw": []}
        assert tool.result == "first\nsecond"
        assert tool.status == "success"
        assert tool.error is None

    @pytest.mark.parametrize(
        ("output", "expected_status", "expected_result", "expected_error"),
        [
            ({"Ok": {"content": [{"text": "complete"}]}}, "success", "complete", None),
            (
                {"Ok": {"isError": True, "content": [{"text": "not completed"}]}},
                "error",
                "not completed",
                "not completed",
            ),
            (json.dumps({"Err": {"message": "rejected"}}), "error", "rejected", "rejected"),
            (
                {"isError": True, "content": [{"type": "text", "text": "not completed"}]},
                "error",
                "not completed",
                "not completed",
            ),
            ({"is_error": False, "content": "complete"}, "success", "complete", None),
            ({"status": "failed", "message": "not completed"}, "error", "not completed", "not completed"),
            ({"state": "in_progress", "message": "waiting"}, "pending", "waiting", None),
            ({"state": "completed", "content": "finished"}, "success", "finished", None),
            ({"exit_code": 3, "stderr": "process detail"}, "error", "process detail", "Exit code: 3"),
            ({"exitCode": 0, "stdout": "complete"}, "success", "complete", None),
            ("ERROR: ordinary returned text", "success", "ERROR: ordinary returned text", None),
        ],
    )
    def test_tool_output_uses_structural_outcome_signals(
        self, tmp_path, output, expected_status, expected_result, expected_error
    ):
        jsonl_file = tmp_path / "rollout-outcome.jsonl"
        events = [
            {"type": "session_meta", "payload": {"id": "outcome-session"}},
            {
                "type": "response_item",
                "payload": {
                    "type": "custom_tool_call",
                    "callId": "outcome-call",
                    "name": "run_task",
                    "input": {"value": 1},
                },
            },
            {
                "type": "response_item",
                "payload": {
                    "type": "custom_tool_call_output",
                    "tool_call_id": "outcome-call",
                    "output": output,
                },
            },
        ]
        jsonl_file.write_text("\n".join(json.dumps(event) for event in events))

        tool = CodexParser().parse_jsonl_file(jsonl_file).chat_history[0].tools[0]

        assert tool.status == expected_status
        assert tool.result == expected_result
        assert tool.error == expected_error

    def test_nested_domain_status_does_not_mark_tool_as_failed(self, tmp_path):
        jsonl_file = tmp_path / "rollout-domain-status.jsonl"
        events = [
            {"type": "session_meta", "payload": {"id": "domain-status-session"}},
            {
                "type": "response_item",
                "payload": {
                    "type": "function_call",
                    "call_id": "domain-status-call",
                    "name": "lookup_record",
                    "arguments": {},
                },
            },
            {
                "type": "response_item",
                "payload": {
                    "type": "function_call_output",
                    "call_id": "domain-status-call",
                    "output": {
                        "content": [
                            {"type": "record", "id": "sample-record", "status": "failed"}
                        ]
                    },
                },
            },
        ]
        jsonl_file.write_text("\n".join(json.dumps(event) for event in events))

        tool = CodexParser().parse_jsonl_file(jsonl_file).chat_history[0].tools[0]

        assert tool.status == "success"
        assert tool.result == '{"type":"record","id":"sample-record","status":"failed"}'
        assert tool.error is None

    def test_unknown_typed_result_item_is_retained(self):
        result = CodexParser()._normalize_tool_output(
            [{"type": "artifact", "path": "sample.txt", "state": "ready", "message": "created"}]
        )

        assert result == '{"type":"artifact","path":"sample.txt","state":"ready","message":"created"}'

    @pytest.mark.parametrize(
        "output",
        [
            {"type": "artifact", "path": "sample.txt", "message": "created"},
            {"content": {"type": "artifact", "path": "sample.txt", "message": "created"}},
        ],
    )
    def test_unknown_typed_result_mapping_is_retained_outside_lists(self, output):
        result = CodexParser()._normalize_tool_output(output)

        assert result == '{"type":"artifact","path":"sample.txt","message":"created"}'

    def test_explicit_mcp_namespace_classifies_plain_tool_name(self, tmp_path):
        jsonl_file = tmp_path / "rollout-mcp-namespace.jsonl"
        events = [
            {"type": "session_meta", "payload": {"id": "mcp-namespace-session"}},
            {
                "type": "response_item",
                "payload": {
                    "type": "function_call",
                    "call_id": "mcp-call",
                    "namespace": "mcp__queryrunner_mcp",
                    "name": "run_query",
                    "arguments": {"query": "SELECT 1"},
                },
            },
        ]
        jsonl_file.write_text("\n".join(json.dumps(event) for event in events))

        tool = CodexParser().parse_jsonl_file(jsonl_file).chat_history[0].tools[0]

        assert tool.tool_type == "mcp_tool"
        assert tool.server_name == "queryrunner_mcp"
        assert tool.tool_name == "run_query"

    def test_nested_outcome_like_fields_remain_domain_data(self, tmp_path):
        jsonl_file = tmp_path / "rollout-nested-domain-outcome.jsonl"
        events = [
            {"type": "session_meta", "payload": {"id": "nested-domain-session"}},
            {
                "type": "response_item",
                "payload": {
                    "type": "function_call",
                    "call_id": "nested-domain-call",
                    "name": "lookup_record",
                    "arguments": {},
                },
            },
            {
                "type": "response_item",
                "payload": {
                    "type": "function_call_output",
                    "call_id": "nested-domain-call",
                    "output": {
                        "isError": False,
                        "content": [
                            {
                                "type": "record",
                                "result": {"status": "failed", "error": "domain value"},
                                "exit_code": 7,
                            }
                        ],
                    },
                },
            },
        ]
        jsonl_file.write_text("\n".join(json.dumps(event) for event in events))

        tool = CodexParser().parse_jsonl_file(jsonl_file).chat_history[0].tools[0]

        assert tool.status == "success"
        assert '"status":"failed"' in tool.result
        assert tool.error is None

    @pytest.mark.parametrize(
        ("status", "expected"),
        [("completed", "success"), ("failed", "error"), ("running", "pending")],
    )
    def test_call_status_is_canonicalized_without_output(self, tmp_path, status, expected):
        jsonl_file = tmp_path / f"rollout-{status}.jsonl"
        events = [
            {"type": "session_meta", "payload": {"id": f"{status}-session"}},
            {
                "type": "response_item",
                "payload": {
                    "type": "function_call",
                    "call_id": f"{status}-call",
                    "name": "sample_tool",
                    "arguments": {},
                    "status": status,
                },
            },
        ]
        jsonl_file.write_text("\n".join(json.dumps(event) for event in events))

        tool = CodexParser().parse_jsonl_file(jsonl_file).chat_history[0].tools[0]

        assert tool.status == expected
        assert tool.result is None

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

    def test_skips_malformed_decoded_records(self, tmp_path):
        jsonl_file = tmp_path / "rollout-malformed.jsonl"
        records = [
            None,
            ["unsupported-record"],
            {"type": "response_item"},
            {"type": "response_item", "payload": "unsupported-payload"},
            {
                "type": "session_meta",
                "payload": {"id": {"unexpected": "value"}, "timestamp": {"unexpected": "value"}},
            },
            {
                "type": "session_meta",
                "payload": {"id": "valid-session", "timestamp": "2025-01-02T03:04:05Z"},
            },
            {
                "type": "response_item",
                "payload": {"type": "message", "role": "user", "content": "kept message"},
            },
        ]
        jsonl_file.write_text("\n".join(json.dumps(record) for record in records))

        entry = CodexParser().parse_jsonl_file(jsonl_file)

        assert entry is not None
        assert entry.session_id == "codex_valid-session"
        assert [message.content for message in entry.chat_history] == ["kept message"]

    def test_invalid_session_timestamp_keeps_valid_session_identity(self, tmp_path):
        jsonl_file = tmp_path / "rollout-invalid-timestamp.jsonl"
        events = [
            {
                "type": "session_meta",
                "payload": {"id": "valid-session", "timestamp": {"unexpected": "value"}},
            },
            {
                "type": "response_item",
                "payload": {"type": "message", "role": "user", "content": "kept message"},
            },
        ]
        jsonl_file.write_text("\n".join(json.dumps(event) for event in events))

        entry = CodexParser().parse_jsonl_file(jsonl_file)

        assert entry is not None
        assert entry.session_id == "codex_valid-session"
        assert [message.content for message in entry.chat_history] == ["kept message"]

    def test_supports_message_content_shapes(self, tmp_path):
        jsonl_file = tmp_path / "rollout-content.jsonl"
        events = [
            {"type": "session_meta", "payload": {"id": "content-session"}},
            {
                "type": "response_item",
                "payload": {"type": "message", "role": "user", "content": "string content"},
            },
            {
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "assistant",
                    "content": {"type": "output_text", "text": "mapping content"},
                },
            },
            {
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "user",
                    "content": [
                        "mixed ",
                        {"type": "input_text", "text": "content"},
                        None,
                        7,
                        {"type": "input_text", "text": {"unexpected": "value"}},
                        {"type": "image", "text": "ignored"},
                        {"type": "output_text", "text": " list"},
                    ],
                },
            },
        ]
        jsonl_file.write_text("\n".join(json.dumps(event) for event in events))

        entry = CodexParser().parse_jsonl_file(jsonl_file)

        assert [(message.role, message.content) for message in entry.chat_history] == [
            ("user", "string content"),
            ("assistant", "mapping content"),
            ("user", "mixed content list"),
        ]

    def test_tolerates_malformed_reasoning_summary_items(self, tmp_path):
        jsonl_file = tmp_path / "rollout-reasoning.jsonl"
        events = [
            {"type": "session_meta", "payload": {"id": "reasoning-session"}},
            {
                "type": "response_item",
                "payload": {"type": "message", "role": "user", "content": "review this"},
            },
            {
                "type": "response_item",
                "payload": {
                    "type": "reasoning",
                    "summary": [
                        None,
                        "unsupported-item",
                        {"type": "summary_text", "text": {"unexpected": "value"}},
                        {"type": "other", "text": "ignored"},
                        {"type": "summary_text", "text": "valid summary"},
                    ],
                },
            },
        ]
        jsonl_file.write_text("\n".join(json.dumps(event) for event in events))

        entry = CodexParser().parse_jsonl_file(jsonl_file)

        assert [message.content for message in entry.chat_history] == [
            "review this",
            "[Reasoning]\nvalid summary\n",
        ]

    def test_first_valid_session_meta_defines_physical_identity(self, tmp_path):
        jsonl_file = tmp_path / "rollout-identity.jsonl"
        first_cwd = str(tmp_path / "first-project")
        later_cwd = str(tmp_path / "later-project")
        events = [
            {
                "type": "session_meta",
                "payload": {
                    "timestamp": "2024-01-01T00:00:00Z",
                    "cwd": str(tmp_path / "missing-id"),
                    "originator": "ignored-originator",
                },
            },
            {
                "type": "session_meta",
                "payload": {
                    "id": "physical-session",
                    "timestamp": "2025-01-02T03:04:05Z",
                    "cwd": first_cwd,
                    "originator": "first-originator",
                },
            },
            {
                "type": "session_meta",
                "payload": {
                    "id": "later-session",
                    "timestamp": "2026-02-03T04:05:06Z",
                    "cwd": later_cwd,
                    "originator": "later-originator",
                },
            },
            {
                "type": "session_meta",
                "payload": {"id": "later-session", "cwd": "/duplicate"},
            },
            {
                "type": "session_meta",
                "payload": {"id": "physical-session", "cwd": "/same-session"},
            },
            {"type": "session_meta", "payload": {"id": 42}},
            {
                "type": "response_item",
                "payload": {"type": "message", "role": "user", "content": "identity check"},
            },
        ]
        jsonl_file.write_text("\n".join(json.dumps(event) for event in events))

        entry = CodexParser().parse_jsonl_file(jsonl_file)

        assert entry.session_id == "codex_physical-session"
        assert entry.project_path == first_cwd
        assert entry.timestamp == datetime(2025, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
        assert entry.session_context == {
            "originator": "first-originator",
            "inherited_session_ids": ["later-session", "42"],
        }

    def test_captures_codex_session_provenance_without_changing_identity(self, tmp_path):
        jsonl_file = tmp_path / "rollout-context.jsonl"
        long_originator = "origin-start-" + ("x" * 1200) + "-origin-end"
        events = [
            {
                "type": "session_meta",
                "payload": {
                    "id": "physical-session",
                    "session_id": "root-session",
                    "timestamp": "2025-01-02T03:04:05Z",
                    "cwd": "/workspace/example",
                    "originator": long_originator,
                    "cli_version": "1.2.3",
                    "model_provider": "provider-name",
                    "git": {"branch": "feature/session-context"},
                    "parent_thread_id": "parent-thread",
                    "forked_from_id": "forked-thread",
                    "agent_path": "root/worker",
                    "agent_nickname": "worker-name",
                    "agent_role": "reviewer",
                    "subagent_history_start_ordinal": 4,
                    "thread_source": "subagent",
                },
            },
            {
                "type": "response_item",
                "payload": {"type": "message", "role": "user", "content": "provenance check"},
            },
        ]
        jsonl_file.write_text("\n".join(json.dumps(event) for event in events))

        entry = CodexParser().parse_jsonl_file(jsonl_file)

        assert entry.source == "codex"
        assert entry.session_id == "codex_physical-session"
        assert entry.project_path == "/workspace/example"
        assert entry.user_id is None
        assert entry.session_context == {
            "originator": entry.session_context["originator"],
            "cli_version": "1.2.3",
            "model_provider": "provider-name",
            "parent_thread_id": "parent-thread",
            "forked_from_id": "forked-thread",
            "agent_path": "root/worker",
            "agent_nickname": "worker-name",
            "agent_role": "reviewer",
            "subagent_history_start_ordinal": 4,
            "thread_source": "subagent",
            "git_branch": "feature/session-context",
            "root_session_id": "root-session",
        }
        assert entry.session_context["originator"].startswith("origin-start-")
        assert entry.session_context["originator"].endswith("-origin-end")
        assert "[truncated" in entry.session_context["originator"]
        assert len(entry.session_context["originator"]) < 1000

    def test_captures_nested_subagent_provenance_and_ignores_structured_values(self, tmp_path):
        jsonl_file = tmp_path / "rollout-subagent-context.jsonl"
        events = [
            {
                "type": "session_meta",
                "payload": {
                    "id": "child-session",
                    "session_id": {"not": "scalar"},
                    "originator": ["not", "scalar"],
                    "cli_version": {"not": "scalar"},
                    "model_provider": ["not", "scalar"],
                    "git": {"branch": {"not": "scalar"}},
                    "parent_thread_id": {"not": "scalar"},
                    "agent_path": ["not", "scalar"],
                    "agent_nickname": {"not": "scalar"},
                    "agent_role": "planner",
                    "forked_from_id": ["not", "scalar"],
                    "subagent_history_start_ordinal": {"not": "scalar"},
                    "thread_source": ["not", "scalar"],
                    "source": {
                        "subagent": {
                            "thread_spawn": {
                                "parent_thread_id": "parent-session",
                                "agent_path": "root/child",
                                "agent_nickname": "child-name",
                                "depth": 2,
                                "agent_role": "reviewer",
                            }
                        }
                    },
                },
            },
            {"type": "session_meta", "payload": {"id": ["not", "scalar"]}},
            {
                "type": "response_item",
                "payload": {"type": "message", "role": "user", "content": "nested provenance"},
            },
        ]
        jsonl_file.write_text("\n".join(json.dumps(event) for event in events))

        entry = CodexParser().parse_jsonl_file(jsonl_file)

        assert entry.session_context == {
            "parent_thread_id": "parent-session",
            "agent_path": "root/child",
            "agent_nickname": "child-name",
            "agent_depth": 2,
            "agent_role": "planner",
        }

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

    def test_redirected_appdata_end_to_end(self, tmp_path):
        """A Cursor DB under a redirected %APPDATA% (outside the profile) is found."""
        import importlib
        import os as os_mod

        from adr_sensor.parsers import cursor_parser as cursor_parser_module

        redirected = tmp_path / "fileserver/profiles$/alice/AppData/Roaming"
        db = redirected / "Cursor/User/globalStorage/state.vscdb"
        db.parent.mkdir(parents=True)
        db.touch()

        original = os_mod.environ.get("APPDATA")
        os_mod.environ["APPDATA"] = str(redirected)
        try:
            # DB_PATHS is built at import time, so reload under the redirected env.
            importlib.reload(cursor_parser_module)
            assert cursor_parser_module.CursorParser().db_path == db
        finally:
            if original is None:
                os_mod.environ.pop("APPDATA", None)
            else:
                os_mod.environ["APPDATA"] = original
            importlib.reload(cursor_parser_module)
