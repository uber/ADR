"""Tests for ADR Sensor schemas."""

import json
from datetime import datetime, timezone

import pytest

from adr_sensor.schemas.agent_event_schema import AgentEvent, ChatMessage, ToolUsage


class TestToolUsage:
    def test_create_basic(self):
        tool = ToolUsage(tool_name="read_file", tool_type="tool_use")
        assert tool.tool_name == "read_file"
        assert tool.tool_type == "tool_use"
        assert tool.arguments == {}
        assert tool.result is None

    def test_create_with_all_fields(self):
        tool = ToolUsage(
            tool_name="execute_command",
            tool_type="terminal_command",
            server_name="my_server",
            arguments={"command": "ls -la"},
            result="file1.py\nfile2.py",
            status="success",
            error=None,
        )
        assert tool.tool_name == "execute_command"
        assert tool.server_name == "my_server"
        assert tool.status == "success"

    def test_frozen(self):
        tool = ToolUsage(tool_name="test", tool_type="test")
        with pytest.raises(AttributeError):
            tool.tool_name = "changed"


class TestChatMessage:
    def test_create_user_message(self):
        msg = ChatMessage(role="user", content="Hello, help me with this code")
        assert msg.role == "user"
        assert msg.content == "Hello, help me with this code"
        assert msg.tools == []

    def test_create_assistant_message_with_tools(self):
        tool = ToolUsage(tool_name="read_file", tool_type="tool_use", arguments={"path": "main.py"})
        msg = ChatMessage(role="assistant", content="Let me read the file.", tools=[tool])
        assert msg.role == "assistant"
        assert len(msg.tools) == 1
        assert msg.tools[0].tool_name == "read_file"


class TestAgentEvent:
    def test_create_basic(self):
        event = AgentEvent(
            timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
            source="claude",
            session_id="test_session_1",
        )
        assert event.source == "claude"
        assert event.session_id == "test_session_1"
        assert event.token_usage is None
        assert event.uuid is not None
        assert len(event.uuid) == 64  # SHA-256 hex

    def test_uuid_deterministic(self):
        """Same inputs should produce same UUID."""
        kwargs = {
            "timestamp": datetime(2025, 1, 1, tzinfo=timezone.utc),
            "source": "claude",
            "session_id": "test_session",
            "hostname": "test-host",
            "username": "test-user",
        }
        event1 = AgentEvent(**kwargs)
        event2 = AgentEvent(**kwargs)
        assert event1.uuid == event2.uuid

    def test_new_fields_preserve_existing_positional_arguments(self):
        event = AgentEvent(
            datetime(2025, 1, 1, tzinfo=timezone.utc),
            "codex",
            "test-session",
            [],
            "user-id",
            "/workspace",
            "model-id",
            "test-host",
            "test-user",
            "/logs/session.jsonl",
            {"originator": "cli"},
            True,
            3,
            2,
            True,
        )

        assert event.session_context == {"originator": "cli"}
        assert event.is_chunked is True
        assert event.total_chunks == 3
        assert event.chunk_sequence == 2
        assert event.is_truncated is True
        assert event.token_usage is None

    def test_uuid_unique_for_different_sessions(self):
        event1 = AgentEvent(
            timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
            source="claude",
            session_id="session_1",
            hostname="host",
            username="user",
        )
        event2 = AgentEvent(
            timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
            source="claude",
            session_id="session_2",
            hostname="host",
            username="user",
        )
        assert event1.uuid != event2.uuid

    def test_has_meaningful_content_empty(self):
        event = AgentEvent(
            timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
            source="claude",
            session_id="test",
        )
        assert not event.has_meaningful_content()

    def test_has_meaningful_content_single_error(self):
        event = AgentEvent(
            timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
            source="claude",
            session_id="test",
            chat_history=[ChatMessage(role="user", content="Invalid API key")],
        )
        assert not event.has_meaningful_content()

    def test_has_meaningful_content_real_conversation(self):
        event = AgentEvent(
            timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
            source="claude",
            session_id="test",
            chat_history=[
                ChatMessage(role="user", content="Help me debug this"),
                ChatMessage(role="assistant", content="Sure, let me take a look."),
            ],
        )
        assert event.has_meaningful_content()

    def test_has_meaningful_content_with_tools(self):
        tool = ToolUsage(tool_name="read_file", tool_type="tool_use")
        event = AgentEvent(
            timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
            source="claude",
            session_id="test",
            chat_history=[ChatMessage(role="assistant", content="Let me check", tools=[tool])],
        )
        assert event.has_meaningful_content()

    def test_has_tool_usage(self):
        tool = ToolUsage(tool_name="read_file", tool_type="tool_use")
        event = AgentEvent(
            timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
            source="claude",
            session_id="test",
            chat_history=[ChatMessage(role="assistant", content="test", tools=[tool])],
        )
        assert event.has_tool_usage()

    def test_to_dict(self):
        event = AgentEvent(
            timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
            source="claude",
            session_id="test",
            hostname="test-host",
            username="test-user",
        )
        d = event.to_dict()
        assert d["source"] == "claude"
        assert d["timestamp"] == "2025-01-01T00:00:00+00:00"

    def test_token_usage_serialization(self):
        token_usage = {
            "last_turn": {"input_tokens": 12, "output_tokens": 3, "total_tokens": 15},
            "cumulative": {"input_tokens": 30, "output_tokens": 8, "total_tokens": 38},
            "model_context_window": 128000,
        }
        event = AgentEvent(
            timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
            source="codex",
            session_id="test",
            hostname="test-host",
            username="test-user",
            token_usage=token_usage,
        )

        assert event.to_dict()["token_usage"] == token_usage
        assert json.loads(event.to_json())["token_usage"] == token_usage

    def test_to_json(self):
        event = AgentEvent(
            timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
            source="claude",
            session_id="test",
            hostname="test-host",
            username="test-user",
        )
        json_str = event.to_json()
        assert '"source": "claude"' in json_str

    def test_get_summary(self):
        event = AgentEvent(
            timestamp=datetime(2025, 6, 15, 10, 30, 0, tzinfo=timezone.utc),
            source="cursor",
            session_id="cursor_abc123",
            chat_history=[
                ChatMessage(role="user", content="hello"),
                ChatMessage(role="assistant", content="hi"),
            ],
        )
        summary = event.get_summary()
        assert "[CURSOR]" in summary
        assert "Turns: 2" in summary

    def test_get_content_hash(self):
        event = AgentEvent(
            timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
            source="claude",
            session_id="test",
            chat_history=[ChatMessage(role="user", content="hello")],
        )
        hash1 = event.get_content_hash()
        assert len(hash1) == 64

    def test_get_non_null_fields(self):
        event = AgentEvent(
            timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
            source="claude",
            session_id="test",
            hostname="test-host",
            username="test-user",
        )
        fields = event.get_non_null_fields()
        assert "source" in fields
        assert fields["source"] == "claude"
        # project_path is None, should not be in output
        assert "project_path" not in fields

    def test_auto_populates_hostname_username(self):
        event = AgentEvent(
            timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
            source="claude",
            session_id="test",
        )
        assert event.hostname is not None
        assert event.username is not None
