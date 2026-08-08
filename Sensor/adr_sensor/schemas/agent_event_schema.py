"""
Agent Event Schema for AI agent telemetry ingestion.
Normalizes logs from Claude Code, Cursor, Cline, Codex, Warp, opencode, and
Claude Desktop into a common format for security analysis.
"""

import hashlib
import json
import os
import socket
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class ToolUsage:
    """Represents a tool/function call made by the AI agent."""

    tool_name: str
    tool_type: str  # mcp_tool, function_call, tool_use, terminal_command, etc.
    server_name: Optional[str] = None  # For MCP tools
    arguments: Dict[str, Any] = field(default_factory=dict)
    result: Optional[str] = None
    status: Optional[str] = None  # success, error, etc.
    error: Optional[str] = None


@dataclass(frozen=True)
class ChatMessage:
    """Represents a single message in a conversation turn."""

    role: str  # 'user' or 'assistant'
    content: str
    tools: List[ToolUsage] = field(default_factory=list)
    sequence_id: Optional[str] = None


@dataclass(frozen=True)
class AgentEvent:
    """Unified agent event schema for all AI agent telemetry.

    This is the core data structure that all parsers produce. It normalizes
    heterogeneous log formats into a single schema for downstream analysis.
    """

    # Core fields
    timestamp: datetime
    source: str  # 'claude', 'cursor', 'cline', 'warp', 'codex', 'claude_desktop', 'opencode'
    session_id: str

    # Chat history
    chat_history: List[ChatMessage] = field(default_factory=list)

    # Metadata
    user_id: Optional[str] = None
    project_path: Optional[str] = None
    model: Optional[str] = None
    hostname: Optional[str] = None
    username: Optional[str] = None
    raw_log_path: Optional[str] = None

    # Session context (populated by some parsers)
    session_context: Optional[Dict[str, Any]] = None

    # Chunking fields (for large session export)
    is_chunked: bool = False
    total_chunks: Optional[int] = None
    chunk_sequence: Optional[int] = None
    is_truncated: bool = False

    # UUID for this log entry
    uuid: str = field(init=False)

    def __post_init__(self):
        """Generate UUID after initialization and populate hostname/username if not provided."""
        if self.username is None:
            try:
                username = os.environ.get("USER") or os.environ.get("USERNAME")
                if not username:
                    username = os.getlogin()
            except Exception:
                username = "unknown_user"
            object.__setattr__(self, "username", username)

        if self.hostname is None:
            try:
                hostname = socket.gethostname()
            except Exception:
                hostname = "unknown_hostname"
            object.__setattr__(self, "hostname", hostname)

        # Generate deterministic UUID via SHA-256
        device_name = self.hostname or "unknown_device"
        timestamp_str = self.timestamp.isoformat()

        content_summary = ""
        tool_count = 0
        for msg in self.chat_history:
            content_summary += msg.content[:100]
            tool_count += len(msg.tools)

        payload_parts = [
            device_name,
            self.username or "unknown_user",
            timestamp_str,
            "llm_interaction",
            self.source,
            self.session_id,
            str(len(self.chat_history)),
            str(tool_count),
            content_summary,
        ]
        event_payload = "|".join(payload_parts)
        uuid_hash = hashlib.sha256(event_payload.encode()).hexdigest()
        object.__setattr__(self, "uuid", uuid_hash)

    def has_meaningful_content(self) -> bool:
        """Check if this entry has meaningful content worth including.

        Filters out empty conversations, single-message errors, and noise.
        """
        if not self.chat_history:
            return False

        if len(self.chat_history) >= 2:
            return True

        msg = self.chat_history[0]
        if msg.tools:
            return True

        content = msg.content.strip()
        if len(content) <= 5:
            return False

        content_lower = content.lower()
        skip_patterns = (
            "invalid api key",
            "please run /login",
            "authentication failed",
            "unauthorized",
            "session expired",
            "rate limit",
            "api error",
            "warmup",
        )
        return not any(pattern in content_lower for pattern in skip_patterns)

    def get_non_null_fields(self) -> Dict[str, Any]:
        """Return only fields that have meaningful (non-null, non-empty) values."""
        data = asdict(self)

        filtered = {}
        for key, value in data.items():
            if value is not None:
                if isinstance(value, str) and value.strip():
                    filtered[key] = value.strip()
                elif isinstance(value, list):
                    filtered[key] = self._serialize_list(value)
                elif isinstance(value, dict) and value:
                    filtered[key] = value
                elif isinstance(value, datetime):
                    filtered[key] = value.isoformat()
                elif not isinstance(value, (str, list, dict)):
                    filtered[key] = value

        return filtered

    def _serialize_list(self, items: List[Any]) -> List[Any]:
        """Recursively serialize datetime objects in a list."""
        serialized_list = []
        for item in items:
            if isinstance(item, dict):
                serialized_dict = {}
                for k, v in item.items():
                    if isinstance(v, datetime):
                        serialized_dict[k] = v.isoformat()
                    elif isinstance(v, list):
                        serialized_dict[k] = self._serialize_list(v)
                    else:
                        serialized_dict[k] = v
                serialized_list.append(serialized_dict)
            else:
                serialized_list.append(item)
        return serialized_list

    def get_summary(self) -> str:
        """Get a human-readable summary of this event."""
        tools_count = sum(len(msg.tools) for msg in self.chat_history if msg.role == "assistant")
        session_info = f" | Session: {self.session_id.split('_')[-1][:8]}..."
        return (
            f"[{self.source.upper()}] {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"
            f"{session_info} | Turns: {len(self.chat_history)} | Tools: {tools_count}"
        )

    def get_content_hash(self) -> str:
        """Get a SHA-256 hash of the event's content for change detection."""
        chat_representation = []
        for msg in self.chat_history:
            chat_representation.append(
                {
                    "role": msg.role,
                    "content": msg.content,
                    "tools": [
                        {"tool_name": tool.tool_name, "tool_type": tool.tool_type, "arguments": tool.arguments}
                        for tool in msg.tools
                    ],
                }
            )

        event_data = {
            "source": self.source,
            "session_id": self.session_id,
            "chat_history": chat_representation,
        }

        event_json = json.dumps(event_data, sort_keys=True)
        return hashlib.sha256(event_json.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()

        for msg in data.get("chat_history", []):
            for tool in msg.get("tools", []):
                if tool.get("timestamp") and isinstance(tool.get("timestamp"), datetime):
                    tool["timestamp"] = tool["timestamp"].isoformat()

        return data

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    def has_tool_usage(self) -> bool:
        """Check if this entry has any tool usage."""
        return any(len(msg.tools) > 0 for msg in self.chat_history if msg.role == "assistant")
