"""
Parser for Claude Desktop Agent Mode (also released as Claude Cowork) logs.

Reads ``audit.jsonl`` files from ``local-agent-mode-sessions`` directories on
macOS and Windows. Two kinds of session live side by side:

* Interactive sessions: ``<user_id>/<org_id>/local_<uuid>/audit.jsonl``
* Dispatch sessions (delegated background agents), which are stored one level
  deeper under an ``agent/`` directory as
  ``<user_id>/<org_id>/agent/local_ditto_<uuid>/audit.jsonl``

Both are emitted with ``source="claude_desktop"``; Dispatch sessions get a
distinct ``claude_desktop_dispatch_`` session-id prefix and an ``is_dispatch``
session-context flag so downstream detection can filter them cleanly.

Memory-optimized: streams audit.jsonl line-by-line, skips thinking blocks,
truncates large tool results, and filters by session age.
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..schemas.agent_event_schema import AgentEvent, ChatMessage, ToolUsage
from ..utils.string_utils import truncate_middle
from .base_parser import BaseParser

MAX_LOG_AGE_DAYS = 14

# Default base paths for agent-mode sessions, checked in order.
DEFAULT_BASE_PATHS = [
    "~/Library/Application Support/Claude/local-agent-mode-sessions",  # macOS
    "~/AppData/Roaming/Claude/local-agent-mode-sessions",  # Windows
]

# Dispatch session directories are named local_ditto_<uuid>; interactive ones local_<uuid>.
DISPATCH_DIR_PREFIX = "local_ditto_"
SESSION_DIR_PREFIX = "local_"

# Session-scoped metadata keys copied verbatim into session_context, mapped to
# their snake_case output names.
_SESSION_FLAG_KEYS = (
    ("hostLoopMode", "host_loop_mode"),
    ("memoryEnabled", "memory_enabled"),
    ("skillsEnabled", "skills_enabled"),
    ("pluginsEnabled", "plugins_enabled"),
)


class ClaudeDesktopParser(BaseParser):
    """Parser for Claude Desktop Agent Mode audit.jsonl log files."""

    def __init__(self, max_age_days: int = MAX_LOG_AGE_DAYS, base_path: Optional[str] = None):
        if base_path:
            self.base_path = Path(base_path)
        else:
            candidates = [Path(p).expanduser() for p in DEFAULT_BASE_PATHS]
            self.base_path = next((p for p in candidates if p.exists()), candidates[0])
        self.max_age_days = max_age_days

    def parse_all(self) -> List[AgentEvent]:
        """Parse all available interactive and Dispatch agent-mode sessions."""
        entries: List[AgentEvent] = []

        if not self.base_path.exists():
            print(f"[CLAUDE_DESKTOP] No sessions found at {self.base_path}")
            return entries

        session_dirs = self._discover_sessions()
        print(f"[CLAUDE_DESKTOP] Found {len(session_dirs)} session directories")

        cutoff_time = datetime.now(timezone.utc) - timedelta(days=self.max_age_days)
        skipped_count = 0
        processed_count = 0

        for session_dir, metadata_path in session_dirs:
            try:
                metadata = self._read_session_metadata(metadata_path)
                if metadata is None:
                    continue

                # Age filter by lastActivityAt (epoch milliseconds).
                last_activity = metadata.get("lastActivityAt")
                if last_activity is not None:
                    try:
                        activity_time = datetime.fromtimestamp(last_activity / 1000, tz=timezone.utc)
                        if activity_time < cutoff_time:
                            skipped_count += 1
                            continue
                    except (ValueError, OSError, OverflowError, TypeError):
                        pass  # If we cannot parse it, process the session anyway.

                audit_path = session_dir / "audit.jsonl"
                if not audit_path.exists():
                    continue

                entry = self._parse_session(audit_path, metadata)
                if entry and entry.has_meaningful_content():
                    entries.append(entry)
                    processed_count += 1

            except Exception as e:
                print(f"[CLAUDE_DESKTOP] Error parsing session {session_dir}: {e}")

        if skipped_count > 0:
            print(f"[CLAUDE_DESKTOP] Skipped {skipped_count} sessions older than {self.max_age_days} days")
        print(f"[CLAUDE_DESKTOP] Processed {processed_count} sessions")

        return entries

    def _discover_sessions(self) -> List[Tuple[Path, Path]]:
        """Discover session directories and their sibling metadata files.

        Directory structure::

            base_path/<user_id>/<org_id>/local_<uuid>/audit.jsonl
            base_path/<user_id>/<org_id>/local_<uuid>.json              (metadata)

            base_path/<user_id>/<org_id>/agent/local_ditto_<uuid>/audit.jsonl
            base_path/<user_id>/<org_id>/agent/local_ditto_<uuid>.json  (metadata)

        Returns a list of (session_dir, metadata_path) tuples. Dispatch sessions
        are intermixed; callers detect them from the directory-name prefix.
        """
        sessions: List[Tuple[Path, Path]] = []

        try:
            for user_dir in self.base_path.iterdir():
                if not user_dir.is_dir() or user_dir.name.startswith("."):
                    continue

                for org_dir in user_dir.iterdir():
                    if not org_dir.is_dir() or org_dir.name.startswith("."):
                        continue

                    # Interactive sessions live directly under the org directory.
                    sessions.extend(self._collect_sessions(org_dir, SESSION_DIR_PREFIX))

                    # Dispatch sessions live one level deeper, under agent/.
                    agent_dir = org_dir / "agent"
                    if agent_dir.is_dir():
                        sessions.extend(self._collect_sessions(agent_dir, DISPATCH_DIR_PREFIX))

        except (PermissionError, OSError) as e:
            print(f"[CLAUDE_DESKTOP] Error scanning base path {self.base_path}: {e}")

        return sessions

    @staticmethod
    def _collect_sessions(parent: Path, prefix: str) -> List[Tuple[Path, Path]]:
        """Collect (session_dir, metadata_path) pairs directly under `parent`."""
        found: List[Tuple[Path, Path]] = []
        try:
            for item in parent.iterdir():
                if not item.is_dir() or not item.name.startswith(prefix):
                    continue
                if not (item / "audit.jsonl").exists():
                    continue
                found.append((item, parent / f"{item.name}.json"))
        except (PermissionError, OSError) as e:
            print(f"[CLAUDE_DESKTOP] Error scanning {parent}: {e}")
        return found

    @staticmethod
    def _read_session_metadata(metadata_path: Path) -> Optional[Dict[str, Any]]:
        """Read a session metadata JSON file.

        Returns an empty dict (rather than None) when the file is missing or
        unreadable, so the audit.jsonl is still parsed.
        """
        if not metadata_path.exists():
            return {}

        try:
            with open(metadata_path, encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except (json.JSONDecodeError, OSError, PermissionError):
            return {}

    @staticmethod
    def _normalize_result_content(result_content: Any) -> str:
        """Normalize result content, which can be a string or a list of content items."""
        if isinstance(result_content, str):
            return result_content

        if isinstance(result_content, list):
            text_parts = []
            for item in result_content:
                if isinstance(item, dict) and item.get("type") == "text" and "text" in item:
                    text_parts.append(item["text"])
            return "\n".join(text_parts)

        return str(result_content) if result_content else ""

    @staticmethod
    def _truncate_large_arguments(arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Truncate large string values in tool arguments."""
        if not isinstance(arguments, dict):
            return arguments

        truncated = {}
        for key, value in arguments.items():
            if isinstance(value, str) and len(value) > 1000:
                truncated[key] = truncate_middle(value, max_length=1000, edge_chars=400)
            else:
                truncated[key] = value

        return truncated

    @staticmethod
    def _extract_session_uuid(session_id: str) -> str:
        """Strip the local_ / local_ditto_ prefix from a session identifier."""
        if session_id.startswith(DISPATCH_DIR_PREFIX):
            return session_id[len(DISPATCH_DIR_PREFIX) :]
        if session_id.startswith(SESSION_DIR_PREFIX):
            return session_id[len(SESSION_DIR_PREFIX) :]
        return session_id

    def _resolve_timestamp(self, audit_path: Path, metadata: Dict[str, Any]) -> datetime:
        """Resolve the session timestamp from metadata, falling back to file mtime.

        ``lastActivityAt`` is preferred so that sessions gaining new messages are
        re-captured by the incremental (per-session file) export path.
        """
        for key in ("lastActivityAt", "createdAt"):
            value = metadata.get(key)
            if value is None:
                continue
            try:
                return datetime.fromtimestamp(value / 1000, tz=timezone.utc)
            except (ValueError, OSError, OverflowError, TypeError) as e:
                print(f"[CLAUDE_DESKTOP] Error parsing timestamp from {key}={value}: {e}")

        try:
            return datetime.fromtimestamp(audit_path.stat().st_mtime, tz=timezone.utc)
        except OSError:
            return datetime.now(timezone.utc)

    def _build_session_context(
        self, metadata: Dict[str, Any], init_data: Optional[Dict[str, Any]], is_dispatch: bool
    ) -> Dict[str, Any]:
        """Assemble the session-scoped context recorded alongside the chat history."""
        context: Dict[str, Any] = {}

        title = metadata.get("title")
        if title:
            context["title"] = title
        if init_data:
            context["init"] = init_data
        if is_dispatch:
            context["is_dispatch"] = True

        for meta_key, ctx_key in (
            ("sessionType", "session_type"),
            ("cliSessionId", "cli_session_id"),
        ):
            value = metadata.get(meta_key)
            if value:
                context[ctx_key] = value

        initial_message = metadata.get("initialMessage")
        if isinstance(initial_message, str) and initial_message:
            context["initial_message"] = initial_message[:1000]

        for meta_key, ctx_key in _SESSION_FLAG_KEYS:
            value = metadata.get(meta_key)
            if value is not None:
                context[ctx_key] = value

        slash_commands = self._extract_slash_command_names(metadata.get("slashCommands"))
        if slash_commands:
            context["available_slash_commands"] = slash_commands

        return context

    @staticmethod
    def _extract_slash_command_names(slash_commands: Any) -> List[str]:
        """Normalize the slashCommands metadata into a flat list of command names."""
        if not isinstance(slash_commands, list):
            return []

        names = []
        for item in slash_commands:
            if isinstance(item, dict):
                name = item.get("name") or item.get("command")
                if name:
                    names.append(str(name))
            elif isinstance(item, str):
                names.append(item)
        return names

    def _parse_session(self, audit_path: Path, metadata: Dict[str, Any]) -> Optional[AgentEvent]:
        """Parse a single session's audit.jsonl file.

        Streams line-by-line to avoid loading the entire file into memory, and
        skips thinking blocks and image data.
        """
        is_dispatch = audit_path.parent.name.startswith(DISPATCH_DIR_PREFIX)

        session_id_from_meta = metadata.get("sessionId") or ""
        if session_id_from_meta:
            session_uuid = self._extract_session_uuid(session_id_from_meta)
        else:
            session_uuid = self._extract_session_uuid(audit_path.parent.name)

        # Extract messages from the audit log.
        messages: List[Dict[str, Any]] = []
        init_data = None

        try:
            with open(audit_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    extracted = self._extract_message_data(obj)
                    if extracted:
                        messages.append(extracted)
                    elif obj.get("type") == "system" and obj.get("subtype") == "init":
                        init_data = self._extract_init_data(obj)

                    del obj

        except (OSError, PermissionError) as e:
            print(f"[CLAUDE_DESKTOP] Error reading {audit_path}: {e}")
            return None

        if not messages:
            return None

        session_context = self._build_session_context(metadata, init_data, is_dispatch)
        session_prefix = "claude_desktop_dispatch_" if is_dispatch else "claude_desktop_"

        entry = AgentEvent(
            timestamp=self._resolve_timestamp(audit_path, metadata),
            source="claude_desktop",
            session_id=f"{session_prefix}{session_uuid}",
            project_path=metadata.get("cwd"),
            model=metadata.get("model"),
            raw_log_path=str(audit_path),
            session_context=session_context or None,
        )

        self._populate_chat_history(entry, messages)
        return entry

    def _populate_chat_history(self, entry: AgentEvent, messages: List[Dict[str, Any]]) -> None:
        """Build the chat history on `entry`, back-filling tool results onto their calls."""
        pending_tools: Dict[str, ToolUsage] = {}

        for i, msg_data in enumerate(messages):
            msg_type = msg_data["type"]
            sequence_id = msg_data.get("uuid") or f"msg_{i}"

            if msg_type == "user":
                tool_results = msg_data.get("tool_results", [])
                if tool_results:
                    for tool_result in tool_results:
                        self._attach_tool_result(entry, pending_tools, tool_result)
                    continue

                content = msg_data.get("content", "")
                if content:
                    entry.chat_history.append(
                        ChatMessage(role="user", content=content, tools=[], sequence_id=sequence_id)
                    )

            elif msg_type == "assistant":
                content = msg_data.get("content", "")
                tools = []

                for tool_data in msg_data.get("tools", []):
                    tool = ToolUsage(
                        tool_name=tool_data.get("name", "unknown"),
                        tool_type="tool_use",
                        arguments=tool_data.get("input", {}),
                        result=None,
                    )
                    tools.append(tool)
                    tool_id = tool_data.get("id")
                    if tool_id:
                        pending_tools[tool_id] = tool

                if content or tools:
                    entry.chat_history.append(
                        ChatMessage(
                            role="assistant",
                            content=content or "[Assistant used tools]",
                            tools=tools,
                            sequence_id=sequence_id,
                        )
                    )

    @staticmethod
    def _attach_tool_result(
        entry: AgentEvent, pending_tools: Dict[str, ToolUsage], tool_result: Dict[str, Any]
    ) -> None:
        """Replace the pending ToolUsage for `tool_use_id` with one carrying its result."""
        tool_use_id = tool_result.get("tool_use_id")
        old_tool = pending_tools.get(tool_use_id)
        if old_tool is None:
            return

        result = tool_result.get("result")
        updated_tool = ToolUsage(
            tool_name=old_tool.tool_name,
            tool_type=old_tool.tool_type,
            server_name=old_tool.server_name,
            arguments=old_tool.arguments,
            result=result,
            status="success" if result else "unknown",
        )

        # ChatMessage/ToolUsage are frozen, so swap the objects rather than mutate
        # them. Match on identity: two identical calls in different messages compare
        # equal, and only the one this result belongs to should change.
        for msg_idx, msg in enumerate(entry.chat_history):
            if msg.role != "assistant":
                continue
            for tool_idx, tool in enumerate(msg.tools):
                if tool is not old_tool:
                    continue
                new_tools = list(msg.tools)
                new_tools[tool_idx] = updated_tool
                entry.chat_history[msg_idx] = ChatMessage(
                    role=msg.role,
                    content=msg.content,
                    tools=new_tools,
                    sequence_id=msg.sequence_id,
                )
                pending_tools[tool_use_id] = updated_tool
                return

    @staticmethod
    def _extract_init_data(obj: Dict[str, Any]) -> Dict[str, Any]:
        """Extract the relevant fields from a system:init event."""
        return {
            "tools": obj.get("tools", []),
            "mcp_servers": obj.get("mcp_servers", []),
            "permission_mode": obj.get("permissionMode"),
            "model": obj.get("model"),
            "claude_code_version": obj.get("claude_code_version"),
            "plugins": obj.get("plugins", []),
            "skills": obj.get("skills", []),
        }

    def _extract_message_data(self, obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract only the needed data from an audit.jsonl line.

        Handles user messages with string content, user messages carrying
        tool_result blocks, and assistant messages with text + tool_use blocks
        (skipping thinking blocks). Skips system, rate_limit_event, result and
        tool_use_summary lines.
        """
        msg_type = obj.get("type")
        if msg_type not in ("user", "assistant"):
            return None

        if "message" not in obj:
            return None

        extracted: Dict[str, Any] = {"type": msg_type, "uuid": obj.get("uuid")}
        message = obj["message"]

        if msg_type == "user":
            content = message.get("content", "")

            tool_results = []
            if isinstance(content, list):
                for item in content:
                    if isinstance(item, dict) and item.get("type") == "tool_result":
                        result_content = item.get("content", "")

                        # The root-level tool_use_result carries the richer payload.
                        if isinstance(obj.get("tool_use_result"), dict):
                            result_content = obj["tool_use_result"].get("result", result_content)

                        result_content = self._normalize_result_content(result_content)
                        if result_content:
                            result_content = truncate_middle(result_content, max_length=1000, edge_chars=400)

                        tool_results.append(
                            {"tool_use_id": item.get("tool_use_id"), "result": result_content}
                        )

            if tool_results:
                extracted["tool_results"] = tool_results
                extracted["content"] = ""
            elif isinstance(content, str):
                extracted["content"] = content
            else:
                extracted["content"] = ""

        elif msg_type == "assistant":
            content_items = message.get("content", [])
            text_parts = []
            tools = []

            if isinstance(content_items, list):
                for item in content_items:
                    if not isinstance(item, dict):
                        continue
                    item_type = item.get("type")
                    if item_type == "text":
                        text_parts.append(item.get("text", ""))
                    elif item_type == "tool_use":
                        tools.append(
                            {
                                "id": item.get("id"),
                                "name": item.get("name", "unknown"),
                                "input": self._truncate_large_arguments(item.get("input", {})),
                            }
                        )
                    # 'thinking' blocks are skipped entirely (they can be huge).

            extracted["content"] = "".join(text_parts)
            extracted["tools"] = tools

        return extracted
