"""
Parser for Claude Code logs.
Reads JSONL files from ~/.claude/projects/

Memory-optimized: Extracts only needed data immediately instead of
storing full raw JSON objects.

Performance-optimized: Skips log files older than 2 weeks by default.
"""

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from ..schemas.agent_event_schema import AgentEvent, ChatMessage, ToolUsage
from ..utils.string_utils import truncate_middle
from ..utils.timestamp_utils import normalize_timestamp
from .base_parser import BaseParser

MAX_LOG_AGE_DAYS = 14

# Transcript bookkeeping is expected even when it has no sessionId or message.
# Keep these kinds separate from unexpected envelopes; never use input types as
# diagnostic labels. New kinds still follow the existing extraction behavior.
_METADATA_RECORD_TYPES = frozenset(
    {
        "system",
        "progress",
        "attachment",
        "summary",
        "file-history-snapshot",
        "queue-operation",
        "custom-title",
        "ai-title",
        "tag",
        "agent-name",
        "agent-color",
        "last-prompt",
        "permission-mode",
        "pr-link",
        "content-replacement",
    }
)
_KNOWN_CONTENT_TYPES = frozenset(
    {
        "text",
        "tool_use",
        "tool_result",
        "image",
        "document",
        "thinking",
        "redacted_thinking",
        "tool_reference",
        "search_result",
        "server_tool_use",
        "web_search_tool_result",
        "web_fetch_tool_result",
        "code_execution_tool_result",
        "bash_code_execution_tool_result",
        "text_editor_code_execution_tool_result",
        "container_upload",
        "compaction",
        "resource",
        "resource_link",
        "audio",
    }
)


class ClaudeParser(BaseParser):
    """Parser for Claude Code JSONL log files."""

    def __init__(self, max_age_days: int = MAX_LOG_AGE_DAYS):
        self.base_path = Path.home() / ".claude/projects"
        self.max_age_days = max_age_days

    def parse_all(self) -> List[AgentEvent]:
        """Parse all available Claude Code logs."""
        entries = []

        try:
            base_exists = self.base_path.exists()
        except OSError:
            self.record_diagnostic("file_stat_error")
            raise
        if not base_exists:
            self.record_diagnostic("input_missing")
            print(f"[CLAUDE] No logs found at {self.base_path}")
            return entries

        try:
            jsonl_files = list(self.base_path.glob("**/*.jsonl"))
        except OSError:
            self.record_diagnostic("file_read_error")
            raise
        print(f"[CLAUDE] Found {len(jsonl_files)} JSONL files")

        cutoff_time = datetime.now(timezone.utc) - timedelta(days=self.max_age_days)
        filtered_files = []
        skipped_count = 0

        for jsonl_file in jsonl_files:
            try:
                mtime = datetime.fromtimestamp(jsonl_file.stat().st_mtime, tz=timezone.utc)
                if mtime >= cutoff_time:
                    filtered_files.append(jsonl_file)
                else:
                    self.record_diagnostic("file_age_skipped")
                    skipped_count += 1
            except (OSError, PermissionError):
                self.record_diagnostic("file_stat_error")
                skipped_count += 1

        if skipped_count > 0:
            print(f"[CLAUDE] Skipped {skipped_count} files older than {self.max_age_days} days")

        print(f"[CLAUDE] Processing {len(filtered_files)} recent files")

        for jsonl_file in filtered_files:
            try:
                file_entries = self.parse_jsonl_file(jsonl_file)
                entries.extend(file_entries)
            except Exception as e:
                self.record_diagnostic("parser_error")
                print(f"[CLAUDE] Error parsing {jsonl_file}: {e}")

        return entries

    def _normalize_result_content(self, result_content: Any) -> str:
        """Normalize result content which can be a string or list of content items."""
        if isinstance(result_content, str):
            return result_content

        if isinstance(result_content, list):
            self._diagnose_content_blocks(result_content)
            text_parts = []
            for item in result_content:
                if isinstance(item, dict):
                    if item.get("type") == "text" and isinstance(item.get("text"), str):
                        text_parts.append(item["text"])
            return "\n".join(text_parts)

        return str(result_content) if result_content else ""

    def _truncate_large_arguments(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
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

    def _decode_jsonl_line(self, line: str) -> Iterator[Any]:
        """Decode complete values on one physical line, retaining a valid prefix.

        NUL padding is accepted only between values, never inside JSON strings.
        Stop at the first damaged value rather than searching its text for another
        object or joining it to the next line of the transcript.
        """
        decoder = json.JSONDecoder()
        offset = 0
        while offset < len(line):
            while offset < len(line) and line[offset] in " \t\r\n\0":
                offset += 1
            if offset == len(line):
                return
            try:
                value, offset = decoder.raw_decode(line, offset)
            except (ValueError, RecursionError) as exc:
                # A writer may not have finished its final physical line yet.
                # Only recognizable JSON prefixes without a newline are expected
                # tails; terminated malformed records remain corruption signals.
                incomplete = (
                    isinstance(exc, json.JSONDecodeError)
                    and not line.endswith(("\n", "\r"))
                    and self._is_incomplete_json(exc)
                )
                self.record_diagnostic("incomplete_record" if incomplete else "record_decode_error")
                return
            yield value

    @staticmethod
    def _is_incomplete_json(error: json.JSONDecodeError) -> bool:
        """Recognize common interrupted JSON writes without repairing content."""
        suffix = error.doc[error.pos :].rstrip(" \t")
        if not suffix or error.msg.startswith("Unterminated string"):
            return True
        if error.msg == "Expecting value" and (
            suffix == "-" or any(token.startswith(suffix) for token in ("true", "false", "null"))
        ):
            return True
        if error.msg == "Expecting ',' delimiter" and suffix in (".", "e", "e+", "e-", "E", "E+", "E-"):
            return True
        if error.msg == "Invalid \\uXXXX escape":
            return suffix.startswith("u") and len(suffix) < 5 and all(c in "0123456789abcdefABCDEF" for c in suffix[1:])
        return False

    def _diagnose_content_blocks(self, content: List[Any]) -> None:
        """Observe ignored shapes/types without changing captured message data."""
        for item in content:
            if not isinstance(item, dict) or not isinstance(item.get("type"), str):
                self.record_diagnostic("record_shape_error")
            elif item["type"] not in _KNOWN_CONTENT_TYPES:
                self.record_diagnostic("unsupported_content_block")
            elif item["type"] == "text" and not isinstance(item.get("text"), str):
                self.record_diagnostic("record_shape_error")

    @staticmethod
    def _agent_id(obj: Dict[str, Any], file_path: Path) -> Optional[str]:
        """Identify documented subagent paths, including nested workflow logs."""
        if file_path.stem.startswith("agent-") and any(parent.name == "subagents" for parent in file_path.parents):
            return file_path.stem[len("agent-") :] or None
        agent_id = obj.get("agentId")
        return agent_id if isinstance(agent_id, str) and agent_id else None

    def parse_jsonl_file(self, file_path: Path) -> List[AgentEvent]:
        """Parse a transcript without letting a malformed record discard its peers."""
        entries = []
        sessions: Dict[Tuple[str, Optional[str]], Dict[str, Any]] = {}

        try:
            with open(file_path, encoding="utf-8") as file:
                for line in file:
                    for obj in self._decode_jsonl_line(line):
                        if not isinstance(obj, dict):
                            self.record_diagnostic("record_shape_error")
                            continue
                        msg_type = obj.get("type")
                        is_metadata = isinstance(msg_type, str) and msg_type in _METADATA_RECORD_TYPES
                        if isinstance(msg_type, str) and msg_type not in ("user", "assistant") and not is_metadata:
                            self.record_diagnostic("unsupported_record_type")
                        session_id = obj.get("sessionId")
                        if not isinstance(session_id, str) or not session_id:
                            if not is_metadata or "sessionId" in obj:
                                self.record_diagnostic("record_shape_error")
                            continue
                        if not isinstance(msg_type, str):
                            self.record_diagnostic("record_shape_error")
                            continue
                        if msg_type in ("user", "assistant"):
                            message = obj.get("message")
                            if not isinstance(message, dict) or not isinstance(message.get("content", ""), (str, list)):
                                self.record_diagnostic("record_shape_error")
                                continue

                        agent_id = self._agent_id(obj, file_path)
                        session_key = (session_id, agent_id)
                        if session_key not in sessions:
                            sessions[session_key] = {
                                "messages": [],
                                "timestamp": None,
                                "last_event_at": None,
                                "event_count": 0,
                                "project_path": None,
                                "model": None,
                                "agent_id": agent_id,
                            }
                        session = sessions[session_key]
                        session["event_count"] += 1
                        if isinstance(obj.get("cwd"), str) and not session["project_path"]:
                            session["project_path"] = obj["cwd"]

                        if "timestamp" in obj and not isinstance(obj["timestamp"], bool):
                            try:
                                ts = normalize_timestamp(obj["timestamp"])
                                session["timestamp"] = min(session["timestamp"] or ts, ts)
                                session["last_event_at"] = max(session["last_event_at"] or ts, ts)
                            except (TypeError, ValueError, OverflowError, OSError):
                                self.record_diagnostic("invalid_timestamp")
                        elif isinstance(obj.get("timestamp"), bool):
                            self.record_diagnostic("invalid_timestamp")

                        if msg_type == "assistant" and isinstance(obj["message"].get("model"), str):
                            session["model"] = obj["message"]["model"]

                        extracted_msg = self._extract_message_data(obj)
                        if extracted_msg:
                            session["messages"].append(extracted_msg)

        except (OSError, UnicodeError) as e:
            self.record_diagnostic("file_read_error")
            print(f"[CLAUDE] Error reading {file_path}: {e}")

        for (session_id, _), session_data in sessions.items():
            entry = self._create_entry_from_extracted_session(session_id, session_data, file_path)
            if entry and entry.has_meaningful_content():
                entries.append(entry)

        return entries

    def _extract_message_data(self, obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract only the needed data from a message object."""
        msg_type = obj.get("type")
        if msg_type not in ("user", "assistant"):
            return None

        message = obj.get("message")
        if not isinstance(message, dict):
            return None

        extracted: Dict[str, Any] = {
            "type": msg_type,
            "uuid": obj.get("uuid") if isinstance(obj.get("uuid"), str) else None,
        }
        content = message.get("content", "")
        text_parts = []
        if isinstance(content, str):
            text_parts.append(content)
        elif isinstance(content, list):
            self._diagnose_content_blocks(content)
            text_parts.extend(
                item["text"]
                for item in content
                if isinstance(item, dict) and item.get("type") == "text" and isinstance(item.get("text"), str)
            )
        extracted["content"] = "".join(text_parts)

        if msg_type == "user":
            tool_results = []
            if isinstance(content, list):
                for item in content:
                    if isinstance(item, dict) and item.get("type") == "tool_result":
                        tool_use_id = item.get("tool_use_id")
                        if not isinstance(tool_use_id, str) or not tool_use_id:
                            self.record_diagnostic("record_shape_error")
                            continue
                        result_content = item.get("content", "")
                        if "toolUseResult" in obj and isinstance(obj["toolUseResult"], dict):
                            result_content = obj["toolUseResult"].get("result", result_content)

                        result_content = self._normalize_result_content(result_content)

                        if result_content and isinstance(result_content, str):
                            result_content = truncate_middle(result_content, max_length=1000, edge_chars=400)
                        tool_results.append({"tool_use_id": tool_use_id, "result": result_content})

            extracted["tool_results"] = tool_results

        elif msg_type == "assistant":
            tools = []
            if isinstance(content, list):
                for item in content:
                    if not isinstance(item, dict) or item.get("type") != "tool_use":
                        continue
                    raw_input = item.get("input", {})
                    name = item.get("name", "unknown")
                    if not isinstance(raw_input, dict) or not isinstance(name, str):
                        self.record_diagnostic("record_shape_error")
                        continue
                    tool_id = item.get("id")
                    if not isinstance(tool_id, str) or not tool_id:
                        self.record_diagnostic("record_shape_error")
                    tools.append(
                        {
                            "id": tool_id if isinstance(tool_id, str) else None,
                            "name": name,
                            "input": self._truncate_large_arguments(raw_input),
                        }
                    )
            extracted["tools"] = tools

        return extracted

    def _create_entry_from_extracted_session(
        self, session_id: str, session_data: Dict[str, Any], file_path: Path
    ) -> Optional[AgentEvent]:
        """Create an AgentEvent from pre-extracted session data."""
        try:
            chat_history: List[ChatMessage] = []
            # Store exact locations: distinct invocations can have equal fields.
            pending_tools: Dict[str, Tuple[int, int]] = {}

            for i, msg_data in enumerate(session_data["messages"]):
                msg_type = msg_data["type"]
                sequence_id = msg_data.get("uuid") or f"msg_{i}"

                if msg_type == "user":
                    tool_results = msg_data.get("tool_results", [])
                    if tool_results:
                        for tool_result in tool_results:
                            tool_use_id = tool_result.get("tool_use_id")
                            result = tool_result.get("result")
                            if tool_use_id in pending_tools:
                                message_index, tool_index = pending_tools[tool_use_id]
                                old_message = chat_history[message_index]
                                new_tools = list(old_message.tools)
                                new_tools[tool_index] = replace(
                                    new_tools[tool_index],
                                    result=result,
                                    status="success" if result else "unknown",
                                )
                                chat_history[message_index] = replace(old_message, tools=new_tools)

                    content = msg_data.get("content", "")
                    if content:
                        msg = ChatMessage(role="user", content=content, tools=[], sequence_id=sequence_id)
                        chat_history.append(msg)

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
                            pending_tools[tool_id] = (len(chat_history), len(tools) - 1)

                    if content or tools:
                        msg = ChatMessage(
                            role="assistant",
                            content=content or "[Assistant used tools]",
                            tools=tools,
                            sequence_id=sequence_id,
                        )
                        chat_history.append(msg)

            timestamp = session_data["timestamp"]
            if timestamp is None:
                timestamp = datetime.fromtimestamp(file_path.stat().st_mtime, tz=timezone.utc)
            context = {
                "last_event_at": (session_data["last_event_at"] or timestamp).isoformat(),
                "event_count": session_data["event_count"],
            }
            entry_session_id = f"claude_{session_id}"
            agent_id = session_data["agent_id"]
            if agent_id:
                context["parent_session_id"] = entry_session_id
                context["agent_id"] = agent_id
                entry_session_id += f"_agent_{agent_id}"

            return AgentEvent(
                timestamp=timestamp,
                source="claude",
                session_id=entry_session_id,
                chat_history=chat_history,
                project_path=session_data["project_path"],
                model=session_data["model"],
                raw_log_path=str(file_path),
                session_context=context,
            )

        except Exception as e:
            self.record_diagnostic("file_stat_error" if isinstance(e, OSError) else "session_build_error")
            print(f"[CLAUDE] Error creating entry for session {session_id}: {e}")
            return None
