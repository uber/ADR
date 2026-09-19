"""
Parser for Claude Code logs.
Reads JSONL files from ~/.claude/projects/

Memory-optimized: Extracts only needed data immediately instead of
storing full raw JSON objects.

Performance-optimized: Skips log files older than 2 weeks by default.
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..schemas.agent_event_schema import AgentEvent, ChatMessage, ToolUsage
from ..utils.string_utils import truncate_middle
from ..utils.timestamp_utils import normalize_timestamp
from .base_parser import BaseParser

MAX_LOG_AGE_DAYS = 14


class ClaudeParser(BaseParser):
    """Parser for Claude Code JSONL log files."""

    def __init__(self, max_age_days: int = MAX_LOG_AGE_DAYS):
        self.base_path = Path.home() / ".claude/projects"
        self.max_age_days = max_age_days

    def parse_all(self) -> List[AgentEvent]:
        """Parse all available Claude Code logs."""
        entries = []

        if not self.base_path.exists():
            print(f"[CLAUDE] No logs found at {self.base_path}")
            return entries

        jsonl_files = list(self.base_path.glob("**/*.jsonl"))
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
                    skipped_count += 1
            except (OSError, PermissionError):
                skipped_count += 1

        if skipped_count > 0:
            print(f"[CLAUDE] Skipped {skipped_count} files older than {self.max_age_days} days")

        print(f"[CLAUDE] Processing {len(filtered_files)} recent files")

        for jsonl_file in filtered_files:
            try:
                file_entries = self.parse_jsonl_file(jsonl_file)
                entries.extend(file_entries)
            except Exception as e:
                print(f"[CLAUDE] Error parsing {jsonl_file}: {e}")

        return entries

    def _classify_tool(self, tool_name: str) -> tuple:
        """Classify a Claude Code tool call and attribute MCP tools to their server.

        Claude Code namespaces MCP tools as ``mcp__<server>__<tool>``, so the server is
        recoverable from the name alone. Without this, every call — including third-party
        MCP servers — collapses into a single ``tool_use`` bucket with no server attribution.
        """
        if tool_name.startswith("mcp__"):
            parts = tool_name.split("__")
            if len(parts) >= 3 and parts[1]:
                return "mcp_tool", parts[1]
            return "mcp_tool", None

        if tool_name in ("Bash", "PowerShell", "BashOutput", "KillShell"):
            return "terminal_command", None

        return "tool_use", None

    def _normalize_result_content(self, result_content: Any) -> str:
        """Normalize result content which can be a string or list of content items."""
        if isinstance(result_content, str):
            return result_content

        if isinstance(result_content, list):
            text_parts = []
            for item in result_content:
                if isinstance(item, dict):
                    if item.get("type") == "text" and "text" in item:
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

    def parse_jsonl_file(self, file_path: Path) -> List[AgentEvent]:
        """Parse a single JSONL file."""
        entries = []
        sessions: Dict[str, Dict[str, Any]] = {}

        try:
            with open(file_path, encoding="utf-8") as file:
                for line_num, line in enumerate(file):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    session_id = obj.get("sessionId")
                    if not session_id:
                        continue

                    if session_id not in sessions:
                        sessions[session_id] = {
                            "messages": [],
                            "timestamp": None,
                            "project_path": obj.get("cwd"),
                            "model": None,
                        }

                    if "timestamp" in obj:
                        try:
                            ts = normalize_timestamp(obj["timestamp"])
                            if sessions[session_id]["timestamp"] is None or ts < sessions[session_id]["timestamp"]:
                                sessions[session_id]["timestamp"] = ts
                        except Exception:
                            pass

                    if obj.get("type") == "assistant" and "message" in obj:
                        msg = obj["message"]
                        if "model" in msg:
                            sessions[session_id]["model"] = msg["model"]

                    extracted_msg = self._extract_message_data(obj)
                    if extracted_msg:
                        sessions[session_id]["messages"].append(extracted_msg)

                    del obj

            for session_id, session_data in sessions.items():
                entry = self._create_entry_from_extracted_session(session_id, session_data, file_path)
                if entry and entry.has_meaningful_content():
                    entries.append(entry)

        except Exception as e:
            print(f"[CLAUDE] Error reading {file_path}: {e}")

        return entries

    def _extract_message_data(self, obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract only the needed data from a message object."""
        msg_type = obj.get("type")
        if msg_type not in ("user", "assistant"):
            return None

        extracted: Dict[str, Any] = {
            "type": msg_type,
            "uuid": obj.get("uuid"),
            "parent_uuid": obj.get("parentUuid"),
        }

        if "message" not in obj:
            return None

        message = obj["message"]

        if msg_type == "user":
            content = message.get("content", "")

            tool_results = []
            if isinstance(content, list):
                for item in content:
                    if isinstance(item, dict) and item.get("type") == "tool_result":
                        tool_use_id = item.get("tool_use_id")
                        result_content = item.get("content", "")
                        if "toolUseResult" in obj and isinstance(obj["toolUseResult"], dict):
                            result_content = obj["toolUseResult"].get("result", result_content)

                        result_content = self._normalize_result_content(result_content)

                        if result_content and isinstance(result_content, str):
                            result_content = truncate_middle(result_content, max_length=1000, edge_chars=400)
                        tool_results.append(
                            {
                                "tool_use_id": tool_use_id,
                                "result": result_content,
                                "is_error": bool(item.get("is_error")),
                            }
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
                    if isinstance(item, dict):
                        if item.get("type") == "text":
                            text_parts.append(item.get("text", ""))
                        elif item.get("type") == "tool_use":
                            raw_input = item.get("input", {})
                            truncated_input = self._truncate_large_arguments(raw_input)
                            tools.append({
                                "id": item.get("id"),
                                "name": item.get("name", "unknown"),
                                "input": truncated_input,
                            })

            extracted["content"] = "".join(text_parts)
            extracted["tools"] = tools

        return extracted

    def _create_entry_from_extracted_session(
        self, session_id: str, session_data: Dict[str, Any], file_path: Path
    ) -> Optional[AgentEvent]:
        """Create an AgentEvent from pre-extracted session data."""
        try:
            entry = AgentEvent(
                timestamp=session_data["timestamp"] or datetime.now(timezone.utc),
                source="claude",
                session_id=f"claude_{session_id}",
                project_path=session_data["project_path"],
                model=session_data["model"],
            )

            pending_tools: Dict[str, ToolUsage] = {}

            for i, msg_data in enumerate(session_data["messages"]):
                msg_type = msg_data["type"]
                sequence_id = msg_data.get("uuid") or f"msg_{i}"

                if msg_type == "user":
                    tool_results = msg_data.get("tool_results", [])
                    if tool_results:
                        for tool_result in tool_results:
                            tool_use_id = tool_result.get("tool_use_id")
                            result = tool_result.get("result")
                            is_error = tool_result.get("is_error", False)
                            if tool_use_id in pending_tools:
                                old_tool = pending_tools[tool_use_id]
                                if is_error:
                                    status = "error"
                                elif result:
                                    status = "success"
                                else:
                                    status = "unknown"
                                updated_tool = ToolUsage(
                                    tool_name=old_tool.tool_name,
                                    tool_type=old_tool.tool_type,
                                    server_name=old_tool.server_name,
                                    arguments=old_tool.arguments,
                                    result=result,
                                    status=status,
                                    error=result if is_error else None,
                                )
                                for msg in entry.chat_history:
                                    if msg.role == "assistant":
                                        for idx, t in enumerate(msg.tools):
                                            if t == old_tool:
                                                new_tools = list(msg.tools)
                                                new_tools[idx] = updated_tool
                                                object.__setattr__(msg, "tools", new_tools)
                                                break
                        continue

                    content = msg_data.get("content", "")
                    if content:
                        msg = ChatMessage(role="user", content=content, tools=[], sequence_id=sequence_id)
                        entry.chat_history.append(msg)

                elif msg_type == "assistant":
                    content = msg_data.get("content", "")
                    tools = []

                    for tool_data in msg_data.get("tools", []):
                        tool_name = tool_data.get("name", "unknown")
                        tool_type, server_name = self._classify_tool(tool_name)
                        tool = ToolUsage(
                            tool_name=tool_name,
                            tool_type=tool_type,
                            server_name=server_name,
                            arguments=tool_data.get("input", {}),
                            result=None,
                        )
                        tools.append(tool)
                        tool_id = tool_data.get("id")
                        if tool_id:
                            pending_tools[tool_id] = tool

                    if content or tools:
                        msg = ChatMessage(
                            role="assistant",
                            content=content or "[Assistant used tools]",
                            tools=tools,
                            sequence_id=sequence_id,
                        )
                        entry.chat_history.append(msg)

            return entry

        except Exception as e:
            print(f"[CLAUDE] Error creating entry for session {session_id}: {e}")
            return None
