"""
Parser for OpenAI Codex CLI logs.
Reads JSONL files from ~/.codex/sessions/

Performance-optimized: Skips log files older than 2 weeks by default.
"""

import json
import traceback
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..schemas.agent_event_schema import AgentEvent, ChatMessage, ToolUsage
from ..utils.string_utils import truncate_middle
from ..utils.timestamp_utils import normalize_timestamp
from .base_parser import BaseParser

MAX_LOG_AGE_DAYS = 14


class CodexParser(BaseParser):
    """Parser for OpenAI Codex CLI JSONL log files."""

    def __init__(self, max_age_days: int = MAX_LOG_AGE_DAYS):
        self.base_path = Path.home() / ".codex/sessions"
        self.max_age_days = max_age_days

    def parse_all(self) -> List[AgentEvent]:
        """Parse all available Codex logs."""
        entries = []

        if not self.base_path.exists():
            print(f"[CODEX] No logs found at {self.base_path}")
            return entries

        jsonl_files = list(self.base_path.glob("**/*.jsonl"))
        print(f"[CODEX] Found {len(jsonl_files)} JSONL files")

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
            print(f"[CODEX] Skipped {skipped_count} files older than {self.max_age_days} days")

        print(f"[CODEX] Processing {len(filtered_files)} recent files")

        for jsonl_file in filtered_files:
            try:
                entry = self.parse_jsonl_file(jsonl_file)
                if entry and entry.has_meaningful_content():
                    entries.append(entry)
            except Exception as e:
                print(f"[CODEX] Error parsing {jsonl_file}: {e}")

        return entries

    def parse_jsonl_file(self, file_path: Path) -> Optional[AgentEvent]:
        """Parse a single JSONL file."""
        try:
            session_data: Dict[str, Any] = {
                "id": None,
                "timestamp": None,
                "cwd": None,
                "model": None,
                "messages": [],
                "pending_tool_calls": {},
            }

            with open(file_path, encoding="utf-8") as file:
                for line in file:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                        self._process_event(event, session_data)
                    except json.JSONDecodeError:
                        continue

            if not session_data["id"]:
                return None

            chat_history = []
            for i, msg_dict in enumerate(session_data["messages"]):
                tools = [
                    ToolUsage(
                        tool_name=tool_dict["tool_name"],
                        tool_type=tool_dict["tool_type"],
                        arguments=tool_dict["arguments"],
                        result=tool_dict.get("result"),
                        status=tool_dict.get("status"),
                        error=tool_dict.get("error"),
                    )
                    for tool_dict in msg_dict["tools"]
                ]

                sequence_id = f"{session_data['id']}_msg_{i}"

                chat_history.append(
                    ChatMessage(
                        role=msg_dict["role"],
                        content=msg_dict["content"],
                        tools=tools,
                        sequence_id=sequence_id,
                    )
                )

            return AgentEvent(
                timestamp=session_data["timestamp"] or datetime.now(timezone.utc),
                source="codex",
                session_id=f"codex_{session_data['id']}",
                project_path=session_data["cwd"],
                model=session_data["model"],
                chat_history=chat_history,
                raw_log_path=str(file_path),
            )

        except Exception as e:
            print(f"[CODEX] Error reading {file_path}: {e}")
            traceback.print_exc()
            return None

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

    def _parse_tool_arguments(self, raw_arguments: Any) -> Dict[str, Any]:
        """Coerce a tool's raw argument payload into a dict.

        Falls back to {"raw": ...} for anything that is not a JSON object, so a
        non-JSON command string is preserved rather than silently discarded.
        """
        if isinstance(raw_arguments, dict):
            return raw_arguments

        if isinstance(raw_arguments, str):
            try:
                parsed = json.loads(raw_arguments)
            except (json.JSONDecodeError, ValueError):
                return {"raw": raw_arguments}
            return parsed if isinstance(parsed, dict) else {"raw": raw_arguments}

        return {"raw": raw_arguments} if raw_arguments else {}

    def _normalize_tool_output(self, output: Any) -> Optional[str]:
        """Normalize a tool result to a truncated string.

        function_call_output carries a plain string; custom_tool_call_output
        carries a list of content items ({"type": "input_text", "text": ...}).
        """
        if output is None:
            return None

        if isinstance(output, str):
            text = output
        elif isinstance(output, list):
            parts = []
            for item in output:
                if isinstance(item, str):
                    parts.append(item)
                elif isinstance(item, dict):
                    value = item.get("text")
                    if isinstance(value, str):
                        parts.append(value)
            text = "\n".join(parts)
        else:
            text = str(output)

        if not text:
            return text

        return truncate_middle(text, max_length=1000, edge_chars=400)

    def _process_event(self, event: Dict[str, Any], session_data: Dict[str, Any]):
        """Process a single event."""
        evt_type = event.get("type")
        payload = event.get("payload", {})

        if evt_type == "session_meta":
            session_data["id"] = payload.get("id")
            if payload.get("timestamp"):
                session_data["timestamp"] = normalize_timestamp(payload.get("timestamp"))
            session_data["cwd"] = payload.get("cwd")

        elif evt_type == "turn_context":
            if payload.get("model"):
                session_data["model"] = payload.get("model")

        elif evt_type == "response_item":
            item_type = payload.get("type")

            if item_type == "message":
                role = payload.get("role")
                content_list = payload.get("content", [])
                text_content = ""
                for content_item in content_list:
                    if content_item.get("type") in ["input_text", "output_text"]:
                        text_content += content_item.get("text", "")

                if text_content:
                    session_data["messages"].append({"role": role, "content": text_content, "tools": []})

            elif item_type in ("function_call", "custom_tool_call"):
                call_id = payload.get("call_id")
                tool_name = payload.get("name")

                # The two record shapes differ in where the arguments live and how
                # they are encoded: function_call carries a JSON string under
                # "arguments", while custom_tool_call (used by agent tools such as
                # `exec`) carries a raw, frequently non-JSON string under "input".
                # Reading the wrong key yields a tool with no arguments at all,
                # which for a shell-execution tool discards the whole signal.
                if item_type == "custom_tool_call":
                    raw_arguments = payload.get("input", "")
                else:
                    raw_arguments = payload.get("arguments", "{}")

                arguments = self._parse_tool_arguments(raw_arguments)
                arguments = self._truncate_large_arguments(arguments)

                tool_dict = {
                    "tool_name": tool_name,
                    "tool_type": item_type,
                    "arguments": arguments,
                    "status": payload.get("status") or "pending",
                    "result": None,
                }

                if not session_data["messages"] or session_data["messages"][-1]["role"] != "assistant":
                    session_data["messages"].append({"role": "assistant", "content": "", "tools": []})

                session_data["messages"][-1]["tools"].append(tool_dict)
                session_data["pending_tool_calls"][call_id] = tool_dict

            elif item_type in ("function_call_output", "custom_tool_call_output"):
                call_id = payload.get("call_id")
                output = self._normalize_tool_output(payload.get("output"))

                if call_id in session_data["pending_tool_calls"]:
                    tool_dict = session_data["pending_tool_calls"][call_id]
                    tool_dict["result"] = output
                    tool_dict["status"] = "success"

            elif item_type == "reasoning":
                summary_list = payload.get("summary", [])
                reasoning_text = ""
                for summary_item in summary_list:
                    if summary_item.get("type") == "summary_text":
                        reasoning_text += summary_item.get("text", "") + "\n"

                if reasoning_text:
                    if (
                        not session_data["messages"]
                        or session_data["messages"][-1]["role"] != "assistant"
                        or session_data["messages"][-1]["tools"]
                    ):
                        session_data["messages"].append({"role": "assistant", "content": "", "tools": []})

                    current_content = session_data["messages"][-1]["content"]
                    if current_content:
                        session_data["messages"][-1]["content"] = (
                            current_content + "\n\n[Reasoning]\n" + reasoning_text
                        )
                    else:
                        session_data["messages"][-1]["content"] = "[Reasoning]\n" + reasoning_text
