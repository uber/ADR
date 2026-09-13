"""Read Pi's versioned local JSONL sessions, preserving every recorded branch."""

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..schemas.agent_event_schema import AgentEvent, ChatMessage, ToolUsage
from ..utils.timestamp_utils import normalize_timestamp
from .base_parser import BaseParser


class PiParser(BaseParser):
    """Normalize the v1-v3 session contract documented by Pi's session manager."""

    def __init__(self, max_age_days: int = 14, base_path: Optional[Path] = None):
        agent_override = os.environ.get("PI_CODING_AGENT_DIR")
        agent_dir = Path(agent_override).expanduser() if agent_override else Path.home() / ".pi" / "agent"
        session_override = os.environ.get("PI_CODING_AGENT_SESSION_DIR")
        self.base_path = Path(session_override).expanduser() if session_override else agent_dir / "sessions"
        if base_path is not None:
            self.base_path = Path(base_path).expanduser()
        self.max_age_days = max_age_days

    def parse_all(self) -> List[AgentEvent]:
        entries: Dict[str, AgentEvent] = {}
        if not self.base_path.is_dir():
            return []
        cutoff = (datetime.now(timezone.utc) - timedelta(days=self.max_age_days)).timestamp()
        for path in sorted(self.base_path.rglob("*.jsonl")):
            try:
                if not path.is_file() or (self.max_age_days > 0 and path.stat().st_mtime < cutoff):
                    continue
                entry = self.parse_file(path)
                if entry is None or not entry.has_meaningful_content():
                    continue
                old = entries.get(entry.session_id)
                if old is None or self._revision(entry) > self._revision(old):
                    entries[entry.session_id] = entry
            except (OSError, ValueError) as exc:
                print(f"[PI] Unable to read {path}: {exc}")
        return list(entries.values())

    @staticmethod
    def _revision(entry: AgentEvent) -> tuple:
        context = entry.session_context or {}
        return normalize_timestamp(context["last_event_at"]), context["event_count"]

    @staticmethod
    def _timestamp(value: Any) -> Optional[datetime]:
        if value is None or isinstance(value, bool):
            return None
        try:
            return normalize_timestamp(value)
        except (TypeError, ValueError, OverflowError, OSError):
            return None

    @staticmethod
    def _text(content: Any) -> str:
        if isinstance(content, str):
            return content
        if not isinstance(content, list):
            return ""
        return "\n".join(
            part["text"] for part in content if isinstance(part, dict) and isinstance(part.get("text"), str)
        )

    def parse_file(self, path: Path) -> Optional[AgentEvent]:
        records = []
        malformed = 0
        try:
            modified_at = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
            with path.open(encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, 1):
                    if not line.strip():
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        malformed += 1
                        continue
                    if isinstance(record, dict):
                        records.append((line_number, record))
                    else:
                        malformed += 1
        except (OSError, UnicodeError) as exc:
            print(f"[PI] Unable to parse {path}: {exc}")
            return None

        if not records or records[0][1].get("type") != "session":
            return None
        header = records[0][1]
        session_id = header.get("id")
        version = header.get("version", 1)
        if not isinstance(session_id, str) or not session_id:
            return None
        if type(version) is not int or version not in {1, 2, 3}:
            print(f"[PI] Unsupported session version in {path}")
            return None

        messages = []
        entry_metadata = []
        parents = {}
        # Per-entry call tables avoid correlating identical call IDs on sibling branches.
        calls_by_entry = {}
        resolved_calls = set()
        timestamps = []
        usage = {}
        model = None
        previous_id = None

        def add_usage(raw: Any) -> None:
            if isinstance(raw, dict):
                for key, value in raw.items():
                    if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0:
                        usage[key] = usage.get(key, 0) + value

        def find_call(parent: Any, call_id: Any) -> Optional[tuple]:
            seen = set()
            while isinstance(parent, str) and parent not in seen:
                seen.add(parent)
                calls = calls_by_entry.get(parent, {})
                if isinstance(call_id, str) and call_id in calls:
                    return parent, calls[call_id]
                parent = parents.get(parent)
            return None

        for line_number, record in records[1:]:
            entry_id = record.get("id")
            if not isinstance(entry_id, str):
                entry_id = f"line-{line_number}"
            parent = record.get("parentId") if version >= 2 else previous_id
            parents[entry_id] = parent
            previous_id = entry_id
            timestamp = self._timestamp(record.get("timestamp"))
            if timestamp:
                timestamps.append(timestamp)
            details = {k: v for k, v in record.items() if k != "message"}
            details["entry_id"] = entry_id
            entry_metadata.append(details)
            kind = record.get("type")
            if kind == "model_change" and isinstance(record.get("modelId"), str):
                model = record["modelId"]
            if kind in {"compaction", "branch_summary"}:
                add_usage(record.get("usage"))
            if kind == "custom_message":
                content = self._text(record.get("content"))
                if content:
                    messages.append({"role": "system", "content": content, "tools": [], "sequence_id": entry_id})
                continue
            message = record.get("message")
            if kind != "message" or not isinstance(message, dict):
                continue
            details["message_metadata"] = {k: v for k, v in message.items() if k != "content"}
            content = message.get("content")
            # Retain source-typed blocks, including recorded thinking and images.
            if not isinstance(content, str):
                details["content_parts"] = content
            timestamp = self._timestamp(message.get("timestamp"))
            if timestamp:
                timestamps.append(timestamp)
            role = message.get("role")
            add_usage(message.get("usage"))
            if role == "assistant" and isinstance(message.get("model"), str):
                model = message["model"]
            if role == "toolResult":
                match = find_call(parent, message.get("toolCallId"))
                result = self._text(content)
                status = (
                    "error"
                    if message.get("isError") is True
                    else ("success" if message.get("isError") is False else None)
                )
                details["result_content"] = content
                if match is not None:
                    call_entry_id, tool = match
                    details["tool_call_entry_id"] = call_entry_id
                    key = (call_entry_id, message["toolCallId"])
                    if key not in resolved_calls:
                        tool.update(result=result, status=status, error=result if status == "error" else None)
                        resolved_calls.add(key)
                        continue
                    # A branch can reuse an ancestor call with a different result.
                    # Keep the first result on the invocation and emit subsequent
                    # results separately, without counting another invocation.
                    details["additional_tool_result"] = True
                else:
                    details["orphan_tool_result"] = True
                if result or isinstance(content, list):
                    messages.append({"role": "tool", "content": result, "tools": [], "sequence_id": entry_id})
                continue
            if role == "bashExecution":
                result = message.get("output")
                result = result if isinstance(result, str) else ""
                code = message.get("exitCode")
                status = (
                    "cancelled"
                    if message.get("cancelled")
                    else (("success" if code == 0 else "error") if type(code) is int else None)
                )
                messages.append(
                    {
                        "role": "user",
                        "content": "",
                        "sequence_id": entry_id,
                        "tools": [
                            {
                                "tool_name": "bash",
                                "tool_type": "terminal_command",
                                "arguments": {"command": message.get("command")},
                                "result": result,
                                "status": status,
                                "error": result if status == "error" else None,
                            }
                        ],
                    }
                )
                continue
            if role not in {"user", "assistant", "custom", "hookMessage"}:
                details["content"] = content
                continue
            tools = []
            if role == "assistant" and isinstance(content, list):
                for part in content:
                    if not isinstance(part, dict) or part.get("type") != "toolCall":
                        continue
                    name = part.get("name")
                    if not isinstance(name, str):
                        continue
                    args = part.get("arguments", {})
                    tool = {
                        "tool_name": name,
                        "tool_type": "function_call",
                        "arguments": args if isinstance(args, dict) else {"raw": args},
                        "status": "pending",
                    }
                    tools.append(tool)
                    call_id = part.get("id")
                    if isinstance(call_id, str):
                        calls_by_entry.setdefault(entry_id, {})[call_id] = tool
            text = self._text(content)
            if text or tools or (isinstance(content, list) and content):
                messages.append(
                    {
                        "role": role if role in {"user", "assistant"} else "system",
                        "content": text,
                        "tools": tools,
                        "sequence_id": entry_id,
                    }
                )

        history = [
            ChatMessage(**{**message, "tools": [ToolUsage(**tool) for tool in message["tools"]]})
            for message in messages
        ]
        if not history:
            return None
        timestamp = self._timestamp(header.get("timestamp")) or (min(timestamps) if timestamps else modified_at)
        context = {
            "last_event_at": (max(timestamps) if timestamps else timestamp).isoformat(),
            "event_count": len(records),
            "session_metadata": header,
            "entries": entry_metadata,
            "history_scope": "all_recorded_branches",
            "malformed_records": malformed,
        }
        if malformed:
            print(f"[PI] Skipped {malformed} malformed records in {path}")
        return AgentEvent(
            timestamp=timestamp,
            source="pi",
            session_id=f"pi_{session_id}",
            project_path=header.get("cwd") if isinstance(header.get("cwd"), str) else None,
            model=model,
            chat_history=history,
            raw_log_path=str(path),
            session_context=context,
            token_usage={
                "cumulative": {
                    target: usage[source]
                    for source, target in (
                        ("input", "input_tokens"),
                        ("output", "output_tokens"),
                        ("cacheRead", "cached_input_tokens"),
                        ("cacheWrite", "cache_write_tokens"),
                        ("reasoning", "reasoning_output_tokens"),
                        ("totalTokens", "total_tokens"),
                    )
                    if source in usage
                }
            }
            if usage
            else None,
        )
