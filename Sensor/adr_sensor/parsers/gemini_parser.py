"""Read Gemini CLI chat journals and legacy conversation snapshots.

The source contract is Google's chatRecordingTypes.ts / chatRecordingService.ts.
Journals upsert complete messages by ID; ADR retains activity across rewinds
and checkpoints because removing model context does not undo executed actions.
"""

import json
import os
import platform
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..schemas.agent_event_schema import AgentEvent, ChatMessage, ToolUsage
from ..utils.timestamp_utils import normalize_timestamp
from .base_parser import BaseParser


class GeminiParser(BaseParser):
    """Capture persisted Gemini CLI messages, tools, metadata and subagents."""

    def __init__(self, max_age_days: int = 14, base_path: Optional[Path] = None):
        home_override = os.environ.get("GEMINI_CLI_HOME")
        home = Path(home_override).expanduser() if home_override else Path.home()
        self.base_paths = [home / ".gemini" / "tmp"]
        if platform.system() == "Darwin":
            self.base_paths.append(home / ".cache" / ".gemini" / "tmp")
        if base_path is not None:
            self.base_paths = [Path(base_path).expanduser()]
        self.max_age_days = max_age_days

    def parse_all(self) -> List[AgentEvent]:
        entries: Dict[str, AgentEvent] = {}
        cutoff = (datetime.now(timezone.utc) - timedelta(days=self.max_age_days)).timestamp()
        seen_paths = set()
        for base in self.base_paths:
            if not base.is_dir():
                self.record_diagnostic("input_missing")
                continue
            for chats in sorted(base.glob("*/chats")):
                for path in sorted(chats.rglob("*")):
                    if path.suffix not in {".json", ".jsonl"}:
                        continue
                    failure_code = "file_stat_error"
                    try:
                        if not path.is_file() or path.resolve() in seen_paths:
                            continue
                        seen_paths.add(path.resolve())
                        if self.max_age_days > 0 and path.stat().st_mtime < cutoff:
                            self.record_diagnostic("file_age_skipped")
                            continue
                        failure_code = "file_read_error"
                        entry = self.parse_file(path)
                        if entry is None or not entry.has_meaningful_content():
                            continue
                        old = entries.get(entry.session_id)
                        # Legacy .json can remain after migration to .jsonl.
                        if old is None or self._revision(entry) > self._revision(old):
                            entries[entry.session_id] = entry
                    except (OSError, ValueError) as exc:
                        self.record_diagnostic(failure_code)
                        print(f"[GEMINI] Unable to read {path}: {exc}")
        return list(entries.values())

    @staticmethod
    def _revision(entry: AgentEvent) -> tuple:
        context = entry.session_context or {}
        return (
            normalize_timestamp(context["last_event_at"]),
            str(entry.raw_log_path).endswith(".jsonl"),
            context["event_count"],
        )

    @staticmethod
    def _timestamp(value: Any) -> Optional[datetime]:
        if value is None or isinstance(value, bool):
            return None
        try:
            return normalize_timestamp(value)
        except (TypeError, ValueError, OverflowError, OSError):
            return None

    def parse_file(self, path: Path) -> Optional[AgentEvent]:
        """Normalize a file without changing it or applying content redaction."""
        metadata: Dict[str, Any] = {}
        messages: Dict[str, dict] = {}
        controls = []
        permissions = []
        timestamps = []
        event_count = 0
        malformed = 0

        def add_message(message: Any) -> None:
            if not isinstance(message, dict) or not isinstance(message.get("id"), str):
                self.record_diagnostic("record_shape_error")
                return
            messages[message["id"]] = message
            timestamp = self._timestamp(message.get("timestamp"))
            if timestamp:
                timestamps.append(timestamp)
            calls = message.get("toolCalls")
            for call in calls if isinstance(calls, list) else []:
                if not isinstance(call, dict):
                    self.record_diagnostic("record_shape_error")
                    continue
                timestamp = self._timestamp(call.get("timestamp"))
                if timestamp:
                    timestamps.append(timestamp)
                if call.get("status") == "awaiting_approval":
                    permission = {"message_id": message["id"], "tool_call": call}
                    if permission not in permissions:
                        permissions.append(permission)

        failure_code = "file_stat_error"
        try:
            # Capture before reading: appended records can advance the revision,
            # but later writes must not give a partial read a newer file timestamp.
            modified_at = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
            failure_code = "file_read_error"
            with path.open(encoding="utf-8") as handle:
                if path.suffix == ".json":
                    records = [json.load(handle)]
                else:
                    records = []
                    for line in handle:
                        if not line.strip():
                            continue
                        try:
                            records.append(json.loads(line))
                        except json.JSONDecodeError:
                            self.record_diagnostic("record_decode_error")
                            malformed += 1
            for record in records:
                if not isinstance(record, dict):
                    self.record_diagnostic("record_shape_error")
                    malformed += 1
                    continue
                event_count += 1
                if "$rewindTo" in record:
                    controls.append(record)
                    continue
                if "id" in record:
                    add_message(record)
                    continue
                update = record.get("$set", record)
                if not isinstance(update, dict):
                    self.record_diagnostic("record_shape_error")
                    malformed += 1
                    continue
                if "$set" in record:
                    controls.append({"$set": {k: v for k, v in update.items() if k != "messages"}})
                metadata.update({k: v for k, v in update.items() if k != "messages"})
                checkpoint = update.get("messages")
                for message in checkpoint if isinstance(checkpoint, list) else []:
                    add_message(message)
        except (OSError, UnicodeError, ValueError) as exc:
            self.record_diagnostic(
                "record_decode_error" if isinstance(exc, json.JSONDecodeError) else failure_code
            )
            print(f"[GEMINI] Unable to parse {path}: {exc}")
            return None

        session_id = metadata.get("sessionId")
        if not isinstance(session_id, str) or not session_id:
            if event_count:
                self.record_diagnostic("record_shape_error")
            return None
        history = []
        message_metadata = {}
        model = None
        usage = {}
        for message_id, message in messages.items():
            role = message.get("type")
            details = {k: v for k, v in message.items() if k not in {"content", "toolCalls"}}
            if not isinstance(message.get("content", ""), str):
                details["content_parts"] = message.get("content")
            message_metadata[message_id] = details
            if role not in {"user", "gemini"}:
                details["content"] = message.get("content")
                continue
            calls = message.get("toolCalls")
            tools = []
            details["tool_metadata"] = []
            for call in calls if isinstance(calls, list) else []:
                if not isinstance(call, dict) or not isinstance(call.get("name"), str):
                    # Non-object calls were counted while collecting messages.
                    if isinstance(call, dict):
                        self.record_diagnostic("record_shape_error")
                    continue
                tools.append(self._tool(call))
                details["tool_metadata"].append({k: v for k, v in call.items() if k not in {"args", "result"}})
            content = self._text(message.get("content"))
            if content or tools or isinstance(message.get("content"), (dict, list)) and message["content"]:
                history.append(
                    ChatMessage(
                        role="assistant" if role == "gemini" else "user",
                        content=content,
                        tools=tools,
                        sequence_id=message_id,
                    )
                )
            if role == "gemini":
                if isinstance(message.get("model"), str):
                    model = message["model"]
                tokens = message.get("tokens")
                if isinstance(tokens, dict):
                    for key, value in tokens.items():
                        if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0:
                            usage[key] = usage.get(key, 0) + value

        if not history:
            return None
        updated = self._timestamp(metadata.get("lastUpdated"))
        if updated:
            timestamps.append(updated)
        timestamp = self._timestamp(metadata.get("startTime")) or (min(timestamps) if timestamps else modified_at)
        context = {
            "last_event_at": (max(timestamps) if timestamps else modified_at).isoformat(),
            "event_count": event_count,
            "session_metadata": metadata,
            "message_metadata": message_metadata,
            "history_scope": "all_recorded_branches",
            "journal_controls": controls,
            "permission_requests": permissions,
            "malformed_records": malformed,
        }
        if metadata.get("kind") == "subagent" and path.parent.name != "chats":
            context["parent_session_id"] = path.parent.name
        if malformed:
            print(f"[GEMINI] Skipped {malformed} malformed records in {path}")
        return AgentEvent(
            timestamp=timestamp,
            source="gemini",
            session_id=f"gemini_{session_id}",
            project_path=self._project_path(path),
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
                        ("cached", "cached_input_tokens"),
                        ("thoughts", "reasoning_output_tokens"),
                        ("tool", "tool_tokens"),
                        ("total", "total_tokens"),
                    )
                    if source in usage
                }
            }
            if usage
            else None,
        )

    def _project_path(self, path: Path) -> Optional[str]:
        chats = next((parent for parent in path.parents if parent.name == "chats"), None)
        if chats is None:
            return None
        project = chats.parent
        try:
            marker = (project / ".project_root").read_text(encoding="utf-8").strip()
            if marker:
                return marker
        except (OSError, UnicodeError) as exc:
            if not isinstance(exc, FileNotFoundError):
                self.record_diagnostic("file_read_error")
            pass
        try:
            registry = json.loads((project.parent.parent / "projects.json").read_text(encoding="utf-8"))
            projects = registry.get("projects", {}) if isinstance(registry, dict) else {}
            if isinstance(projects, dict):
                return next((key for key, value in projects.items() if value == project.name), None)
        except (OSError, UnicodeError, ValueError) as exc:
            if not isinstance(exc, FileNotFoundError):
                self.record_diagnostic(
                    "record_decode_error" if isinstance(exc, json.JSONDecodeError) else "file_read_error"
                )
            pass
        return None

    @staticmethod
    def _text(content: Any) -> str:
        if isinstance(content, str):
            return content
        parts = content if isinstance(content, list) else [content]
        return "\n".join(
            part if isinstance(part, str) else part["text"]
            for part in parts
            if isinstance(part, str) or isinstance(part, dict) and isinstance(part.get("text"), str)
        )

    @staticmethod
    def _tool(call: dict) -> ToolUsage:
        name = call["name"]
        server = None
        # Only the explicit qualified separator is unambiguous; older bare
        # names and truncated names do not establish server identity.
        if "__" in name and "..." not in name:
            server = name.removeprefix("mcp_").split("__", 1)[0] or None
        status = call.get("status") if isinstance(call.get("status"), str) else None
        result = call.get("result")
        serialized = result if isinstance(result, str) else json.dumps(result, ensure_ascii=False)
        args = call.get("args", {})
        return ToolUsage(
            tool_name=name,
            tool_type="mcp_tool" if server or name.startswith("mcp_") else "function_call",
            server_name=server,
            arguments=args if isinstance(args, dict) else {"raw": args},
            result=serialized if result is not None else None,
            status=status,
            error=serialized if status == "error" and result is not None else None,
        )
