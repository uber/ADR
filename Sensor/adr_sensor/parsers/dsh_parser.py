"""Parser for DeepSeek Harness v3 session logs."""

import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

import zstandard

from ..schemas.agent_event_schema import AgentEvent, ChatMessage, ToolUsage
from ..utils.string_utils import truncate_middle
from ..utils.timestamp_utils import normalize_timestamp
from .base_parser import BaseParser

MAX_LOG_AGE_DAYS = 14
MAX_TEXT_LENGTH = 1000
_SESSION_FILE_PATTERN = re.compile(r"^session(?:\.v(\d+))?\.jsonl(?:\.zstd)?$")
MAX_SUPPORTED_SESSION_VERSION = 3


class DshParser(BaseParser):
    """Parse DeepSeek Harness ``session.v3.jsonl[.zstd]`` files."""

    def __init__(self, max_age_days: int = MAX_LOG_AGE_DAYS, base_path: Optional[Path] = None):
        dsh_home = os.environ.get("DSH_HOME", "").strip()
        if dsh_home:
            home = Path(dsh_home).expanduser()
        else:
            home = Path.home() / ".dsh"
        self.base_path = Path(base_path).expanduser() if base_path is not None else home / "sessions"
        self.max_age_days = max_age_days

    def parse_all(self) -> List[AgentEvent]:
        if not self.base_path.is_dir():
            self.record_diagnostic("input_missing")
            print(f"[DSH] No logs found at {self.base_path}")
            return []

        cutoff = None
        if self.max_age_days > 0:
            cutoff = datetime.now(timezone.utc) - timedelta(days=self.max_age_days)

        files = self._select_session_generations()
        entries: Dict[str, AgentEvent] = {}
        for path in files:
            failure_code = "file_stat_error"
            try:
                if cutoff and datetime.fromtimestamp(path.stat().st_mtime, timezone.utc) < cutoff:
                    self.record_diagnostic("file_age_skipped")
                    continue
                failure_code = "file_read_error"
                entry = self.parse_session_file(path)
                if not entry or not entry.has_meaningful_content():
                    continue
                previous = entries.get(entry.session_id)
                if previous is None or self._revision(entry) > self._revision(previous):
                    entries[entry.session_id] = entry
            except (OSError, UnicodeError, ValueError, zstandard.ZstdError) as exc:
                self.record_diagnostic(failure_code)
                print(f"[DSH] Unable to read {path}: {exc}")
        print(f"[DSH] Found {len(entries)} sessions")
        return list(entries.values())

    @staticmethod
    def _revision(entry: AgentEvent) -> tuple:
        context = entry.session_context or {}
        updated_at = DshParser._timestamp(context.get("last_event_at")) or entry.timestamp
        return updated_at, context.get("event_count", 0)

    def _select_session_generations(self) -> List[Path]:
        """Select the highest generation per directory when it is current v3."""
        selected: Dict[Path, tuple[int, float, Path]] = {}
        candidates = [*self.base_path.glob("**/session.jsonl"), *self.base_path.glob("**/session.jsonl.zstd")]
        candidates.extend(self.base_path.glob("**/session.v*.jsonl"))
        candidates.extend(self.base_path.glob("**/session.v*.jsonl.zstd"))
        for path in candidates:
            match = _SESSION_FILE_PATTERN.fullmatch(path.name)
            if not match:
                continue
            version = int(match.group(1) or 0)
            try:
                mtime = path.stat().st_mtime
            except OSError as exc:
                self.record_diagnostic("file_stat_error")
                print(f"[DSH] Error inspecting {path}: {exc}")
                continue
            current = selected.get(path.parent)
            candidate = (version, mtime, path)
            if current is None or candidate[:2] > current[:2]:
                selected[path.parent] = candidate
        current_paths = []
        for version, _, path in sorted(selected.values(), key=lambda item: item[1], reverse=True):
            if version != MAX_SUPPORTED_SESSION_VERSION:
                self.record_diagnostic("unsupported_schema")
                print(f"[DSH] Unsupported session generation v{version} in {path.parent}")
                continue
            current_paths.append(path)
        return current_paths

    def parse_session_file(self, file_path: Path) -> Optional[AgentEvent]:
        data: Dict[str, Any] = {
            "id": None,
            "created_at": None,
            "cwd": None,
            "model": None,
            "messages": [],
            "pending_tools": {},
            "first_event_at": None,
            "last_event_at": None,
            "event_count": 0,
            "malformed_records": 0,
            "token_usage": {
                "input_tokens": 0,
                "output_tokens": 0,
                "total_tokens": 0,
                "cached_input_tokens": 0,
                "cache_write_input_tokens": 0,
                "reasoning_output_tokens": 0,
            },
            "context": {},
        }

        header_seen = False
        for line in self._iter_lines(file_path):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                self.record_diagnostic("record_decode_error")
                data["malformed_records"] += 1
                continue
            if not isinstance(event, dict):
                self.record_diagnostic("record_shape_error")
                data["malformed_records"] += 1
                continue
            if not header_seen:
                if event.get("type") != "session" or event.get("version") != MAX_SUPPORTED_SESSION_VERSION:
                    self.record_diagnostic("unsupported_schema")
                    print(f"[DSH] Unsupported or malformed session header in {file_path}")
                    return None
                if not isinstance(event.get("id"), str) or not event["id"]:
                    self.record_diagnostic("record_shape_error")
                    return None
                header_seen = True
                data["id"] = event["id"]
                data["created_at"] = self._timestamp(event.get("createdAt"))
                data["cwd"] = event.get("cwd") if isinstance(event.get("cwd"), str) else None
                data["context"]["session_metadata"] = {
                    key: value
                    for key, value in event.items()
                    if key not in {"type", "version", "id", "createdAt", "cwd"}
                }
                continue

            event_type = event.get("type")
            payload = event.get("data")
            if not isinstance(payload, dict):
                self.record_diagnostic("record_shape_error")
                data["malformed_records"] += 1
                continue
            data["event_count"] += 1
            event_time = self._timestamp(event.get("time"))
            if event_time:
                data["first_event_at"] = min(data["first_event_at"] or event_time, event_time)
                data["last_event_at"] = max(data["last_event_at"] or event_time, event_time)
            self._process_event(event_type, payload, data, event_time, event)

        if not header_seen:
            return None

        chat_history = []
        for index, message in enumerate(data["messages"]):
            chat_history.append(
                ChatMessage(
                    role=message["role"],
                    content=message["content"],
                    tools=[
                        ToolUsage(**{key: value for key, value in tool.items() if key != "_call_id"})
                        for tool in message["tools"]
                    ],
                    sequence_id=message.get("sequence_id") or f"{data['id']}_msg_{index}",
                )
            )

        if not chat_history:
            return None
        context = dict(data["context"])
        context["event_count"] = data["event_count"]
        context["malformed_records"] = data["malformed_records"]
        if data["last_event_at"]:
            context["last_event_at"] = data["last_event_at"].isoformat()
        token_usage = {key: value for key, value in data["token_usage"].items() if value}
        return AgentEvent(
            timestamp=data["created_at"] or data["first_event_at"] or datetime.now(timezone.utc),
            source="dsh",
            session_id=f"dsh_{data['id']}",
            project_path=data["cwd"],
            model=data["model"],
            chat_history=chat_history,
            raw_log_path=str(file_path),
            session_context=context or None,
            token_usage={"cumulative": token_usage} if token_usage else None,
        )

    def _process_event(
        self,
        event_type: str,
        payload: Dict[str, Any],
        data: Dict[str, Any],
        event_time: Optional[datetime],
        event: Dict[str, Any],
    ):
        if event_type == "user/message":
            message = payload.get("message", payload)
            if self._message_role(message) == "user":
                self._append_message(data, "user", message, message.get("id"))
                self._record_message_metadata(data, event_type, payload, message, event_time)
        elif event_type == "assistant/message":
            message = payload.get("message", payload)
            blocks = message.get("content", []) if isinstance(message, dict) else []
            tools = self._tools_from_blocks(blocks)
            content = self._blocks_text(blocks)
            if content or tools or isinstance(blocks, list) and blocks:
                data["messages"].append(
                    {
                        "role": "assistant",
                        "content": content,
                        "tools": tools,
                        "sequence_id": message.get("id") if isinstance(message, dict) else None,
                    }
                )
                for tool in tools:
                    data["pending_tools"][tool["_call_id"]] = tool
                self._record_message_metadata(data, event_type, payload, message, event_time)
            usage = payload.get("usage")
            if isinstance(usage, dict):
                for source_key, target_key in (
                    ("inputTokens", "input_tokens"),
                    ("outputTokens", "output_tokens"),
                    ("totalTokens", "total_tokens"),
                    ("cacheReadTokens", "cached_input_tokens"),
                    ("cacheWriteTokens", "cache_write_input_tokens"),
                    ("reasoningTokens", "reasoning_output_tokens"),
                ):
                    value = usage.get(source_key)
                    if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0:
                        data["token_usage"][target_key] += int(value)
            source = message.get("source", {}) if isinstance(message, dict) else {}
            if not isinstance(source, dict):
                source = {}
            data["model"] = payload.get("model") or source.get("model") or data["model"]
            if source.get("provider"):
                data["context"]["provider"] = source["provider"]
        elif event_type == "tool/call":
            call_id = payload.get("callId")
            if isinstance(call_id, str) and call_id and call_id not in data["pending_tools"]:
                tool = self._tool_dict(payload.get("name"), payload.get("arguments"), call_id)
                self._attach_tool(data, tool)
                data["pending_tools"][call_id] = tool
        elif event_type == "tool/result":
            message = payload.get("message", {})
            if not isinstance(message, dict):
                return
            source = message.get("source", {})
            if not isinstance(source, dict):
                source = {}
            call_id = source.get("callId") or message.get("toolCallId")
            tool = data["pending_tools"].get(call_id)
            blocks = message.get("content", [])
            is_replacement = self._record_tool_result_metadata(data, payload, message, event, event_time, call_id)
            if tool and not is_replacement:
                tool["result"] = self._blocks_text(blocks)
                is_error = self._has_error_result(blocks)
                tool["status"] = "error" if is_error else "success"
                error = payload.get("error")
                if is_error and error:
                    if isinstance(error, dict):
                        name = error.get("name")
                        code = error.get("code")
                        tool["error"] = ": ".join(str(value) for value in (name, code) if value) or str(error)
                    else:
                        tool["error"] = str(error)
                elif is_error:
                    tool["error"] = tool["result"]
        elif event_type in {"tool/ptc-dispatch-start", "tool/ptc-dispatch"}:
            call_id = payload.get("subCallId")
            if not isinstance(call_id, str) or not call_id:
                return
            tool = data["pending_tools"].get(call_id)
            if tool is None:
                tool = self._tool_dict(payload.get("name"), payload.get("arguments"), call_id)
                self._attach_tool(data, tool)
                data["pending_tools"][call_id] = tool
            if event_type == "tool/ptc-dispatch":
                tool["result"] = self._blocks_text(payload.get("content", []))
                tool["status"] = "error" if payload.get("isError") is True else "success"
                if tool["status"] == "error":
                    tool["error"] = tool["result"]
        elif event_type == "request/context":
            data["model"] = payload.get("model") or data["model"]
            if payload.get("provider"):
                data["context"]["provider"] = payload["provider"]
            if payload.get("contextWindow"):
                data["context"]["model_context_window"] = payload["contextWindow"]
        elif event_type == "request/header":
            header = payload.get("header", {})
            config = header.get("config", {}) if isinstance(header, dict) else {}
            if isinstance(config, dict):
                data["model"] = config.get("model") or data["model"]
        elif event_type == "system/message":
            message = payload.get("message", {})
            content = self._blocks_text(message.get("content", []) if isinstance(message, dict) else [])
            if content:
                data["context"].setdefault("system_messages", []).append(content)
        elif event_type in {"approval/asked", "approval/decided"}:
            data["context"].setdefault("approvals", []).append({"type": event_type, **payload})
        elif event_type == "approval/policy":
            data["context"]["approval_policy"] = payload.get("policy")
        elif event_type == "plan/mode":
            data["context"]["plan_mode"] = payload.get("active")
        elif event_type == "sandbox/mode":
            data["context"]["sandbox_mode"] = payload.get("mode")
        elif event_type == "permission/preset":
            data["context"]["permission_preset"] = payload.get("preset")

    def _append_message(self, data: Dict[str, Any], role: str, message: Dict[str, Any], sequence_id: Optional[str]):
        blocks = message.get("content", []) if isinstance(message, dict) else []
        content = self._blocks_text(blocks)
        if content or isinstance(blocks, list) and blocks:
            data["messages"].append({"role": role, "content": content, "tools": [], "sequence_id": sequence_id})

    @staticmethod
    def _record_message_metadata(
        data: Dict[str, Any],
        event_type: str,
        payload: Dict[str, Any],
        message: Dict[str, Any],
        event_time: Optional[datetime],
    ) -> None:
        sequence_id = message.get("id") or f"event-{data['event_count']}"
        metadata = {
            "event_type": event_type,
            "role": message.get("role"),
            "source": message.get("source"),
            "turn": payload.get("turn"),
            "step": payload.get("step"),
            "interrupted": payload.get("interrupted"),
            "timestamp": event_time.isoformat() if event_time else None,
            "content_parts": message.get("content"),
        }
        data["context"].setdefault("message_metadata", {})[sequence_id] = {
            key: value for key, value in metadata.items() if value is not None
        }

    @staticmethod
    def _record_tool_result_metadata(
        data: Dict[str, Any],
        payload: Dict[str, Any],
        message: Dict[str, Any],
        event: Dict[str, Any],
        event_time: Optional[datetime],
        call_id: Any,
    ) -> bool:
        surface_op = event.get("surfaceOp")
        is_replacement = isinstance(surface_op, dict) and surface_op.get("op") == "replace"
        metadata = {
            "call_id": call_id,
            "seq": event.get("seq"),
            "turn": payload.get("turn"),
            "step": payload.get("step"),
            "timestamp": event_time.isoformat() if event_time else None,
            "message_source": message.get("source"),
            "content_parts": message.get("content"),
            "surface_op": surface_op,
            "source_event_seqs": event.get("sourceEventSeqs"),
            "is_replacement": is_replacement,
        }
        if "error" in payload:
            metadata["error"] = payload["error"]
        if "meta" in payload:
            metadata["meta"] = payload["meta"]
        data["context"].setdefault("tool_result_metadata", []).append(
            {key: value for key, value in metadata.items() if value is not None}
        )
        return is_replacement

    @staticmethod
    def _attach_tool(data: Dict[str, Any], tool: Dict[str, Any]) -> None:
        message = next((item for item in reversed(data["messages"]) if item["role"] == "assistant"), None)
        if message is None:
            message = {"role": "assistant", "content": "", "tools": [], "sequence_id": None}
            data["messages"].append(message)
        message["tools"].append(tool)

    @staticmethod
    def _message_role(message: Any) -> Optional[str]:
        return message.get("role") if isinstance(message, dict) else None

    def _tools_from_blocks(self, blocks: Any) -> List[Dict[str, Any]]:
        tools = []
        for block in blocks if isinstance(blocks, list) else []:
            if isinstance(block, dict) and block.get("type") == "tool-call":
                call_id = block.get("id") or block.get("toolCallId") or block.get("callId")
                if call_id:
                    tools.append(self._tool_dict(block.get("name"), block.get("arguments"), call_id))
        return tools

    def _tool_dict(self, name: Any, arguments: Any, call_id: str) -> Dict[str, Any]:
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except json.JSONDecodeError:
                arguments = {"raw": arguments}
        if not isinstance(arguments, dict):
            arguments = {"raw": arguments} if arguments is not None else {}
        return {
            "_call_id": call_id,
            "tool_name": name or "unknown",
            "tool_type": "function_call",
            "arguments": arguments,
            "result": None,
            "status": "pending",
            "error": None,
        }

    @staticmethod
    def _blocks_text(blocks: Any) -> str:
        parts = []
        for block in blocks if isinstance(blocks, list) else []:
            if not isinstance(block, dict):
                continue
            if block.get("type") in {"text", "reasoning"} and block.get("text"):
                prefix = "[Reasoning]\n" if block["type"] == "reasoning" else ""
                parts.append(prefix + truncate_middle(str(block["text"]), max_length=MAX_TEXT_LENGTH, edge_chars=400))
            elif block.get("type") == "tool-result":
                parts.append(DshParser._blocks_text(block.get("content", [])))
        return "\n".join(part for part in parts if part)

    @staticmethod
    def _has_error_result(blocks: Any) -> bool:
        for block in blocks if isinstance(blocks, list) else []:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "tool-result" and block.get("isError") is True:
                return True
            if DshParser._has_error_result(block.get("content", [])):
                return True
        return False

    @staticmethod
    def _timestamp(value: Any) -> Optional[datetime]:
        if value is None or isinstance(value, bool):
            return None
        try:
            return normalize_timestamp(value)
        except (TypeError, ValueError, OSError, OverflowError):
            return None

    def _iter_lines(self, file_path: Path) -> Iterator[str]:
        if not file_path.name.endswith(".zstd"):
            with open(file_path, "rb") as handle:
                for line in handle:
                    # Only LF-terminated records are committed. Discard a torn
                    # tail before decoding: it may end inside a UTF-8 character.
                    if line.endswith(b"\n"):
                        yield line.decode("utf-8")
                    else:
                        self.record_diagnostic("incomplete_record")
            return
        with open(file_path, "rb") as raw:
            for frame in DshParser._iter_complete_zstd_frames(raw):
                # Unicode line separators may occur literally inside JSON
                # strings; JSONL record boundaries are LF only.
                yield from frame.decode("utf-8", errors="replace").split("\n")

    @staticmethod
    def _iter_complete_zstd_frames(raw: Any) -> Iterator[bytes]:
        """Yield complete frames and complete JSONL records from a torn final frame."""
        decoder = zstandard.ZstdDecompressor().decompressobj()
        frame_parts = []
        while chunk := raw.read(128 * 1024):
            pending = chunk
            while pending:
                decoded = decoder.decompress(pending)
                if decoded:
                    frame_parts.append(decoded)
                pending = decoder.unused_data
                if not decoder.eof:
                    break
                yield b"".join(frame_parts)
                decoder = zstandard.ZstdDecompressor().decompressobj()
                frame_parts = []
        if frame_parts:
            recovered = b"".join(frame_parts)
            last_newline = recovered.rfind(b"\n")
            if last_newline >= 0:
                yield recovered[: last_newline + 1]
