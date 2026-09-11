"""
Parser for OpenAI Codex CLI logs.
Reads JSONL files from ~/.codex/sessions/
"""

import json
import re
import traceback
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..schemas.agent_event_schema import AgentEvent, ChatMessage, ToolUsage
from ..utils.string_utils import truncate_middle
from ..utils.timestamp_utils import normalize_timestamp
from .base_parser import BaseParser

MAX_ARGUMENT_JSON_LENGTH = 100_000
MAX_NORMALIZATION_DEPTH = 8
MAX_COLLECTION_ITEMS = 100
MAX_TEXT_LENGTH = 1000
_DEPTH_LIMIT_MARKER = "[truncated: maximum depth reached]"
_MCP_NAME_PART = re.compile(r"^[A-Za-z0-9_-]+$")
_CALL_ID_KEYS = (
    "call_id",
    "callId",
    "callID",
    "tool_call_id",
    "toolCallId",
    "toolCallID",
    "id",
)
_SUCCESS_STATES = frozenset({"success", "succeeded", "completed", "complete", "done", "ok"})
_ERROR_STATES = frozenset(
    {"error", "failed", "failure", "cancelled", "canceled", "rejected", "timed_out", "timeout"}
)
_PENDING_STATES = frozenset({"pending", "in_progress", "running", "queued", "started"})
_NON_TEXT_CONTENT_TYPES = frozenset(
    {"computer_screenshot", "image", "image_url", "input_image", "output_image"}
)
_TEXT_CONTENT_TYPES = frozenset({"input_text", "output_text", "text"})


class CodexParser(BaseParser):
    """Parser for OpenAI Codex CLI JSONL log files."""

    def __init__(self):
        self.base_path = Path.home() / ".codex/sessions"

    def parse_all(self) -> List[AgentEvent]:
        """Parse all available Codex logs."""
        entries = []

        if not self.base_path.exists():
            print(f"[CODEX] No logs found at {self.base_path}")
            return entries

        jsonl_files = list(self.base_path.glob("**/*.jsonl"))
        print(f"[CODEX] Found {len(jsonl_files)} JSONL files")

        for jsonl_file in jsonl_files:
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
                        if not isinstance(event, Mapping):
                            continue

                        payload = event.get("payload")
                        if not isinstance(payload, Mapping):
                            continue

                        self._process_event(event, payload, session_data)
                    except Exception:
                        # Rollout records evolve independently; keep a malformed
                        # record from invalidating the rest of the session.
                        continue

            if not session_data["id"]:
                return None

            chat_history = []
            for i, msg_dict in enumerate(session_data["messages"]):
                tools = [
                    ToolUsage(
                        tool_name=tool_dict["tool_name"],
                        tool_type=tool_dict["tool_type"],
                        server_name=tool_dict.get("server_name"),
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

    def _bound_value(self, value: Any, depth: int = 0) -> Any:
        """Bound nested values before retaining them in an event."""
        if isinstance(value, str):
            return truncate_middle(value, max_length=MAX_TEXT_LENGTH, edge_chars=400)

        if value is None or isinstance(value, (bool, int, float)):
            return value

        if depth >= MAX_NORMALIZATION_DEPTH:
            return _DEPTH_LIMIT_MARKER

        if isinstance(value, Mapping):
            bounded: Dict[str, Any] = {}
            for index, (key, item) in enumerate(value.items()):
                if index >= MAX_COLLECTION_ITEMS:
                    break
                bounded_key = truncate_middle(str(key), max_length=MAX_TEXT_LENGTH, edge_chars=400)
                bounded[bounded_key] = self._bound_value(item, depth + 1)
            return bounded

        if isinstance(value, (list, tuple)):
            return [self._bound_value(item, depth + 1) for item in value[:MAX_COLLECTION_ITEMS]]

        return truncate_middle(str(value), max_length=MAX_TEXT_LENGTH, edge_chars=400)

    def _parse_tool_arguments(self, raw_arguments: Any) -> Dict[str, Any]:
        """Coerce a tool's raw arguments into a recursively bounded dict."""
        if raw_arguments is None or raw_arguments == "":
            return {}

        if isinstance(raw_arguments, str):
            if len(raw_arguments) <= MAX_ARGUMENT_JSON_LENGTH:
                try:
                    raw_arguments = json.loads(raw_arguments)
                except (json.JSONDecodeError, RecursionError, ValueError):
                    pass

        if isinstance(raw_arguments, Mapping):
            return self._bound_value(raw_arguments)

        return {"raw": self._bound_value(raw_arguments)}

    @staticmethod
    def _decode_output_container(output: Any) -> Any:
        """Decode bounded JSON object/array strings so structural signals remain visible."""
        if not isinstance(output, str) or len(output) > MAX_ARGUMENT_JSON_LENGTH:
            return output

        try:
            decoded = json.loads(output)
        except (json.JSONDecodeError, RecursionError, ValueError):
            return output
        return decoded if isinstance(decoded, (Mapping, list)) else output

    def _flatten_result_parts(self, value: Any, depth: int = 0, in_collection: bool = False) -> List[str]:
        """Flatten common content containers without interpreting their prose."""
        if value is None:
            return []

        if isinstance(value, str):
            return [truncate_middle(value, max_length=MAX_TEXT_LENGTH, edge_chars=400)]

        if depth >= MAX_NORMALIZATION_DEPTH:
            return [_DEPTH_LIMIT_MARKER]

        if isinstance(value, list):
            parts: List[str] = []
            for item in value[:MAX_COLLECTION_ITEMS]:
                if isinstance(item, (str, list, Mapping)):
                    parts.extend(self._flatten_result_parts(item, depth + 1, in_collection=True))
            return parts

        if isinstance(value, Mapping):
            item_type = value.get("type")
            if isinstance(item_type, str):
                normalized_type = item_type.lower()
                if normalized_type in _NON_TEXT_CONTENT_TYPES:
                    return []
                if normalized_type not in _TEXT_CONTENT_TYPES:
                    try:
                        return [json.dumps(self._bound_value(value), ensure_ascii=False, separators=(",", ":"))]
                    except (TypeError, ValueError):
                        return [truncate_middle(str(value), max_length=MAX_TEXT_LENGTH, edge_chars=400)]

            for wrapper_key in ("Err", "Ok"):
                if wrapper_key in value:
                    parts = self._flatten_result_parts(value[wrapper_key], depth + 1)
                    if parts:
                        return parts

            for content_key in ("content", "text", "output", "result", "message", "error", "value"):
                if content_key in value:
                    parts = self._flatten_result_parts(value[content_key], depth + 1)
                    if parts:
                        return parts

            stream_parts: List[str] = []
            for stream_key in ("stdout", "stderr"):
                if stream_key in value:
                    stream_parts.extend(self._flatten_result_parts(value[stream_key], depth + 1))
            if stream_parts:
                return stream_parts

            try:
                return [json.dumps(self._bound_value(value), ensure_ascii=False, separators=(",", ":"))]
            except (TypeError, ValueError):
                return [truncate_middle(str(value), max_length=MAX_TEXT_LENGTH, edge_chars=400)]

        if in_collection:
            return []
        return [truncate_middle(str(value), max_length=MAX_TEXT_LENGTH, edge_chars=400)]

    def _normalize_tool_output(self, output: Any) -> Optional[str]:
        """Normalize string, list, or mapping output into bounded text."""
        if output is None:
            return None

        output = self._decode_output_container(output)
        text = "\n".join(part for part in self._flatten_result_parts(output) if part)
        return truncate_middle(text, max_length=MAX_TEXT_LENGTH, edge_chars=400) if text else text

    @staticmethod
    def _classify_tool(
        tool_name: Any, fallback_type: str, namespace: Any = None
    ) -> Tuple[str, Optional[str]]:
        """Classify well-formed encoded names or explicit MCP namespaces."""
        if not isinstance(tool_name, str):
            return fallback_type, None

        parts = tool_name.split("__")
        if (
            len(parts) == 3
            and parts[0] == "mcp"
            and _MCP_NAME_PART.fullmatch(parts[1])
            and _MCP_NAME_PART.fullmatch(parts[2])
        ):
            return "mcp_tool", parts[1]
        if isinstance(namespace, str):
            namespace_parts = namespace.split("__", 1)
            if (
                len(namespace_parts) == 2
                and namespace_parts[0] == "mcp"
                and _MCP_NAME_PART.fullmatch(namespace_parts[1])
                and _MCP_NAME_PART.fullmatch(tool_name)
            ):
                return "mcp_tool", namespace_parts[1]
        return fallback_type, None

    @staticmethod
    def _call_ids(payload: Mapping[str, Any]) -> List[str]:
        """Return distinct call identifiers from common wire aliases."""
        call_ids: List[str] = []
        for key in _CALL_ID_KEYS:
            value = payload.get(key)
            if isinstance(value, bool) or not isinstance(value, (str, int)):
                continue
            call_id = str(value).strip()
            if call_id and call_id not in call_ids:
                call_ids.append(call_id)
        return call_ids

    @staticmethod
    def _canonical_status(value: Any) -> Optional[str]:
        if not isinstance(value, str):
            return None
        normalized = value.strip().lower().replace("-", "_").replace(" ", "_")
        if normalized in _SUCCESS_STATES:
            return "success"
        if normalized in _ERROR_STATES:
            return "error"
        if normalized in _PENDING_STATES:
            return "pending"
        return None

    def _scan_outcome(
        self,
        value: Any,
        signals: set,
        error_details: List[Any],
    ) -> None:
        """Collect outcome signals only from an explicit result envelope."""
        if not isinstance(value, Mapping):
            return

        if "Err" in value:
            signals.add("error")
            error_details.append(value.get("Err"))
        if "Ok" in value:
            signals.add("success")
            if isinstance(value.get("Ok"), Mapping):
                self._scan_outcome(value["Ok"], signals, error_details)

        for key in ("isError", "is_error"):
            is_error = value.get(key)
            if isinstance(is_error, bool):
                signals.add("error" if is_error else "success")

        for key in ("status", "state"):
            status = self._canonical_status(value.get(key))
            if status:
                signals.add(status)

        for key in ("exit_code", "exitCode", "exit_status", "exitStatus"):
            exit_code = value.get(key)
            if isinstance(exit_code, (int, float)) and not isinstance(exit_code, bool):
                if exit_code == 0:
                    signals.add("success")
                else:
                    signals.add("error")
                    error_details.append(f"Exit code: {exit_code}")

        if "error" in value and value.get("error") not in (None, False, ""):
            signals.add("error")
            error_details.append(value.get("error"))

    def _infer_tool_outcome(self, sources: List[Any], default: str) -> Tuple[str, Any]:
        """Infer a canonical status, preferring error evidence on conflicts."""
        signals = set()
        error_details: List[Any] = []
        for source in sources:
            self._scan_outcome(source, signals, error_details)

        if "error" in signals:
            return "error", next((detail for detail in error_details if detail is not None), None)
        if "success" in signals:
            return "success", None
        if "pending" in signals:
            return "pending", None
        return default, None

    def _process_event(
        self, event: Mapping[str, Any], payload: Mapping[str, Any], session_data: Dict[str, Any]
    ):
        """Process a single event."""
        evt_type = event.get("type")

        if evt_type == "session_meta":
            if session_data["id"] is not None:
                return

            session_id = payload.get("id")
            if not isinstance(session_id, str) or not session_id:
                return

            timestamp = payload.get("timestamp")
            normalized_timestamp = None
            if timestamp:
                try:
                    normalized_timestamp = normalize_timestamp(timestamp)
                except (TypeError, ValueError, OverflowError, OSError):
                    pass

            session_data["id"] = session_id
            session_data["timestamp"] = normalized_timestamp
            session_data["cwd"] = payload.get("cwd")

        elif evt_type == "turn_context":
            if payload.get("model"):
                session_data["model"] = payload.get("model")

        elif evt_type == "response_item":
            item_type = payload.get("type")

            if item_type == "message":
                role = payload.get("role")
                content = payload.get("content", [])
                if isinstance(content, str):
                    text_content = content
                else:
                    if isinstance(content, Mapping):
                        content_items = [content]
                    elif isinstance(content, list):
                        content_items = content
                    else:
                        content_items = []

                    text_parts = []
                    for content_item in content_items:
                        if isinstance(content_item, str):
                            text_parts.append(content_item)
                        elif (
                            isinstance(content_item, Mapping)
                            and content_item.get("type") in ("input_text", "output_text")
                            and isinstance(content_item.get("text"), str)
                        ):
                            text_parts.append(content_item["text"])
                    text_content = "".join(text_parts)

                if text_content:
                    session_data["messages"].append({"role": role, "content": text_content, "tools": []})

            elif item_type in ("function_call", "custom_tool_call"):
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
                tool_type, server_name = self._classify_tool(
                    tool_name, item_type, payload.get("namespace"))
                status, error_detail = self._infer_tool_outcome([payload], default="pending")
                error = self._normalize_tool_output(error_detail) if error_detail is not None else None

                tool_dict = {
                    "tool_name": tool_name,
                    "tool_type": tool_type,
                    "server_name": server_name,
                    "arguments": arguments,
                    "status": status,
                    "result": None,
                    "error": error,
                }

                if not session_data["messages"] or session_data["messages"][-1]["role"] != "assistant":
                    session_data["messages"].append({"role": "assistant", "content": "", "tools": []})

                session_data["messages"][-1]["tools"].append(tool_dict)
                for call_id in self._call_ids(payload):
                    session_data["pending_tool_calls"][call_id] = tool_dict

            elif item_type in ("function_call_output", "custom_tool_call_output"):
                tool_dict = next(
                    (
                        session_data["pending_tool_calls"][call_id]
                        for call_id in self._call_ids(payload)
                        if call_id in session_data["pending_tool_calls"]
                    ),
                    None,
                )
                if tool_dict is not None:
                    raw_output = next(
                        (payload[key] for key in ("output", "result", "content") if key in payload),
                        None,
                    )
                    structured_output = self._decode_output_container(raw_output)
                    output = self._normalize_tool_output(structured_output)
                    default_status = (
                        tool_dict["status"] if tool_dict["status"] in ("success", "error") else "success"
                    )
                    status, error_detail = self._infer_tool_outcome(
                        [payload, structured_output], default=default_status
                    )
                    error = self._normalize_tool_output(error_detail) if error_detail is not None else None
                    if status == "error":
                        error = error or tool_dict.get("error") or output
                    else:
                        error = None

                    tool_dict["result"] = output
                    tool_dict["status"] = status
                    tool_dict["error"] = error

            elif item_type == "reasoning":
                summary_list = payload.get("summary", [])
                reasoning_text = ""
                if isinstance(summary_list, list):
                    for summary_item in summary_list:
                        if not isinstance(summary_item, Mapping):
                            continue
                        summary_text = summary_item.get("text")
                        if summary_item.get("type") == "summary_text" and isinstance(summary_text, str):
                            reasoning_text += summary_text + "\n"

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
