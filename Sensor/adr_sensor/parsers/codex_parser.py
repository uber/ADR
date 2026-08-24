"""
Parser for OpenAI Codex CLI logs.
Reads JSONL files from ~/.codex/sessions/
"""

import hashlib
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
MAX_AGENT_PARTY_LENGTH = 100
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
    {
        "error",
        "failed",
        "failure",
        "cancelled",
        "canceled",
        "declined",
        "rejected",
        "timed_out",
        "timeout",
    }
)
_PENDING_STATES = frozenset({"pending", "in_progress", "running", "queued", "started"})
_NON_TEXT_CONTENT_TYPES = frozenset(
    {"computer_screenshot", "image", "image_url", "input_image", "output_image"}
)
_TEXT_CONTENT_TYPES = frozenset({"input_text", "output_text", "text"})
_SESSION_CONTEXT_FIELDS = (
    "originator",
    "cli_version",
    "model_provider",
    "parent_thread_id",
    "forked_from_id",
    "agent_path",
    "agent_nickname",
    "agent_role",
    "subagent_history_start_ordinal",
    "thread_source",
)


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
                "_event_index": 0,
                "_action_boundaries": [],
                "_custom_tool_wrappers": [],
                "_rich_actions": [],
                "_rich_mcp_calls": [],
                "_classic_mcp_calls": [],
                "_tool_records": {},
                "_current_turn_id": None,
                "_previous_trigger_turn": False,
                "session_context": {},
            }

            with open(file_path, encoding="utf-8") as file:
                for line in file:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                        if not isinstance(event, Mapping):
                            session_data["_previous_trigger_turn"] = False
                            continue

                        payload = event.get("payload")
                        if not isinstance(payload, Mapping):
                            session_data["_previous_trigger_turn"] = False
                            continue

                        self._process_event(event, payload, session_data)
                    except Exception:
                        # Rollout records evolve independently; keep a malformed
                        # record from invalidating the rest of the session.
                        session_data["_previous_trigger_turn"] = False
                        continue

            self._reconcile_rich_actions(session_data)
            self._reconcile_rich_mcp_calls(session_data)

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
                session_context=session_data["session_context"] or None,
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
        normalized = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value.strip())
        normalized = normalized.lower().replace("-", "_").replace(" ", "_")
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

    @staticmethod
    def _wire_token(value: Any) -> str:
        """Normalize wire enum aliases without accepting unrelated item kinds."""
        return re.sub(r"[^a-z0-9]", "", value.lower()) if isinstance(value, str) else ""

    @staticmethod
    def _agent_message_text(content: Any) -> str:
        """Extract only locally readable agent-message text."""
        if not isinstance(content, list):
            return ""
        return "".join(
            item["text"]
            for item in content
            if isinstance(item, Mapping)
            and item.get("type") == "input_text"
            and isinstance(item.get("text"), str)
        )

    @staticmethod
    def _format_agent_party(value: Any) -> str:
        """Render a bounded scalar as a JSON value for the metadata prefix."""
        if not isinstance(value, (str, bool, int, float)):
            return "null"
        bounded = truncate_middle(str(value), max_length=MAX_AGENT_PARTY_LENGTH, edge_chars=30)
        return json.dumps(bounded, ensure_ascii=False)

    @staticmethod
    def _first_value(value: Mapping[str, Any], keys: Tuple[str, ...]) -> Any:
        for key in keys:
            if key in value:
                return value[key]
        return None

    def _event_turn_id(self, *sources: Any) -> Optional[str]:
        """Read an optional turn ID from direct fields or response metadata."""
        for source in sources:
            if not isinstance(source, Mapping):
                continue

            turn_id = self._first_value(source, ("turn_id", "turnId", "turnID"))
            if isinstance(turn_id, (str, int)) and not isinstance(turn_id, bool):
                normalized = str(turn_id).strip()
                if normalized:
                    return truncate_middle(normalized, max_length=MAX_TEXT_LENGTH, edge_chars=400)

            metadata = self._first_value(
                source,
                (
                    "internal_chat_message_metadata_passthrough",
                    "internalChatMessageMetadataPassthrough",
                ),
            )
            if isinstance(metadata, Mapping):
                turn_id = self._first_value(metadata, ("turn_id", "turnId", "turnID"))
                if isinstance(turn_id, (str, int)) and not isinstance(turn_id, bool):
                    normalized = str(turn_id).strip()
                    if normalized:
                        return truncate_middle(normalized, max_length=MAX_TEXT_LENGTH, edge_chars=400)
        return None

    def _normalize_command(self, value: Any) -> Any:
        """Retain command strings or argv lists in their source shape, with bounds."""
        if isinstance(value, str):
            return truncate_middle(value, max_length=MAX_TEXT_LENGTH, edge_chars=400)
        if isinstance(value, (list, tuple)):
            return [
                truncate_middle(part, max_length=MAX_TEXT_LENGTH, edge_chars=400)
                for part in value[:MAX_COLLECTION_ITEMS]
                if isinstance(part, str)
            ]
        return None

    @staticmethod
    def _is_plain_command_text(value: str) -> bool:
        """Keep signatures conservative; opaque scripts are intentionally not parsed."""
        stripped = value.strip()
        if not stripped or len(stripped) > MAX_TEXT_LENGTH or "\n" in stripped or "\r" in stripped:
            return False
        return not re.match(r"^(?:async\s+)?(?:const|function|let|var)\b", stripped)

    def _command_signatures(self, value: Any, allow_plain_text: bool = False) -> Tuple[str, ...]:
        """Build bounded command identities used only for wrapper reconciliation."""
        if isinstance(value, str) and len(value) <= MAX_ARGUMENT_JSON_LENGTH:
            try:
                value = json.loads(value)
            except (json.JSONDecodeError, RecursionError, ValueError):
                pass

        if isinstance(value, Mapping):
            value = self._first_value(value, ("command", "cmd", "argv"))
        elif isinstance(value, str) and not allow_plain_text:
            return ()

        if isinstance(value, str):
            if not self._is_plain_command_text(value):
                return ()
            command = truncate_middle(value.strip(), max_length=MAX_TEXT_LENGTH, edge_chars=400)
            return (command,)

        command = self._normalize_command(value)
        if not isinstance(command, list) or not command:
            return ()

        signatures = [
            truncate_middle(
                "\0".join(command),
                max_length=MAX_TEXT_LENGTH,
                edge_chars=400,
            )
        ]
        executable = command[0].replace("\\", "/").rsplit("/", 1)[-1].lower()
        if len(command) >= 3 and executable in {"bash", "cmd", "dash", "powershell", "pwsh", "sh", "zsh"}:
            option = command[-2].lower()
            if option == "/c" or option in {"-c", "-command"} or (
                option.startswith("-") and "c" in option[1:]
            ):
                nested = command[-1].strip()
                if self._is_plain_command_text(nested):
                    signatures.append(
                        truncate_middle(nested, max_length=MAX_TEXT_LENGTH, edge_chars=400)
                    )
        return tuple(dict.fromkeys(signatures))

    @staticmethod
    def _wrapper_action_kinds(tool_name: Any) -> Tuple[str, ...]:
        token = CodexParser._wire_token(tool_name)
        if token in {"exec", "execute"}:
            return ("command", "file")
        if token in {"commandexecution", "execcommand", "runcommand", "shell", "shellcommand"}:
            return ("command",)
        if token in {"applypatch", "filechange", "patch"}:
            return ("file",)
        return ()

    def _rich_output(self, item: Mapping[str, Any]) -> Any:
        """Select the richest completed output without interpreting its prose."""
        for keys in (
            ("aggregated_output", "aggregatedOutput"),
            ("formatted_output", "formattedOutput"),
            ("output", "result", "content"),
        ):
            output = self._first_value(item, keys)
            if output not in (None, ""):
                return output

        streams = {}
        for canonical, aliases in (
            ("stdout", ("stdout", "standard_output", "standardOutput")),
            ("stderr", ("stderr", "standard_error", "standardError")),
        ):
            stream = self._first_value(item, aliases)
            if stream not in (None, ""):
                streams[canonical] = stream
        return streams or None

    def _rich_outcome(self, item: Mapping[str, Any], output: Any) -> Tuple[str, Optional[str], Optional[str]]:
        """Apply the structural outcome rules shared with classic tool results."""
        outcome_source = dict(item)
        for canonical, aliases in (
            ("status", ("status", "state")),
            ("exit_code", ("exit_code", "exitCode", "exit_status", "exitStatus")),
            ("error", ("error", "error_message", "errorMessage")),
        ):
            if canonical not in outcome_source:
                alias_value = self._first_value(item, aliases)
                if alias_value is not None:
                    outcome_source[canonical] = alias_value

        structured_output = self._decode_output_container(output)
        result = self._normalize_tool_output(structured_output)
        status, error_detail = self._infer_tool_outcome(
            [outcome_source, structured_output], default="success"
        )
        error = self._normalize_tool_output(error_detail) if error_detail is not None else None
        if status == "error":
            error = error or result
        else:
            error = None
        return status, result, error

    def _normalize_rich_command(
        self, item: Mapping[str, Any]
    ) -> Optional[Tuple[Dict[str, Any], Tuple[str, ...]]]:
        raw_command = self._first_value(item, ("command", "cmd", "argv"))
        command = self._normalize_command(raw_command)
        if command is None or not command or (isinstance(command, str) and not command.strip()):
            return None

        arguments: Dict[str, Any] = {"command": command}
        cwd = self._first_value(item, ("cwd", "workdir", "working_directory", "workingDirectory"))
        if isinstance(cwd, str):
            arguments["cwd"] = truncate_middle(cwd, max_length=MAX_TEXT_LENGTH, edge_chars=400)

        duration = self._first_value(item, ("duration", "duration_ms", "durationMs"))
        if duration is not None:
            arguments["_codex"] = {"duration": self._bound_value(duration)}

        status, result, error = self._rich_outcome(item, self._rich_output(item))
        return (
            {
                "tool_name": "exec_command",
                "tool_type": "function_call",
                "server_name": None,
                "arguments": arguments,
                "status": status,
                "result": result,
                "error": error,
            },
            self._command_signatures(raw_command, allow_plain_text=True),
        )

    @staticmethod
    def _change_type(value: Any) -> Optional[str]:
        if not isinstance(value, str) or not value.strip():
            return None
        token = CodexParser._wire_token(value)
        aliases = {
            "add": "add",
            "added": "add",
            "create": "add",
            "created": "add",
            "delete": "delete",
            "deleted": "delete",
            "remove": "delete",
            "removed": "delete",
            "modify": "update",
            "modified": "update",
            "update": "update",
            "updated": "update",
        }
        return aliases.get(token, truncate_middle(value.strip().lower(), max_length=MAX_TEXT_LENGTH, edge_chars=400))

    @staticmethod
    def _private_text_summary(value: Any) -> Optional[Dict[str, Any]]:
        if not isinstance(value, str):
            return None
        encoded = value.encode("utf-8")
        return {"utf8_bytes": len(encoded), "sha256": hashlib.sha256(encoded).hexdigest()}

    def _summarize_file_changes(self, raw_changes: Any) -> Optional[Tuple[List[Dict[str, Any]], int]]:
        """Build a bounded allowlisted view of file changes, hashing private bodies."""
        if isinstance(raw_changes, Mapping):
            singular_path = self._first_value(raw_changes, ("path", "file_path", "filePath"))
            if isinstance(singular_path, str) and any(
                key in raw_changes for key in ("type", "change_type", "changeType", "kind")
            ):
                entries = [
                    (
                        singular_path,
                        raw_changes,
                    )
                ]
                total_changes = 1
            else:
                total_changes = len(raw_changes)
                entries = []
                for index, entry in enumerate(raw_changes.items()):
                    if index >= MAX_COLLECTION_ITEMS:
                        break
                    entries.append(entry)
        elif isinstance(raw_changes, (list, tuple)):
            total_changes = len(raw_changes)
            entries = []
            for change in raw_changes[:MAX_COLLECTION_ITEMS]:
                if isinstance(change, Mapping):
                    entries.append(
                        (
                            self._first_value(change, ("path", "file_path", "filePath")),
                            change,
                        )
                    )
        else:
            return None

        summaries = []
        for path, change in entries:
            if not isinstance(path, str) or not isinstance(change, Mapping):
                continue
            change_type = self._change_type(
                self._first_value(change, ("type", "change_type", "changeType", "kind"))
            )
            if change_type is None:
                continue

            summary: Dict[str, Any] = {
                "path": truncate_middle(path, max_length=MAX_TEXT_LENGTH, edge_chars=400),
                "type": change_type,
            }
            move_path = self._first_value(
                change,
                ("move_path", "movePath", "new_path", "newPath", "destination"),
            )
            if isinstance(move_path, str):
                summary["move_path"] = truncate_middle(
                    move_path, max_length=MAX_TEXT_LENGTH, edge_chars=400
                )

            for canonical, aliases in (
                ("content", ("content", "file_content", "fileContent")),
                ("unified_diff", ("unified_diff", "unifiedDiff", "diff")),
            ):
                private_summary = self._private_text_summary(self._first_value(change, aliases))
                if private_summary is not None:
                    summary[canonical] = private_summary
            summaries.append(summary)

        return summaries, max(0, total_changes - MAX_COLLECTION_ITEMS)

    def _normalize_rich_file_change(self, item: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        summarized = self._summarize_file_changes(
            self._first_value(item, ("changes", "file_changes", "fileChanges"))
        )
        if summarized is None:
            return None

        changes, truncated_changes = summarized
        if not changes:
            return None
        arguments: Dict[str, Any] = {"changes": changes}
        if truncated_changes:
            arguments["_codex"] = {"truncated_changes": truncated_changes}

        outcome_item = dict(item)
        for key in ("changes", "file_changes", "fileChanges"):
            outcome_item.pop(key, None)
        status, result, error = self._rich_outcome(outcome_item, self._rich_output(item))
        return {
            "tool_name": "file_change",
            "tool_type": "function_call",
            "server_name": None,
            "arguments": arguments,
            "status": status,
            "result": result,
            "error": error,
        }

    @staticmethod
    def _first_present(
        sources: Tuple[Mapping[str, Any], ...], keys: Tuple[str, ...]
    ) -> Tuple[bool, Any]:
        for source in sources:
            for key in keys:
                if key in source:
                    return True, source[key]
        return False, None

    def _first_nonempty_string(
        self, sources: Tuple[Mapping[str, Any], ...], keys: Tuple[str, ...]
    ) -> Optional[str]:
        for source in sources:
            for key in keys:
                value = source.get(key)
                if isinstance(value, str) and value.strip():
                    return truncate_middle(
                        value.strip(), max_length=MAX_TEXT_LENGTH, edge_chars=400
                    )
        return None

    @staticmethod
    def _codex_metadata(arguments: Dict[str, Any]) -> Dict[str, Any]:
        metadata = arguments.get("_codex")
        if not isinstance(metadata, dict):
            metadata = {}
            arguments["_codex"] = metadata
        return metadata

    def _normalize_rich_mcp_call(
        self, record: Mapping[str, Any]
    ) -> Optional[Tuple[Dict[str, Any], Tuple[str, ...]]]:
        """Normalize a completed rich MCP record without relying on server identity."""
        invocation = None
        server_name = None
        tool_name = None
        for key in ("invocation", "tool_call", "toolCall", "call"):
            candidate = record.get(key)
            if not isinstance(candidate, Mapping):
                continue
            candidate_server = self._first_nonempty_string(
                (candidate,),
                ("server", "server_name", "serverName", "mcp_server", "mcpServer"),
            )
            candidate_tool = self._first_nonempty_string(
                (candidate,), ("tool", "tool_name", "toolName", "name")
            )
            if candidate_server and candidate_tool:
                invocation = candidate
                server_name = candidate_server
                tool_name = candidate_tool
                break

        if invocation is None:
            invocation = record
            server_name = self._first_nonempty_string(
                (record,),
                ("server", "server_name", "serverName", "mcp_server", "mcpServer"),
            )
            tool_name = self._first_nonempty_string(
                (record,), ("tool", "tool_name", "toolName", "name")
            )
        if not server_name or not tool_name:
            return None

        _, raw_arguments = self._first_present(
            (invocation,),
            ("arguments", "args", "input", "params", "parameters"),
        )
        arguments = self._parse_tool_arguments(raw_arguments)

        if self._wire_token(tool_name) == "invoketool":
            effective_server = self._first_nonempty_string(
                (arguments,),
                (
                    "server",
                    "server_name",
                    "serverName",
                    "mcp_server",
                    "mcpServer",
                    "target_server",
                    "targetServer",
                ),
            )
            effective_tool = self._first_nonempty_string(
                (arguments,),
                ("tool", "tool_name", "toolName", "name", "target_tool", "targetTool"),
            )
            has_nested_arguments, nested_arguments = self._first_present(
                (arguments,),
                ("arguments", "args", "input", "params", "parameters"),
            )
            if effective_server and effective_tool and has_nested_arguments:
                outer_server, outer_tool = server_name, tool_name
                server_name, tool_name = effective_server, effective_tool
                arguments = self._parse_tool_arguments(nested_arguments)
                arguments["_codex_mcp_wrapper"] = {
                    "server_name": outer_server,
                    "tool_name": outer_tool,
                }

        metadata: Dict[str, Any] = {}
        sources = (record, invocation) if invocation is not record else (record,)
        duration = next(
            (
                source[key]
                for source in sources
                for key in ("duration", "duration_ms", "durationMs", "elapsed_ms", "elapsedMs")
                if key in source and source[key] is not None
            ),
            None,
        )
        if duration is not None:
            metadata["duration"] = self._bound_value(duration)

        read_only_hint = next(
            (
                source[key]
                for source in sources
                for key in ("read_only_hint", "readOnlyHint")
                if isinstance(source.get(key), bool)
            ),
            None,
        )
        if isinstance(read_only_hint, bool):
            metadata["read_only_hint"] = read_only_hint

        connector = {}
        for canonical, aliases in (
            ("connector_id", ("connector_id", "connectorId")),
            ("link_id", ("link_id", "linkId")),
            ("app_name", ("app_name", "appName")),
            ("action_name", ("action_name", "actionName")),
        ):
            value = next(
                (
                    source[key]
                    for source in sources
                    for key in aliases
                    if isinstance(source.get(key), (str, bool, int, float))
                ),
                None,
            )
            if value is not None:
                connector[canonical] = self._bound_value(value)
        if connector:
            metadata["connector"] = connector
        if metadata:
            self._codex_metadata(arguments).update(metadata)

        output = self._rich_output(record)
        if output is None:
            _, output = self._first_present((record,), ("response",))
        if output is None and invocation is not record:
            output = self._rich_output(invocation)
            if output is None:
                _, output = self._first_present((invocation,), ("response",))
        outcome_record = dict(invocation)
        outcome_record.update(record)
        status, result, error = self._rich_outcome(outcome_record, output)

        call_ids = []
        for source in (record, invocation):
            for call_id in self._call_ids(source):
                if call_id not in call_ids:
                    call_ids.append(call_id)
        return (
            {
                "tool_name": tool_name,
                "tool_type": "mcp_tool",
                "server_name": server_name,
                "arguments": arguments,
                "status": status,
                "result": result,
                "error": error,
            },
            tuple(call_ids),
        )

    def _normalize_rich_action(
        self, item: Mapping[str, Any]
    ) -> Optional[Tuple[str, Dict[str, Any], Tuple[str, ...]]]:
        item_type = self._wire_token(item.get("type"))
        if item_type == "commandexecution":
            command = self._normalize_rich_command(item)
            if command is None:
                return None
            tool, signatures = command
            return "command", tool, signatures
        if item_type == "filechange":
            tool = self._normalize_rich_file_change(item)
            return ("file", tool, ()) if tool is not None else None
        return None

    def _process_subagent_activity(
        self, item: Mapping[str, Any], session_data: Dict[str, Any]
    ) -> None:
        activity = {}
        for key in ("kind", "agent_thread_id", "agent_path"):
            value = item.get(key)
            if isinstance(value, (str, bool, int, float)):
                activity[key] = self._bound_value(value)

        tool_dict = None
        call_ids = self._call_ids(item)
        for key in ("event_id", "eventId", "eventID"):
            value = item.get(key)
            if isinstance(value, (str, int)) and not isinstance(value, bool):
                call_id = str(value).strip()
                if call_id and call_id not in call_ids:
                    call_ids.append(call_id)

        for call_id in call_ids:
            candidate = session_data["pending_tool_calls"].get(call_id)
            tool_record = session_data["_tool_records"].get(id(candidate))
            if tool_record is not None and tool_record.get("item_type") == "function_call":
                tool_dict = candidate
                break

        if tool_dict is not None:
            self._codex_metadata(tool_dict["arguments"])["subagent_activity"] = activity
            if tool_dict.get("status") == "pending":
                tool_dict["status"] = "success"
            return

        self._append_tool(
            session_data,
            {
                "tool_name": "subagent_activity",
                "tool_type": "function_call",
                "server_name": None,
                "arguments": {"_codex": {"subagent_activity": activity}},
                "status": "success",
                "result": None,
                "error": None,
            },
        )

    @staticmethod
    def _append_tool(session_data: Dict[str, Any], tool: Dict[str, Any]) -> Dict[str, Any]:
        if not session_data["messages"] or session_data["messages"][-1]["role"] != "assistant":
            session_data["messages"].append({"role": "assistant", "content": "", "tools": []})
        message = session_data["messages"][-1]
        message["tools"].append(tool)
        return message

    @staticmethod
    def _turns_are_compatible(left: Optional[str], right: Optional[str]) -> bool:
        return not left or not right or left == right

    def _reconcile_rich_actions(self, session_data: Dict[str, Any]) -> None:
        """Replace confidently matched custom wrappers with completed rich actions."""
        wrappers = session_data.get("_custom_tool_wrappers", [])
        rich_actions = session_data.get("_rich_actions", [])
        if not wrappers or not rich_actions:
            return

        boundaries = sorted(set(session_data.get("_action_boundaries", [])))
        for wrapper in wrappers:
            wrapper["window_end"] = next(
                (index for index in boundaries if index > wrapper["index"]),
                float("inf"),
            )
            wrapper["matched"] = []

        for rich_action in sorted(rich_actions, key=lambda action: action["index"]):
            candidates = []
            for wrapper in wrappers:
                if not (wrapper["index"] < rich_action["index"] < wrapper["window_end"]):
                    continue
                if rich_action["kind"] not in wrapper["kinds"]:
                    continue
                if not self._turns_are_compatible(wrapper["turn_id"], rich_action["turn_id"]):
                    continue
                if (
                    rich_action["kind"] == "command"
                    and wrapper["signatures"]
                    and rich_action["signatures"]
                    and not set(wrapper["signatures"]).intersection(rich_action["signatures"])
                ):
                    continue
                candidates.append(wrapper)

            if candidates:
                max(candidates, key=lambda wrapper: wrapper["index"])["matched"].append(rich_action)

        matched_actions = [
            action for wrapper in wrappers for action in wrapper["matched"]
        ]
        if not matched_actions:
            return

        matched_tool_ids = {id(action["tool"]) for action in matched_actions}
        for message in session_data["messages"]:
            message["tools"] = [
                tool for tool in message["tools"] if id(tool) not in matched_tool_ids
            ]

        for wrapper in wrappers:
            if not wrapper["matched"]:
                continue
            tools = wrapper["message"]["tools"]
            wrapper_index = next(
                (index for index, tool in enumerate(tools) if tool is wrapper["tool"]),
                None,
            )
            if wrapper_index is None:
                continue
            replacements = [
                action["tool"] for action in sorted(wrapper["matched"], key=lambda action: action["index"])
            ]
            tools[wrapper_index : wrapper_index + 1] = replacements

    def _mcp_signature(self, tool: Mapping[str, Any]) -> Tuple[str, str, str]:
        """Build a stable signature for classic and rich forms of one MCP call."""
        server_name = tool.get("server_name")
        tool_name = tool.get("tool_name")
        if isinstance(tool_name, str):
            parts = tool_name.split("__")
            if len(parts) == 3 and parts[0] == "mcp":
                tool_name = parts[2]

        arguments = tool.get("arguments")
        if isinstance(arguments, Mapping):
            arguments = {
                key: value
                for key, value in arguments.items()
                if not str(key).startswith("_codex")
            }
        try:
            encoded_arguments = json.dumps(arguments, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError):
            encoded_arguments = str(arguments)

        return (
            server_name.strip() if isinstance(server_name, str) else "",
            tool_name.strip() if isinstance(tool_name, str) else "",
            encoded_arguments,
        )

    def _reconcile_rich_mcp_calls(self, session_data: Dict[str, Any]) -> None:
        """Replace classic MCP calls matched by ID or an exact call signature."""
        classic_calls = session_data.get("_classic_mcp_calls", [])
        rich_calls = session_data.get("_rich_mcp_calls", [])
        if not classic_calls or not rich_calls:
            return

        boundaries = sorted(set(session_data.get("_action_boundaries", [])))
        for classic_call in classic_calls:
            classic_call["window_end"] = next(
                (index for index in boundaries if index > classic_call["index"]),
                float("inf"),
            )

        matched_rich_tool_ids = set()
        matched_classic_tool_ids = set()
        for rich_call in sorted(rich_calls, key=lambda call: call["index"]):
            rich_ids = set(rich_call["call_ids"])
            candidates = [
                classic_call
                for classic_call in classic_calls
                if id(classic_call["tool"]) not in matched_classic_tool_ids
                and rich_ids.intersection(classic_call["call_ids"])
            ]
            if not candidates:
                rich_signature = self._mcp_signature(rich_call["tool"])
                candidates = [
                    classic_call
                    for classic_call in classic_calls
                    if id(classic_call["tool"]) not in matched_classic_tool_ids
                    and (not rich_ids or not classic_call["call_ids"])
                    and classic_call["index"] <= rich_call["index"]
                    and rich_call["index"] < classic_call["window_end"]
                    and self._turns_are_compatible(
                        classic_call.get("turn_id"), rich_call.get("turn_id")
                    )
                    and self._mcp_signature(classic_call["tool"]) == rich_signature
                ]
                if not candidates:
                    continue

            preceding = [
                candidate
                for candidate in candidates
                if candidate["index"] <= rich_call["index"]
            ]
            if preceding:
                classic_call = max(preceding, key=lambda call: call["index"])
            else:
                classic_call = min(candidates, key=lambda call: call["index"])
            classic_call["tool"].clear()
            classic_call["tool"].update(rich_call["tool"])
            matched_classic_tool_ids.add(id(classic_call["tool"]))
            matched_rich_tool_ids.add(id(rich_call["tool"]))

        if matched_rich_tool_ids:
            for message in session_data["messages"]:
                message["tools"] = [
                    tool for tool in message["tools"] if id(tool) not in matched_rich_tool_ids
                ]

    def _process_event(
        self, event: Mapping[str, Any], payload: Mapping[str, Any], session_data: Dict[str, Any]
    ):
        """Process a single event."""
        evt_type = event.get("type")
        previous_trigger_turn = session_data.get("_previous_trigger_turn", False)
        session_data["_previous_trigger_turn"] = bool(
            evt_type == "inter_agent_communication_metadata"
            and payload.get("trigger_turn") is True
        )
        event_index = session_data.setdefault("_event_index", 0)
        session_data["_event_index"] = event_index + 1

        if evt_type == "session_meta":
            if session_data["id"] is not None:
                self._add_inherited_session_id(payload.get("id"), session_data)
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
            session_data["session_context"] = self._extract_session_context(payload, session_id)

        elif evt_type == "turn_context":
            session_data["_action_boundaries"].append(event_index)
            turn_id = self._event_turn_id(event, payload)
            session_data["_current_turn_id"] = turn_id
            if payload.get("model"):
                session_data["model"] = payload.get("model")

        elif self._wire_token(evt_type) == "subagentactivity":
            activity = dict(event)
            activity.update(payload)
            self._process_subagent_activity(activity, session_data)

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

            elif item_type == "agent_message":
                text_content = self._agent_message_text(payload.get("content"))
                if text_content:
                    author = self._format_agent_party(payload.get("author"))
                    recipient = self._format_agent_party(payload.get("recipient"))
                    trigger_turn = str(previous_trigger_turn).lower()
                    content = (
                        f"[agent_message author={author} recipient={recipient} "
                        f"trigger_turn={trigger_turn}]\n{text_content}"
                    )
                    session_data["messages"].append(
                        {"role": "user", "content": content, "tools": []}
                    )

            elif item_type in ("function_call", "custom_tool_call"):
                session_data["_action_boundaries"].append(event_index)
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

                call_ids = self._call_ids(payload)
                tool_dict = {
                    "tool_name": tool_name,
                    "tool_type": tool_type,
                    "server_name": server_name,
                    "arguments": arguments,
                    "status": status,
                    "result": None,
                    "error": error,
                }

                message = self._append_tool(session_data, tool_dict)
                turn_id = self._event_turn_id(event, payload) or session_data.get("_current_turn_id")
                tool_record = {
                    "tool": tool_dict,
                    "message": message,
                    "index": event_index,
                    "turn_id": turn_id,
                    "call_ids": tuple(call_ids),
                    "item_type": item_type,
                }
                session_data["_tool_records"][id(tool_dict)] = tool_record
                if item_type == "function_call" and tool_type == "mcp_tool":
                    session_data["_classic_mcp_calls"].append(tool_record)
                if item_type == "custom_tool_call":
                    signatures = self._command_signatures(raw_arguments, allow_plain_text=True)
                    kinds = self._wrapper_action_kinds(tool_name)
                    if signatures and self._wire_token(tool_name) in {"exec", "execute"}:
                        kinds = ("command",)
                    tool_record.update(
                        {
                            "kinds": kinds,
                            "signatures": signatures,
                        }
                    )
                    session_data["_custom_tool_wrappers"].append(tool_record)
                for call_id in call_ids:
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
                    tool_record = session_data["_tool_records"].get(id(tool_dict))
                    if tool_record is not None:
                        tool_record["turn_id"] = (
                            tool_record["turn_id"]
                            or self._event_turn_id(event, payload)
                            or session_data.get("_current_turn_id")
                        )
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

        elif self._wire_token(evt_type) == "eventmsg":
            payload_type = self._wire_token(payload.get("type"))
            if payload_type == "mcptoolcallend":
                normalized_mcp = self._normalize_rich_mcp_call(payload)
                if normalized_mcp is None:
                    return
                tool_dict, call_ids = normalized_mcp
                self._append_tool(session_data, tool_dict)
                session_data["_rich_mcp_calls"].append(
                    {
                        "tool": tool_dict,
                        "index": event_index,
                        "call_ids": call_ids,
                        "turn_id": self._event_turn_id(event, payload)
                        or session_data.get("_current_turn_id"),
                    }
                )
                return

            if payload_type != "itemcompleted":
                return
            item = payload.get("item")
            if not isinstance(item, Mapping):
                return

            item_type = self._wire_token(item.get("type"))
            if item_type == "subagentactivity":
                self._process_subagent_activity(item, session_data)
                return

            if item_type in ("mcptoolcall", "mcptoolcallend"):
                normalized_mcp = self._normalize_rich_mcp_call(item)
                if normalized_mcp is None:
                    return
                tool_dict, call_ids = normalized_mcp
                self._append_tool(session_data, tool_dict)
                session_data["_rich_mcp_calls"].append(
                    {
                        "tool": tool_dict,
                        "index": event_index,
                        "call_ids": call_ids,
                        "turn_id": self._event_turn_id(event, payload, item)
                        or session_data.get("_current_turn_id"),
                    }
                )
                return

            normalized = self._normalize_rich_action(item)
            if normalized is None:
                return

            kind, tool_dict, signatures = normalized
            self._append_tool(session_data, tool_dict)
            session_data["_rich_actions"].append(
                {
                    "tool": tool_dict,
                    "index": event_index,
                    "turn_id": self._event_turn_id(event, payload, item)
                    or session_data.get("_current_turn_id"),
                    "kind": kind,
                    "signatures": signatures,
                }
            )

    @staticmethod
    def _normalize_context_scalar(value: Any) -> Optional[Any]:
        """Return a bounded JSON scalar, ignoring structured metadata values."""
        if not isinstance(value, (str, int, float, bool)):
            return None
        if isinstance(value, str):
            return truncate_middle(value, max_length=1000, edge_chars=400)
        return value

    def _extract_session_context(
        self, payload: Mapping[str, Any], physical_session_id: str
    ) -> Dict[str, Any]:
        """Extract bounded provenance from the physical session metadata."""
        context: Dict[str, Any] = {}

        source = payload.get("source")
        thread_spawn = None
        if isinstance(source, Mapping):
            subagent = source.get("subagent")
            if isinstance(subagent, Mapping):
                candidate = subagent.get("thread_spawn")
                if isinstance(candidate, Mapping):
                    thread_spawn = candidate

        for key in _SESSION_CONTEXT_FIELDS:
            value = self._normalize_context_scalar(payload.get(key))
            if value is None and thread_spawn is not None and key in (
                "parent_thread_id",
                "agent_path",
                "agent_nickname",
            ):
                value = self._normalize_context_scalar(thread_spawn.get(key))
            if value is not None:
                context[key] = value

        git_info = payload.get("git")
        if isinstance(git_info, Mapping):
            git_branch = self._normalize_context_scalar(git_info.get("branch"))
            if git_branch is not None:
                context["git_branch"] = git_branch

        if thread_spawn is not None:
            for source_key, context_key in (("depth", "agent_depth"), ("agent_role", "agent_role")):
                value = self._normalize_context_scalar(thread_spawn.get(source_key))
                if value is not None and context_key not in context:
                    context[context_key] = value

        root_session_id = payload.get("session_id")
        normalized_root_id = (
            self._normalize_context_scalar(str(root_session_id))
            if isinstance(root_session_id, (str, int, float, bool))
            else None
        )
        if normalized_root_id is not None and str(root_session_id) != physical_session_id:
            context["root_session_id"] = normalized_root_id

        return context

    def _add_inherited_session_id(self, inherited_id: Any, session_data: Dict[str, Any]) -> None:
        """Record later session metadata as lineage without replacing identity."""
        normalized_id = (
            self._normalize_context_scalar(str(inherited_id))
            if isinstance(inherited_id, (str, int, float, bool))
            else None
        )
        if normalized_id is None or normalized_id == "" or str(inherited_id) == session_data["id"]:
            return

        inherited_ids = session_data["session_context"].setdefault("inherited_session_ids", [])
        if normalized_id not in inherited_ids:
            inherited_ids.append(normalized_id)
