"""
Parser for GitHub Copilot session-state logs.

Reads per-session event streams from ``~/.copilot/session-state/<session-id>/``
and normalizes them into ADR's ``AgentEvent`` schema.

The primary signal lives in ``events.jsonl``. When available, the parser also
enriches sessions with lightweight metadata from ``workspace.yaml`` and
``vscode.metadata.json``.
"""

import json
import traceback
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..schemas.agent_event_schema import AgentEvent, ChatMessage, ToolUsage
from ..utils.string_utils import truncate_middle
from ..utils.timestamp_utils import normalize_timestamp
from .base_parser import BaseParser

MAX_STRING_LENGTH = 1000
EDGE_CHARS = 400


class CopilotParser(BaseParser):
    """Parser for GitHub Copilot session-state logs."""

    def __init__(self, base_path: Optional[Path] = None):
        self.base_path = Path(base_path) if base_path else Path.home() / ".copilot" / "session-state"

    def parse_all(self) -> List[AgentEvent]:
        """Parse all available Copilot sessions."""
        entries: List[AgentEvent] = []

        if not self.base_path.exists():
            print(f"[COPILOT] No logs found at {self.base_path}")
            return entries

        session_dirs = [path for path in self.base_path.iterdir() if path.is_dir() and (path / "events.jsonl").exists()]
        session_dirs.sort(key=lambda path: path.stat().st_mtime, reverse=True)
        print(f"[COPILOT] Found {len(session_dirs)} session directories")

        for session_dir in session_dirs:
            try:
                entry = self.parse_session_dir(session_dir)
                if entry and entry.has_meaningful_content():
                    entries.append(entry)
            except Exception as exc:
                print(f"[COPILOT] Error parsing {session_dir}: {exc}")

        return entries

    def parse_session_dir(self, session_dir: Path) -> Optional[AgentEvent]:
        """Parse one Copilot session directory."""
        events_path = session_dir / "events.jsonl"
        if not events_path.exists():
            return None

        workspace_meta = self._load_workspace_yaml(session_dir / "workspace.yaml")
        vscode_meta = self._load_json_file(session_dir / "vscode.metadata.json")

        session_data: Dict[str, Any] = {
            "id": session_dir.name,
            "timestamp": None,
            "cwd": workspace_meta.get("cwd"),
            "model": None,
            "messages": [],
            "pending_tool_calls": {},
            "first_event_at": None,
            "last_event_at": None,
            "event_counts": Counter(),
            "workspace_metadata": workspace_meta,
            "vscode_metadata": self._sanitize_for_context(vscode_meta) if isinstance(vscode_meta, dict) else {},
            "model_changes": [],
            "usage_checkpoints": [],
            "permissions": [],
            "skills_invoked": [],
            "subagents": [],
            "session_info": [],
            "mode_changes": [],
            "hooks": [],
            "system_messages": [],
            "system_notifications": [],
            "workspace_file_changes": [],
            "plan_changes": [],
            "transformed_user_messages": [],
        }

        try:
            with open(events_path, encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    self._process_event(event, session_data)
        except Exception as exc:
            print(f"[COPILOT] Error reading {events_path}: {exc}")
            traceback.print_exc()
            return None

        chat_history: List[ChatMessage] = []
        for index, msg_dict in enumerate(session_data["messages"]):
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

            chat_history.append(
                ChatMessage(
                    role=msg_dict["role"],
                    content=msg_dict["content"],
                    tools=tools,
                    sequence_id=msg_dict.get("sequence_id") or f"{session_data['id']}_msg_{index}",
                )
            )

        if not chat_history:
            return None

        timestamp = (
            # Updated/modified sidecars can lag resumed events and must not define file identity.
            session_data["timestamp"]
            or self._normalize_optional_timestamp(workspace_meta.get("created_at"))
            or self._normalize_optional_timestamp(vscode_meta.get("created"))
            or self._normalize_optional_timestamp(session_data["first_event_at"])
            or datetime.now(timezone.utc)
        )

        context = self._build_session_context(session_data)

        return AgentEvent(
            timestamp=timestamp,
            source="copilot",
            session_id=f"copilot_{session_data['id']}",
            project_path=session_data["cwd"],
            model=session_data["model"],
            chat_history=chat_history,
            raw_log_path=str(events_path),
            session_context=context or None,
        )

    def _process_event(self, event: Dict[str, Any], session_data: Dict[str, Any]):
        """Process a single Copilot event from events.jsonl."""
        event_type = event.get("type")
        if not event_type:
            return

        data = event.get("data", {})
        event_time = self._normalize_optional_timestamp(event.get("timestamp"))

        session_data["event_counts"][event_type] += 1
        if event_time:
            first_event_at = session_data["first_event_at"]
            last_event_at = session_data["last_event_at"]
            if first_event_at is None or event_time < first_event_at:
                session_data["first_event_at"] = event_time
            if last_event_at is None or event_time > last_event_at:
                session_data["last_event_at"] = event_time

        if event_type == "session.start":
            session_id = data.get("sessionId")
            if session_id:
                session_data["id"] = session_id
            session_data["timestamp"] = self._normalize_optional_timestamp(data.get("startTime")) or event_time
            session_data["model"] = data.get("selectedModel") or session_data["model"]
            context = data.get("context", {})
            if isinstance(context, dict):
                session_data["cwd"] = context.get("cwd") or session_data["cwd"]
            return

        if event_type == "session.resume":
            session_id = data.get("sessionId")
            if session_id:
                session_data["id"] = session_id
            context = data.get("context", {})
            if isinstance(context, dict):
                session_data["cwd"] = context.get("cwd") or session_data["cwd"]
            return

        if event_type == "user.message":
            content = (data.get("content") or "").strip()
            transformed = (data.get("transformedContent") or "").strip()
            if transformed and transformed != content:
                session_data["transformed_user_messages"].append(
                    {
                        "sequence_id": event.get("id"),
                        "content": truncate_middle(transformed, max_length=MAX_STRING_LENGTH, edge_chars=EDGE_CHARS),
                    }
                )
            if content:
                session_data["messages"].append(
                    {
                        "role": "user",
                        "content": content,
                        "tools": [],
                        "sequence_id": event.get("id"),
                    }
                )
            return

        if event_type == "assistant.message":
            content = (data.get("content") or "").strip()
            tools = []
            for request in data.get("toolRequests") or []:
                tool_call_id = request.get("toolCallId")
                tool_dict = {
                    "tool_name": request.get("name") or "unknown",
                    "tool_type": request.get("type") or "tool_request",
                    "arguments": self._truncate_large_arguments(request.get("arguments") or {}),
                    "result": None,
                    "status": "pending",
                    "error": None,
                }
                tools.append(tool_dict)
                if tool_call_id:
                    session_data["pending_tool_calls"][tool_call_id] = tool_dict

            if content or tools:
                session_data["messages"].append(
                    {
                        "role": "assistant",
                        "content": content,
                        "tools": tools,
                        "sequence_id": data.get("messageId") or event.get("id"),
                    }
                )

            session_data["model"] = data.get("model") or session_data["model"]
            return

        if event_type == "tool.execution_start":
            tool = self._get_or_create_tool(
                session_data,
                data.get("toolCallId"),
                default_tool_name=data.get("toolName"),
            )
            if tool is not None:
                tool["tool_name"] = data.get("toolName") or tool["tool_name"]
                tool["arguments"] = self._truncate_large_arguments(data.get("arguments") or tool["arguments"])
                tool["status"] = "running"
            session_data["model"] = data.get("model") or session_data["model"]
            return

        if event_type == "tool.execution_complete":
            tool = self._get_or_create_tool(session_data, data.get("toolCallId"), default_tool_name=None)
            if tool is not None:
                success = bool(data.get("success"))
                result_text = self._normalize_tool_result(data.get("result"))
                error_text = self._normalize_tool_result(data.get("error"))
                tool["result"] = result_text
                tool["status"] = "success" if success else "error"
                if not success:
                    tool["error"] = error_text or result_text
            session_data["model"] = data.get("model") or session_data["model"]
            return

        if event_type == "permission.requested":
            permission_record = {
                "request_id": data.get("requestId"),
                "tool_call_id": self._extract_tool_call_id_from_permission(data),
                "permission_kind": self._extract_permission_kind(data),
                "command": self._extract_permission_command(data),
                "timestamp": event.get("timestamp"),
            }
            session_data["permissions"].append(self._sanitize_for_context(permission_record))

            tool = self._get_or_create_tool(
                session_data,
                permission_record["tool_call_id"],
                default_tool_name="permission_request",
            )
            if tool is not None and tool.get("status") == "pending":
                tool["status"] = "permission_requested"
            return

        if event_type == "permission.completed":
            permission_result = data.get("result", {})
            permission_record = {
                "request_id": data.get("requestId"),
                "tool_call_id": data.get("toolCallId"),
                "result": permission_result,
                "timestamp": event.get("timestamp"),
            }
            session_data["permissions"].append(self._sanitize_for_context(permission_record))

            tool = self._get_or_create_tool(session_data, data.get("toolCallId"), default_tool_name=None)
            kind = permission_result.get("kind") if isinstance(permission_result, dict) else None
            if tool is not None and tool.get("status") in {"pending", "permission_requested"} and kind == "approved":
                tool["status"] = "approved"
            return

        if event_type == "session.model_change":
            session_data["model_changes"].append(
                self._sanitize_for_context(
                    {
                        "previous_model": data.get("previousModel"),
                        "new_model": data.get("newModel"),
                        "previous_reasoning_effort": data.get("previousReasoningEffort"),
                        "reasoning_effort": data.get("reasoningEffort"),
                        "timestamp": event.get("timestamp"),
                    }
                )
            )
            session_data["model"] = data.get("newModel") or session_data["model"]
            return

        if event_type == "session.usage_checkpoint":
            session_data["usage_checkpoints"].append(self._sanitize_for_context(data))
            return

        if event_type == "skill.invoked":
            session_data["skills_invoked"].append(
                self._sanitize_for_context(
                    {
                        "name": data.get("name"),
                        "path": data.get("path"),
                        "content": data.get("content"),
                    }
                )
            )
            return

        if event_type == "subagent.started":
            session_data["subagents"].append(
                self._sanitize_for_context(
                    {
                        "agent_id": event.get("agentId"),
                        "tool_call_id": data.get("toolCallId"),
                        "agent_name": data.get("agentName"),
                        "display_name": data.get("agentDisplayName"),
                        "description": data.get("agentDescription"),
                        "timestamp": event.get("timestamp"),
                    }
                )
            )
            return

        if event_type == "session.info":
            session_data["session_info"].append(self._sanitize_for_context(data))
            return

        if event_type == "session.mode_changed":
            session_data["mode_changes"].append(self._sanitize_for_context(data))
            return

        if event_type in {"hook.start", "hook.end"}:
            session_data["hooks"].append(
                self._sanitize_for_context(
                    {
                        "type": event_type,
                        "timestamp": event.get("timestamp"),
                        "data": data,
                    }
                )
            )
            return

        if event_type == "system.message":
            content = data.get("content")
            if isinstance(content, str) and content.strip():
                session_data["system_messages"].append(
                    truncate_middle(content.strip(), max_length=MAX_STRING_LENGTH, edge_chars=EDGE_CHARS)
                )
            return

        if event_type == "system.notification":
            session_data["system_notifications"].append(self._sanitize_for_context(data))
            return

        if event_type == "session.workspace_file_changed":
            session_data["workspace_file_changes"].append(self._sanitize_for_context(data))
            return

        if event_type == "session.plan_changed":
            session_data["plan_changes"].append(self._sanitize_for_context(data))

    def _get_or_create_tool(
        self,
        session_data: Dict[str, Any],
        tool_call_id: Optional[str],
        default_tool_name: Optional[str],
    ) -> Optional[Dict[str, Any]]:
        """Return a mutable tool dict for a toolCallId, creating an orphan entry if needed."""
        if not tool_call_id:
            return None

        existing = session_data["pending_tool_calls"].get(tool_call_id)
        if existing is not None:
            return existing

        tool_dict = {
            "tool_name": default_tool_name or "unknown",
            "tool_type": "tool_execution",
            "arguments": {},
            "result": None,
            "status": "pending",
            "error": None,
        }
        session_data["pending_tool_calls"][tool_call_id] = tool_dict
        session_data["messages"].append(
            {
                "role": "assistant",
                "content": "",
                "tools": [tool_dict],
                "sequence_id": f"{session_data['id']}_tool_{tool_call_id}",
            }
        )
        return tool_dict

    def _build_session_context(self, session_data: Dict[str, Any]) -> Dict[str, Any]:
        """Build session-level context from side-channel event metadata."""
        context = {
            "workspace_metadata": session_data["workspace_metadata"],
            "vscode_metadata": session_data["vscode_metadata"],
            "first_event_at": self._format_datetime(session_data["first_event_at"]),
            "last_event_at": self._format_datetime(session_data["last_event_at"]),
            "event_counts": dict(session_data["event_counts"]),
            "event_count": sum(session_data["event_counts"].values()),
            "model_changes": session_data["model_changes"],
            "usage_checkpoints": session_data["usage_checkpoints"],
            "permissions": session_data["permissions"],
            "skills_invoked": session_data["skills_invoked"],
            "subagents": session_data["subagents"],
            "session_info": session_data["session_info"],
            "mode_changes": session_data["mode_changes"],
            "hooks": session_data["hooks"],
            "system_messages": session_data["system_messages"][:5],
            "system_notifications": session_data["system_notifications"],
            "workspace_file_changes": session_data["workspace_file_changes"],
            "plan_changes": session_data["plan_changes"],
            "transformed_user_messages": session_data["transformed_user_messages"],
        }

        filtered: Dict[str, Any] = {}
        for key, value in context.items():
            if isinstance(value, dict) and value:
                filtered[key] = value
            elif isinstance(value, list) and value:
                filtered[key] = value
            elif isinstance(value, str) and value:
                filtered[key] = value
            elif isinstance(value, int) and value >= 0:
                filtered[key] = value
        return filtered

    def _normalize_tool_result(self, result: Any) -> Optional[str]:
        """Normalize tool result payloads to a truncated string."""
        if result is None:
            return None

        if isinstance(result, str):
            text = result
        elif isinstance(result, dict):
            text = result.get("detailedContent") or result.get("content") or json.dumps(result, ensure_ascii=False)
        else:
            text = str(result)

        if not text:
            return text

        return truncate_middle(text, max_length=MAX_STRING_LENGTH, edge_chars=EDGE_CHARS)

    def _truncate_large_arguments(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Truncate large string values within tool argument dictionaries."""
        if not isinstance(arguments, dict):
            return {"raw": arguments}

        return {key: self._sanitize_for_context(value) for key, value in arguments.items()}

    def _sanitize_for_context(self, value: Any) -> Any:
        """Recursively truncate long strings so session_context stays bounded."""
        if isinstance(value, str):
            return truncate_middle(value, max_length=MAX_STRING_LENGTH, edge_chars=EDGE_CHARS)
        if isinstance(value, dict):
            return {str(key): self._sanitize_for_context(val) for key, val in value.items()}
        if isinstance(value, list):
            return [self._sanitize_for_context(item) for item in value]
        return value

    def _load_json_file(self, path: Path) -> Dict[str, Any]:
        """Read a JSON file if it exists, else return an empty dict."""
        if not path.exists():
            return {}

        try:
            with open(path, encoding="utf-8") as handle:
                value = json.load(handle)
            return value if isinstance(value, dict) else {}
        except Exception:
            return {}

    def _load_workspace_yaml(self, path: Path) -> Dict[str, Any]:
        """Parse the simple key/value workspace.yaml emitted by Copilot."""
        if not path.exists():
            return {}

        data: Dict[str, Any] = {}
        try:
            with open(path, encoding="utf-8") as handle:
                for raw_line in handle:
                    line = raw_line.strip()
                    if not line or ":" not in line:
                        continue
                    key, value = line.split(":", 1)
                    data[key.strip()] = self._coerce_scalar(value.strip())
        except Exception:
            return {}
        return data

    def _coerce_scalar(self, value: str) -> Any:
        """Coerce simple YAML scalars without pulling in a YAML dependency."""
        if value == "":
            return ""
        if value.lower() == "true":
            return True
        if value.lower() == "false":
            return False
        try:
            return int(value)
        except ValueError:
            return value

    def _normalize_optional_timestamp(self, value: Any) -> Optional[datetime]:
        """Normalize a timestamp when possible."""
        if value in (None, ""):
            return None
        try:
            return normalize_timestamp(value)
        except Exception:
            return None

    @staticmethod
    def _format_datetime(value: Optional[datetime]) -> Optional[str]:
        """Format datetimes for session_context."""
        return value.isoformat() if isinstance(value, datetime) else None

    @staticmethod
    def _extract_tool_call_id_from_permission(data: Dict[str, Any]) -> Optional[str]:
        """Extract toolCallId from the permission event payload."""
        if data.get("toolCallId"):
            return data.get("toolCallId")

        permission_request = data.get("permissionRequest", {})
        if isinstance(permission_request, dict) and permission_request.get("toolCallId"):
            return permission_request.get("toolCallId")

        prompt_request = data.get("promptRequest", {})
        if isinstance(prompt_request, dict):
            return prompt_request.get("toolCallId")

        return None

    @staticmethod
    def _extract_permission_kind(data: Dict[str, Any]) -> Optional[str]:
        """Return the requested permission kind if present."""
        permission_request = data.get("permissionRequest", {})
        if isinstance(permission_request, dict) and permission_request.get("kind"):
            return permission_request.get("kind")

        prompt_request = data.get("promptRequest", {})
        if isinstance(prompt_request, dict):
            return prompt_request.get("kind")

        return None

    def _extract_permission_command(self, data: Dict[str, Any]) -> Optional[str]:
        """Return the shell command associated with a permission request."""
        permission_request = data.get("permissionRequest", {})
        if isinstance(permission_request, dict):
            command = permission_request.get("fullCommandText")
            if isinstance(command, str) and command.strip():
                return truncate_middle(command.strip(), max_length=MAX_STRING_LENGTH, edge_chars=EDGE_CHARS)

        prompt_request = data.get("promptRequest", {})
        if isinstance(prompt_request, dict):
            command = prompt_request.get("fullCommandText")
            if isinstance(command, str) and command.strip():
                return truncate_middle(command.strip(), max_length=MAX_STRING_LENGTH, edge_chars=EDGE_CHARS)

        return None
