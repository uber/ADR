"""
Parser for OpenAI Codex CLI logs.
Discovers JSONL files from $CODEX_HOME/sessions/ and read-only state catalogs.

Performance-optimized: Skips rollout files older than 2 weeks by default.
"""

import json
import math
import os
import sqlite3
import stat
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
        codex_home_env = os.environ.get("CODEX_HOME")
        self.codex_home = Path(codex_home_env).expanduser() if codex_home_env else Path.home() / ".codex"
        self.base_path = self.codex_home / "sessions"
        self.max_age_days = max_age_days

    def parse_all(self) -> List[AgentEvent]:
        """Parse all available Codex logs."""
        entries = []

        rollout_candidates = self._discover_rollout_files()
        if not rollout_candidates:
            print(f"[CODEX] No logs found under {self.codex_home}")
            return entries

        print(f"[CODEX] Found {len(rollout_candidates)} JSONL files")

        rollout_files = list(rollout_candidates)
        if self.max_age_days > 0:
            cutoff_time = datetime.now(timezone.utc) - timedelta(days=self.max_age_days)
            rollout_files = []
            skipped_count = 0

            for jsonl_file, activity_time in rollout_candidates.items():
                if activity_time >= cutoff_time:
                    rollout_files.append(jsonl_file)
                else:
                    skipped_count += 1

            if skipped_count > 0:
                print(f"[CODEX] Skipped {skipped_count} files older than {self.max_age_days} days")

        print(f"[CODEX] Processing {len(rollout_files)} files")

        for jsonl_file in rollout_files:
            try:
                entry = self.parse_jsonl_file(jsonl_file)
                if entry and entry.has_meaningful_content():
                    entries.append(entry)
            except Exception as e:
                print(f"[CODEX] Error parsing {jsonl_file}: {e}")

        return entries

    def _discover_rollout_files(self) -> Dict[Path, datetime]:
        """Return valid rollout paths and their latest known activity times."""
        candidates: Dict[Path, datetime] = {}

        try:
            for rollout_path in self.base_path.glob("**/*.jsonl"):
                self._add_rollout_candidate(candidates, rollout_path)
        except OSError as e:
            # Keep any files yielded before an inaccessible directory interrupted discovery.
            print(f"[CODEX] Error discovering logs under {self.base_path}: {e}")

        try:
            for catalog_path in self.codex_home.glob("state_*.sqlite"):
                self._add_catalog_rollouts(candidates, catalog_path)
        except OSError as e:
            print(f"[CODEX] Error discovering state catalogs under {self.codex_home}: {e}")

        return candidates

    @staticmethod
    def _add_rollout_candidate(
        candidates: Dict[Path, datetime],
        rollout_path: Path,
        catalog_timestamp: Optional[datetime] = None,
    ) -> None:
        """Add one existing regular JSONL file, merging duplicate activity times."""
        try:
            if rollout_path.suffix != ".jsonl":
                return

            resolved_path = rollout_path.resolve()
            file_stat = resolved_path.stat()
            if not stat.S_ISREG(file_stat.st_mode):
                return
            file_mtime = datetime.fromtimestamp(file_stat.st_mtime, tz=timezone.utc)
        except (OSError, RuntimeError, ValueError, OverflowError):
            return

        activity_time = file_mtime
        if catalog_timestamp is not None and catalog_timestamp > activity_time:
            activity_time = catalog_timestamp

        previous_activity = candidates.get(resolved_path)
        if previous_activity is None or activity_time > previous_activity:
            candidates[resolved_path] = activity_time

    def _add_catalog_rollouts(self, candidates: Dict[Path, datetime], catalog_path: Path) -> None:
        """Read rollout paths from one compatible Codex state catalog."""
        connection = None
        try:
            if not catalog_path.is_file():
                return

            catalog_uri = f"{catalog_path.resolve().as_uri()}?mode=ro"
            connection = sqlite3.connect(catalog_uri, uri=True, timeout=0)

            columns = {str(row[1]).lower() for row in connection.execute("PRAGMA table_info(threads)")}
            if not {"id", "rollout_path"}.issubset(columns):
                return

            timestamp_columns = [name for name in ("updated_at", "updated_at_ms") if name in columns]
            selected_columns = ['"id"', '"rollout_path"', *(f'"{name}"' for name in timestamp_columns)]
            query = f'SELECT {", ".join(selected_columns)} FROM "threads"'

            for row in connection.execute(query):
                raw_rollout_path = row[1]
                if not isinstance(raw_rollout_path, str) or not raw_rollout_path:
                    continue

                rollout_path = Path(raw_rollout_path)
                if not rollout_path.is_absolute():
                    rollout_path = self.codex_home / rollout_path

                catalog_timestamp = None
                for column_name, value in zip(timestamp_columns, row[2:]):
                    timestamp = self._parse_catalog_timestamp(value, milliseconds=column_name == "updated_at_ms")
                    if timestamp is not None and (catalog_timestamp is None or timestamp > catalog_timestamp):
                        catalog_timestamp = timestamp

                self._add_rollout_candidate(candidates, rollout_path, catalog_timestamp)
        except (OSError, sqlite3.Error, ValueError) as e:
            print(f"[CODEX] Error reading state catalog {catalog_path}: {e}")
        finally:
            if connection is not None:
                try:
                    connection.close()
                except sqlite3.Error:
                    pass

    @staticmethod
    def _parse_catalog_timestamp(value: Any, milliseconds: bool = False) -> Optional[datetime]:
        """Parse a catalog timestamp, returning None when the value is malformed."""
        if value is None or isinstance(value, bool):
            return None

        if isinstance(value, str):
            raw_value = value.strip()
            if not raw_value:
                return None
            try:
                numeric_value = float(raw_value)
            except ValueError:
                try:
                    iso_value = raw_value[:-1] + "+00:00" if raw_value.endswith(("Z", "z")) else raw_value
                    parsed = datetime.fromisoformat(iso_value)
                    if parsed.tzinfo is None:
                        parsed = parsed.replace(tzinfo=timezone.utc)
                    return parsed.astimezone(timezone.utc)
                except (OSError, ValueError, OverflowError):
                    return None
        elif isinstance(value, (int, float)):
            try:
                numeric_value = float(value)
            except (OverflowError, ValueError):
                return None
        else:
            return None

        if not math.isfinite(numeric_value):
            return None
        if milliseconds or abs(numeric_value) >= 1e12:
            numeric_value /= 1000

        try:
            return datetime.fromtimestamp(numeric_value, tz=timezone.utc)
        except (OSError, ValueError, OverflowError):
            return None

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
