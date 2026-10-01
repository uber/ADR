"""
Parser for Google Antigravity CLI and harness session transcripts.

Reads JSONL transcript files from Antigravity's brain storage
(~/.gemini/antigravity-cli/brain/, ~/.gemini/antigravity2/brain/, and IDE roots)
across macOS, Linux, and Windows. Captures user prompts, assistant thoughts, tool invocations
(including MCP servers and shell tools), status, and execution trajectories.
"""

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..schemas.agent_event_schema import AgentEvent, ChatMessage, ToolUsage
from ..utils.platform_paths import windows_appdata
from ..utils.timestamp_utils import normalize_timestamp
from .base_parser import BaseParser

logger = logging.getLogger(__name__)

MAX_LOG_AGE_DAYS = 14


def _default_candidate_base_paths() -> List[Path]:
    """Candidate brain directories across supported platforms, in order of priority."""
    home = Path.home()
    candidates: List[Path] = [
        home / ".gemini" / "antigravity-cli" / "brain",
        home / ".gemini" / "antigravity2" / "brain",
        home / ".gemini" / "antigravity-ide" / "brain",
        home / ".antigravity" / "brain",
        windows_appdata() / "Google" / "Antigravity" / "brain",
        home / "Library" / "Application Support" / "Google" / "Antigravity" / "brain",
        home / ".config" / "google" / "antigravity" / "brain",
    ]
    seen = set()
    unique = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            unique.append(c)
    return unique


class AntigravityParser(BaseParser):
    """Capture persisted Google Antigravity CLI steps, prompts, and tool invocations."""

    def __init__(self, max_age_days: int = MAX_LOG_AGE_DAYS, base_path: Optional[Path] = None):
        antigravity_home = os.environ.get("ANTIGRAVITY_HOME") or os.environ.get("AGY_HOME")
        if antigravity_home:
            home_path = Path(antigravity_home).expanduser()
            self.base_paths = [home_path / "brain" if (home_path / "brain").is_dir() else home_path]
        else:
            self.base_paths = _default_candidate_base_paths()

        if base_path is not None:
            self.base_paths = [Path(base_path).expanduser()]

        self.max_age_days = max_age_days

    @property
    def base_path(self) -> Path:
        return self.base_paths[0]

    @base_path.setter
    def base_path(self, value: Path) -> None:
        self.base_paths = [Path(value)]

    def parse_all(self) -> List[AgentEvent]:
        """Scan candidate base paths and normalize all discovered Antigravity transcripts."""
        entries: Dict[str, AgentEvent] = {}
        cutoff = None
        if self.max_age_days > 0:
            cutoff = (datetime.now(timezone.utc) - timedelta(days=self.max_age_days)).timestamp()

        scanned_any = False
        scan_failed = False
        seen_paths = set()

        for base in self.base_paths:
            try:
                if not base.is_dir():
                    continue
                scanned_any = True
                logger.info("[ANTIGRAVITY] Scanning for brain sessions in %s", base)

                for conv_dir in sorted(base.iterdir()):
                    if not conv_dir.is_dir():
                        continue

                    # Compare usable snapshots, preferring the full transcript at
                    # the same revision without hiding a newer compact snapshot.
                    transcript_candidates = [
                        conv_dir / ".system_generated" / "logs" / "transcript_full.jsonl",
                        conv_dir / ".system_generated" / "logs" / "transcript.jsonl",
                        conv_dir / "transcript_full.jsonl",
                        conv_dir / "transcript.jsonl",
                    ]

                    for transcript_file in transcript_candidates:
                        if not transcript_file.is_file():
                            continue
                        try:
                            resolved = transcript_file.resolve()
                        except OSError:
                            resolved = transcript_file

                        if resolved in seen_paths:
                            continue
                        seen_paths.add(resolved)

                        failure_code = "file_stat_error"
                        try:
                            if cutoff and transcript_file.stat().st_mtime < cutoff:
                                self.record_diagnostic("file_age_skipped")
                                continue

                            failure_code = "file_read_error"
                            entry = self.parse_transcript_file(transcript_file, conversation_id=conv_dir.name)
                            if entry and entry.has_meaningful_content():
                                old = entries.get(entry.session_id)
                                if old is None or self._revision(entry) > self._revision(old):
                                    entries[entry.session_id] = entry
                        except (OSError, ValueError) as exc:
                            self.record_diagnostic(failure_code)
                            logger.warning("[ANTIGRAVITY] Unable to read %s: %s", transcript_file, exc)

            except OSError as exc:
                scan_failed = True
                self.record_diagnostic("file_read_error")
                logger.error("[ANTIGRAVITY] Error scanning base path %s: %s", base, exc)

        if not scanned_any and not scan_failed:
            self.record_diagnostic("input_missing")
            logger.info("[ANTIGRAVITY] No logs found at %s", self.base_path)

        return list(entries.values())

    @staticmethod
    def _revision(entry: AgentEvent) -> tuple:
        context = entry.session_context or {}
        last_at = context.get("last_event_at")
        ts = normalize_timestamp(last_at) if last_at else entry.timestamp
        return (
            ts,
            context.get("event_count", context.get("step_count", 0)),
            not entry.is_truncated,
            Path(entry.raw_log_path or "").name == "transcript_full.jsonl",
        )

    def _step_timestamp(self, step: Dict[str, Any]) -> Optional[datetime]:
        """Use CLI creation times, accepting the older timestamp spelling too."""
        for field in ("created_at", "timestamp"):
            value = step.get(field)
            if value is None:
                continue
            if isinstance(value, bool):
                self.record_diagnostic("invalid_timestamp")
                continue
            try:
                return normalize_timestamp(value)
            except (TypeError, ValueError, OverflowError, OSError):
                self.record_diagnostic("invalid_timestamp")
        return None

    def parse_transcript_file(self, path: Path, conversation_id: Optional[str] = None) -> Optional[AgentEvent]:
        """Normalize an Antigravity transcript.jsonl file into an AgentEvent."""
        if conversation_id is None:
            if path.parent.name == "logs" and path.parent.parent.name == ".system_generated":
                conversation_id = path.parent.parent.parent.name
            else:
                conversation_id = path.parent.name

        try:
            mod_time = path.stat().st_mtime
            timestamp = datetime.fromtimestamp(mod_time, tz=timezone.utc)
        except OSError:
            self.record_diagnostic("file_stat_error")
            return None

        records: List[Dict[str, Any]] = []
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    stripped = line.strip()
                    if not stripped:
                        continue
                    try:
                        obj = json.loads(stripped)
                        if isinstance(obj, dict):
                            records.append(obj)
                        else:
                            self.record_diagnostic("record_shape_error")
                    except json.JSONDecodeError:
                        self.record_diagnostic("record_decode_error")
        except (OSError, UnicodeError) as exc:
            self.record_diagnostic("file_read_error")
            logger.warning("[ANTIGRAVITY] Failed reading transcript %s: %s", path, exc)
            return None

        if not records:
            return None

        chat_history: List[ChatMessage] = []
        total_tool_calls = 0
        first_event_at: Optional[datetime] = None
        last_event_at: Optional[datetime] = None

        for idx, step in enumerate(records):
            step_type = str(step.get("type", "")).upper()
            role = str(step.get("role", "")).lower()
            source = str(step.get("source", "")).upper()
            raw_content = step.get("content")
            content_str = str(raw_content).strip() if raw_content is not None else ""
            step_index = step.get("step_index", idx)
            seq_id = f"step_{step_index}"

            step_timestamp = self._step_timestamp(step)
            if step_timestamp is not None:
                first_event_at = min(first_event_at or step_timestamp, step_timestamp)
                last_event_at = max(last_event_at or step_timestamp, step_timestamp)

            # 1. User Inputs
            if step_type in ("USER_INPUT", "USER") or role == "user" or source == "USER_EXPLICIT":
                if content_str:
                    chat_history.append(ChatMessage(role="user", content=content_str, tools=[], sequence_id=seq_id))

            # 2. Assistant / Planner Responses & Tools
            elif (
                step_type in ("PLANNER_RESPONSE", "MODEL", "ASSISTANT")
                or role in ("assistant", "model")
                or source == "MODEL"
            ):
                thinking = step.get("thinking")
                if isinstance(thinking, str) and thinking.strip():
                    content_str = (
                        f"[Thinking]\n{thinking}\n\n{content_str}" if content_str else f"[Thinking]\n{thinking}"
                    )
                tools: List[ToolUsage] = []
                tool_calls_raw = step.get("tool_calls")
                if isinstance(tool_calls_raw, list):
                    for tc in tool_calls_raw:
                        if not isinstance(tc, dict):
                            continue
                        tool_usage = self._normalize_tool_call(tc)
                        if tool_usage:
                            tools.append(tool_usage)
                            total_tool_calls += 1

                if content_str or tools:
                    chat_history.append(
                        ChatMessage(
                            role="assistant",
                            content=content_str or "[Agent executed tools]",
                            tools=tools,
                            sequence_id=seq_id,
                        )
                    )

        if not chat_history:
            return None

        session_context = {
            "conversation_id": conversation_id,
            "step_count": len(chat_history),
            "event_count": len(records),
            "tool_call_count": total_tool_calls,
            "last_event_at": (last_event_at or timestamp).isoformat(),
        }

        entry = AgentEvent(
            timestamp=first_event_at or timestamp,
            source="antigravity",
            session_id=f"antigravity_{conversation_id}",
            chat_history=chat_history,
            raw_log_path=str(path),
            session_context=session_context,
            is_truncated=any(bool(step.get("truncated_fields")) for step in records),
        )

        return entry if entry.has_meaningful_content() else None

    @staticmethod
    def _normalize_tool_call(tc: Dict[str, Any]) -> Optional[ToolUsage]:
        """Normalize a tool call dictionary into ADR ToolUsage."""
        name = tc.get("name") or tc.get("toolAction") or tc.get("toolSummary") or "unknown_tool"
        if not isinstance(name, str):
            name = "unknown_tool"
        parameters = next(
            (tc[field] for field in ("parameters", "arguments", "args") if tc.get(field) is not None),
            {},
        )
        if isinstance(parameters, str):
            try:
                parameters = json.loads(parameters)
            except json.JSONDecodeError:
                pass
        if not isinstance(parameters, dict):
            parameters = {"input": parameters}

        # Attribute MCP server if namespaced
        server_name = None
        tool_type = "tool_use"
        if name.startswith("mcp_"):
            parts = name.split("_", 2)
            if len(parts) >= 3:
                server_name = parts[1]
                tool_type = "mcp_tool"
        elif ":" in name:
            parts = name.split(":", 1)
            server_name = parts[0]
            tool_type = "mcp_tool"

        status = tc.get("status")
        return ToolUsage(
            tool_name=name,
            tool_type=tool_type,
            server_name=server_name,
            arguments=parameters,
            status=str(status) if status else None,
        )
