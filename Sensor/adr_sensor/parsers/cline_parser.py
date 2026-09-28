"""
Parser for Cline (Claude Dev) logs.
Reads JSON files from the Cline extension's task directories.

Supports macOS, Linux and Windows paths.
"""

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional

from ..schemas.agent_event_schema import AgentEvent, ChatMessage, ToolUsage
from ..utils.platform_paths import windows_appdata
from .base_parser import BaseParser

# Task history subpath for the Cline extension across VS Code-based editors,
# relative to the per-platform app-data root.
_CLINE_TASKS_SUBPATH = "User/globalStorage/saoudrizwan.claude-dev/tasks"

# Legacy alias for backward compatibility.
_CLINE_TASKS_SUFFIX = f"Cursor/{_CLINE_TASKS_SUBPATH}"

# Editors known to host the Cline extension, ordered by prominence.
_SUPPORTED_EDITORS = (
    "Code",  # Visual Studio Code (primary)
    "Cursor",  # Cursor
    "Code - Insiders",  # Visual Studio Code Insiders
    "VSCodium",  # VSCodium
    "Windsurf",  # Windsurf
)
MAX_LOG_AGE_DAYS = 14


def _build_candidate_base_paths() -> List[Path]:
    """Generate candidate task directories across supported editors and platforms."""
    candidates: List[Path] = []
    for editor in _SUPPORTED_EDITORS:
        suffix = f"{editor}/{_CLINE_TASKS_SUBPATH}"
        candidates.extend(
            [
                Path.home() / "Library/Application Support" / suffix,  # macOS
                Path.home() / ".config" / suffix,  # Linux
                windows_appdata() / suffix,  # Windows (%APPDATA%)
            ]
        )
    return candidates


class ClineParser(BaseParser):
    """Parser for Cline (Claude Dev) logs."""

    #: Candidate task directories, checked in order across supported editors and platforms.
    BASE_PATHS = _build_candidate_base_paths()

    def __init__(
        self,
        max_age_days: int = MAX_LOG_AGE_DAYS,
        base_path: Optional[Path] = None,
    ):
        self._custom_base_path = Path(base_path) if base_path is not None else None
        if self._custom_base_path is not None:
            self.base_path = self._custom_base_path
        else:
            self.base_path = next((p for p in self.BASE_PATHS if p.exists()), self.BASE_PATHS[0])
        self.max_age_days = max_age_days

    def _candidate_base_paths(self) -> List[Path]:
        """Return task directories to scan for Cline logs."""
        custom_base_path = getattr(self, "_custom_base_path", None)
        if custom_base_path is not None:
            return [custom_base_path]
        if self.base_path not in self.BASE_PATHS:
            # An external caller or test directly mutated self.base_path
            return [self.base_path]
        existing = [p for p in self.BASE_PATHS if p.exists()]
        return existing if existing else [self.base_path]

    def parse_all(self) -> List[AgentEvent]:
        """Parse all available Cline logs."""
        entries: List[AgentEvent] = []
        candidate_paths = self._candidate_base_paths()
        scanned_any = False
        seen_sessions = set()

        for base_path in candidate_paths:
            if not base_path.exists():
                continue

            scanned_any = True
            print(f"[CLINE] Scanning for logs in {base_path}")

            task_dirs = [d for d in base_path.iterdir() if d.is_dir()]
            print(f"[CLINE] Found {len(task_dirs)} task directories")

            if self.max_age_days > 0:
                cutoff_timestamp = (datetime.now(timezone.utc) - timedelta(days=self.max_age_days)).timestamp()
                recent_task_dirs = []
                skipped_count = 0

                for task_dir in task_dirs:
                    api_file = task_dir / "api_conversation_history.json"
                    try:
                        modified_at = api_file.stat().st_mtime
                    except OSError as exc:
                        # A missing conversation file uses the task timestamp; an
                        # inaccessible task below is a separate inspection failure.
                        if not isinstance(exc, FileNotFoundError):
                            self.record_diagnostic("file_stat_error")
                        try:
                            modified_at = task_dir.stat().st_mtime
                        except OSError as e:
                            self.record_diagnostic("file_stat_error")
                            print(f"[CLINE] Error checking task {task_dir}: {e}")
                            recent_task_dirs.append(task_dir)
                            continue

                    if modified_at >= cutoff_timestamp:
                        recent_task_dirs.append(task_dir)
                    else:
                        skipped_count += 1

                task_dirs = recent_task_dirs
                if skipped_count > 0:
                    self.record_diagnostic("file_age_skipped", skipped_count)
                    print(f"[CLINE] Skipped {skipped_count} tasks older than {self.max_age_days} days")

            print(f"[CLINE] Processing {len(task_dirs)} task directories")

            for task_dir in task_dirs:
                try:
                    entry = self.parse_cline_log(task_dir)
                    if entry and entry.session_id not in seen_sessions:
                        seen_sessions.add(entry.session_id)
                        entries.append(entry)
                except Exception as e:
                    self.record_diagnostic("session_build_error")
                    print(f"[CLINE] Error parsing task {task_dir}: {e}")

        if not scanned_any:
            self.record_diagnostic("input_missing")
            print(f"[CLINE] No logs found at {self.base_path}")

        return entries

    def parse_cline_log(self, task_dir: Path) -> Optional[AgentEvent]:
        """Parse a single Cline task log."""
        try:
            api_file = task_dir / "api_conversation_history.json"
            if not api_file.exists():
                return None

            with open(api_file, encoding="utf-8") as f:
                conversation = json.load(f)

            if not conversation:
                return None

            # Use file modification time for timestamp
            file_mod_time = api_file.stat().st_mtime
            timestamp = datetime.fromtimestamp(file_mod_time, tz=timezone.utc)

            entry = AgentEvent(timestamp=timestamp, source="cline", session_id=f"cline_{task_dir.name}")

            for i, message in enumerate(conversation):
                role = message.get("role", "")
                content = message.get("content", [])
                sequence_id = f"msg_{i}"

                if role == "user":
                    prompt_text = self.extract_text_from_content(content)
                    if prompt_text:
                        msg = ChatMessage(role="user", content=prompt_text, tools=[], sequence_id=sequence_id)
                        entry.chat_history.append(msg)

                elif role == "assistant":
                    response_text = self.extract_text_from_content(content)
                    tool_usages = self.extract_mcp_tools(response_text) if response_text else []

                    if response_text or tool_usages:
                        msg = ChatMessage(
                            role="assistant",
                            content=response_text or "[Assistant used tools]",
                            tools=tool_usages,
                            sequence_id=sequence_id,
                        )
                        entry.chat_history.append(msg)

            return entry if entry.has_meaningful_content() else None

        except Exception as e:
            if isinstance(e, json.JSONDecodeError):
                self.record_diagnostic("record_decode_error")
            elif isinstance(e, (OSError, UnicodeError)):
                self.record_diagnostic("file_read_error")
            else:
                self.record_diagnostic("session_build_error")
            print(f"[CLINE] Error parsing task {task_dir}: {e}")
            return None

    def extract_text_from_content(self, content: List[Dict]) -> str:
        """Extract text from content array."""
        texts = []

        if isinstance(content, list):
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text":
                    text = item.get("text", "")
                    if "<environment_details>" in text:
                        text = text.split("<environment_details>")[0].strip()
                    if "<task>" in text:
                        match = re.search(r"<task>(.*?)</task>", text, re.DOTALL)
                        if match:
                            text = match.group(1).strip()
                    texts.append(text)

        return " ".join(texts).strip()

    def extract_mcp_tools(self, text: str) -> List[ToolUsage]:
        """Extract MCP tool usage from text."""
        tools = []

        mcp_pattern = (
            r"<use_mcp_tool>\s*<server_name>([^<]+)</server_name>\s*"
            r"<tool_name>([^<]+)</tool_name>\s*"
            r"<arguments>\s*(\{.*?\})\s*</arguments>\s*</use_mcp_tool>"
        )
        matches = re.findall(mcp_pattern, text, re.DOTALL)

        for server_name, tool_name, arguments_str in matches:
            try:
                arguments = json.loads(arguments_str)
                tool = ToolUsage(
                    tool_name=tool_name,
                    tool_type="mcp_tool",
                    server_name=server_name,
                    arguments=arguments,
                )
                tools.append(tool)
            except json.JSONDecodeError:
                self.record_diagnostic("record_decode_error")
                pass

        return tools
