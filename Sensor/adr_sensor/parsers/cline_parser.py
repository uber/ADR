"""
Parser for Cline (Claude Dev) logs.
Reads JSON files from the Cline extension's task directories.

Supports both macOS and Linux paths.
"""

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..schemas.agent_event_schema import AgentEvent, ChatMessage, ToolUsage
from ..utils.timestamp_utils import normalize_timestamp
from .base_parser import BaseParser


class ClineParser(BaseParser):
    """Parser for Cline (Claude Dev) logs."""

    def __init__(self):
        # Support macOS, Linux, and Windows paths
        macos_path = (
            Path.home()
            / "Library/Application Support/Cursor/User/globalStorage/saoudrizwan.claude-dev/tasks"
        )
        linux_path = (
            Path.home() / ".config/Cursor/User/globalStorage/saoudrizwan.claude-dev/tasks"
        )
        windows_path = (
            Path(os.getenv("APPDATA", Path.home() / "AppData/Roaming")) 
            / "Cursor/User/globalStorage/saoudrizwan.claude-dev/tasks"
        )
        
        if macos_path.exists():
            self.base_path = macos_path
        elif windows_path.exists():
            self.base_path = windows_path
        else:
            self.base_path = linux_path

    def parse_all(self) -> List[AgentEvent]:
        """Parse all available Cline logs."""
        entries = []

        if not self.base_path.exists():
            print(f"[CLINE] No logs found at {self.base_path}")
            return entries

        print(f"[CLINE] Scanning for logs in {self.base_path}")

        task_dirs = [d for d in self.base_path.iterdir() if d.is_dir()]
        print(f"[CLINE] Found {len(task_dirs)} task directories")

        for task_dir in task_dirs:
            try:
                entry = self.parse_cline_log(task_dir)
                if entry:
                    entries.append(entry)
            except Exception as e:
                print(f"[CLINE] Error parsing task {task_dir}: {e}")

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
                pass

        return tools
