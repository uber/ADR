"""
Parser for Cursor IDE logs.
Extracts composerData from SQLite database.

Supports macOS, Linux and Windows paths.
Memory-optimized: Uses cursor iteration instead of fetchall().
Performance-optimized: Skips conversations older than 2 weeks.
"""

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from ..schemas.agent_event_schema import AgentEvent, ChatMessage, ToolUsage
from ..utils.platform_paths import windows_appdata
from ..utils.string_utils import truncate_middle
from ..utils.timestamp_utils import normalize_timestamp
from .base_parser import BaseParser

DB_BATCH_SIZE = 500
MAX_CONVERSATION_AGE_DAYS = 14

# Path to Cursor's global storage database, relative to the per-platform app-data root.
_CURSOR_STORAGE_SUFFIX = "Cursor/User/globalStorage/state.vscdb"


class CursorParser(BaseParser):
    """Parser for Cursor SQLite database logs."""

    #: Candidate database locations, checked in order.
    DB_PATHS = [
        Path.home() / "Library/Application Support" / _CURSOR_STORAGE_SUFFIX,  # macOS
        Path.home() / ".config" / _CURSOR_STORAGE_SUFFIX,  # Linux
        windows_appdata() / _CURSOR_STORAGE_SUFFIX,  # Windows (%APPDATA%)
    ]

    def __init__(self, max_age_days: int = MAX_CONVERSATION_AGE_DAYS):
        self.db_path = next((p for p in self.DB_PATHS if p.exists()), self.DB_PATHS[0])
        self.max_age_days = max_age_days

    def parse_all(self) -> List[AgentEvent]:
        """Parse all available Cursor logs."""
        entries = []

        if not self.db_path.exists():
            print(f"[CURSOR] No database found at {self.db_path}")
            return entries

        try:
            entries = self.parse_conversations_from_bubbles()
            print(f"[CURSOR] Found {len(entries)} entries")
        except Exception as e:
            print(f"[CURSOR] Error parsing database: {e}")

        return entries

    def parse_conversations_from_bubbles(self) -> List[AgentEvent]:
        """Parse conversations by grouping bubble entries by conversation ID."""
        entries = []

        try:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()

                composer_metadata = self.get_composer_metadata(cursor)

                cutoff_time = datetime.now(timezone.utc) - timedelta(days=self.max_age_days)
                recent_conv_ids = set()
                skipped_count = 0

                for conv_id, metadata in composer_metadata.items():
                    conv_timestamp = None
                    if "lastUpdatedAt" in metadata:
                        try:
                            conv_timestamp = normalize_timestamp(metadata["lastUpdatedAt"])
                        except Exception:
                            pass
                    if conv_timestamp is None and "createdAt" in metadata:
                        try:
                            conv_timestamp = normalize_timestamp(metadata["createdAt"])
                        except Exception:
                            pass

                    if conv_timestamp is None or conv_timestamp >= cutoff_time:
                        recent_conv_ids.add(conv_id)
                    else:
                        skipped_count += 1

                if skipped_count > 0:
                    print(f"[CURSOR] Skipped {skipped_count} conversations older than {self.max_age_days} days")

                cursor.execute("SELECT key, value FROM cursorDiskKV WHERE key LIKE 'bubbleId:%'")

                conversations: Dict[str, List] = {}
                for key, value in self._iter_cursor_batches(cursor):
                    try:
                        parts = key.split(":")
                        if len(parts) >= 3:
                            conv_id = parts[1]

                            if conv_id not in recent_conv_ids:
                                continue

                            if conv_id not in conversations:
                                conversations[conv_id] = []

                            if isinstance(value, str):
                                try:
                                    bubble_data = json.loads(value)
                                    conversations[conv_id].append(bubble_data)
                                except json.JSONDecodeError:
                                    continue
                            else:
                                conversations[conv_id].append(value)
                    except Exception:
                        continue

                for conv_id, bubbles in conversations.items():
                    try:
                        entry = self.parse_conversation(conv_id, bubbles, composer_metadata)
                        if entry:
                            entries.append(entry)
                    except Exception:
                        pass
            finally:
                conn.close()

        except Exception as e:
            print(f"[CURSOR] Error parsing conversations: {e}")

        return entries

    def _iter_cursor_batches(self, cursor) -> Iterator[tuple]:
        """Iterate over cursor results in batches to control memory usage."""
        while True:
            rows = cursor.fetchmany(DB_BATCH_SIZE)
            if not rows:
                break
            for row in rows:
                yield row

    def get_composer_metadata(self, cursor) -> Dict[str, Any]:
        """Get composer metadata including timestamps."""
        metadata = {}

        try:
            cursor.execute("SELECT key, value FROM cursorDiskKV WHERE key LIKE 'composerData:%'")

            for key, value_blob in self._iter_cursor_batches(cursor):
                try:
                    composer_id = key.split(":", 1)[1] if ":" in key else key

                    if isinstance(value_blob, bytes):
                        value_str = value_blob.decode("utf-8", errors="ignore")
                    else:
                        value_str = str(value_blob)

                    try:
                        data = json.loads(value_str)
                        if isinstance(data, dict):
                            metadata_entry = {}
                            if "createdAt" in data:
                                metadata_entry["createdAt"] = data["createdAt"]
                            if "lastUpdatedAt" in data:
                                metadata_entry["lastUpdatedAt"] = data["lastUpdatedAt"]
                            if metadata_entry:
                                metadata[composer_id] = metadata_entry
                    except json.JSONDecodeError:
                        pass

                except Exception:
                    continue

        except Exception as e:
            print(f"[CURSOR] Error getting composer metadata: {e}")

        return metadata

    def parse_conversation(
        self, conv_id: str, bubbles: List[Dict[str, Any]], composer_metadata: Dict[str, Any]
    ) -> Optional[AgentEvent]:
        """Parse a single conversation from its bubbles."""
        try:
            valid_bubbles = [b for b in bubbles if isinstance(b, dict)]

            if not valid_bubbles:
                return None

            sorted_bubbles = sorted(valid_bubbles, key=lambda b: b.get("_bubble_id", ""))

            timestamp = datetime.now(timezone.utc)
            if conv_id in composer_metadata:
                metadata = composer_metadata[conv_id]
                if "lastUpdatedAt" in metadata:
                    try:
                        timestamp = normalize_timestamp(metadata["lastUpdatedAt"])
                    except Exception:
                        pass
                elif "createdAt" in metadata:
                    try:
                        timestamp = normalize_timestamp(metadata["createdAt"])
                    except Exception:
                        pass

            entry = AgentEvent(timestamp=timestamp, source="cursor", session_id=f"cursor_{conv_id}")

            for i, bubble in enumerate(sorted_bubbles):
                bubble_type = bubble.get("type", -1)
                sequence_id = bubble.get("checkpointId", "") or bubble.get("_bubble_id", "") or f"seq_{i}"

                if bubble_type == 1:
                    text = self.extract_text_from_bubble(bubble)
                    if text:
                        msg = ChatMessage(role="user", content=text, sequence_id=sequence_id)
                        entry.chat_history.append(msg)

                elif bubble_type == 2:
                    text = self.extract_text_from_bubble(bubble)
                    tools = self.extract_tools_from_bubble(bubble)

                    if not text and tools:
                        text = "[Assistant decided to use a tool]"

                    if text or tools:
                        msg = ChatMessage(role="assistant", content=text, tools=tools, sequence_id=sequence_id)
                        entry.chat_history.append(msg)

            if not entry.has_meaningful_content():
                return None

            return entry

        except Exception:
            pass

        return None

    def extract_text_from_bubble(self, bubble: Dict[str, Any]) -> str:
        """Extract plain text from a bubble."""
        text = bubble.get("text", "") or ""
        rich_text = bubble.get("richText", "") or ""

        if isinstance(rich_text, str) and rich_text.startswith('{"root":'):
            try:
                rich_data = json.loads(rich_text)
                extracted_text = self._extract_text_recursive(rich_data)
                if extracted_text:
                    return extracted_text.strip()
            except json.JSONDecodeError:
                pass

        if isinstance(text, str):
            return text.strip()

        return ""

    def extract_tools_from_bubble(self, bubble: Dict[str, Any]) -> List[ToolUsage]:
        """Extract tool usage from a bubble."""
        tools = []
        if "toolFormerData" in bubble:
            tool_data = bubble["toolFormerData"]
            if isinstance(tool_data, dict):
                tool_name = tool_data.get("name") or tool_data.get("tool") or "unknown"
                if tool_name == "unknown":
                    return []

                args = tool_data.get("params", tool_data.get("rawArgs", {}))
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except Exception:
                        args = {"raw_args": args}
                elif not isinstance(args, dict):
                    args = {"raw_args": str(args)}

                # Truncate large argument values
                truncated_args: Dict[str, Any] = {}
                for key, value in args.items():
                    if isinstance(value, str) and len(value) > 1000:
                        truncated_args[key] = truncate_middle(value, max_length=1000, edge_chars=400)
                    else:
                        truncated_args[key] = value

                status = tool_data.get("status", "unknown")
                error = tool_data.get("error", "")

                result = None
                if tool_name == "list_dir":
                    result = tool_data.get("result", "")
                    if result and isinstance(result, str):
                        result = truncate_middle(result.strip(), max_length=1000, edge_chars=400)

                tool = ToolUsage(
                    tool_name=tool_name,
                    tool_type="tool_call",
                    arguments=truncated_args,
                    status=status,
                    error=error,
                    result=result,
                )
                tools.append(tool)
        return tools

    def _extract_text_recursive(self, node) -> str:
        """Extract plain text from Cursor's rich text structure."""
        try:
            if isinstance(node, dict):
                if "text" in node and isinstance(node["text"], str):
                    return node["text"]
                elif "children" in node and isinstance(node["children"], list):
                    return " ".join(self._extract_text_recursive(child) for child in node["children"])
            elif isinstance(node, list):
                return " ".join(self._extract_text_recursive(item) for item in node)
        except Exception:
            pass
        return ""
