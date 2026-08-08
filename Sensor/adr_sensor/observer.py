"""
AgentObserver - Main class for observing and analyzing AI agent interactions.

This is the central orchestrator that coordinates all parsers and manages
the ingestion, display, and export of agent telemetry data.
"""

import json
import os
import platform
import sys
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from tabulate import tabulate

from .parsers.claude_desktop_parser import ClaudeDesktopParser
from .parsers.claude_parser import ClaudeParser
from .parsers.cline_parser import ClineParser
from .parsers.codex_parser import CodexParser
from .parsers.cursor_parser import CursorParser
from .parsers.opencode_parser import OpencodeParser
from .parsers.warp_parser import WarpParser
from .schemas.agent_event_schema import AgentEvent
from .schemas.system_config_schema import SystemConfiguration
from .utils.timestamp_utils import format_timestamp_for_filename, normalize_timestamp, parse_timestamp_from_filename


class AgentObserver:
    """Main class for observing and analyzing AI agent interactions.

    The AgentObserver coordinates multiple parsers to collect telemetry
    from various AI coding agents and provides unified output.

    Example:
        observer = AgentObserver()
        events, configs = observer.ingest_all()
        observer.display_summary(events, configs)
        observer.save_to_file(events, configs)
    """

    #: Supported sources in ingestion order, as (source key, display label).
    #: The parser for each source is looked up as ``self.<source>_parser``.
    SOURCES = (
        ("claude", "Claude Code"),
        ("cursor", "Cursor"),
        ("claude_desktop", "Claude Desktop Agent Mode"),
        ("cline", "Cline"),
        ("warp", "Warp Terminal"),
        ("codex", "Codex"),
        ("opencode", "opencode"),
    )

    #: Sources that only produce logs on some operating systems. A source absent
    #: from this map is attempted on every platform.
    PLATFORM_RESTRICTED_SOURCES = {
        "claude_desktop": ("Darwin", "Windows"),
    }

    def __init__(self, output_dir: Optional[Path] = None, max_age_days: Optional[int] = None):
        """Initialize the AgentObserver.

        Args:
            output_dir: Directory to save output files. Defaults to ./output.
            max_age_days: Maximum age of logs to process. None uses parser defaults (14 days).
        """
        self.claude_parser = ClaudeParser(max_age_days=max_age_days) if max_age_days is not None else ClaudeParser()
        self.cursor_parser = CursorParser(max_age_days=max_age_days) if max_age_days is not None else CursorParser()
        self.claude_desktop_parser = (
            ClaudeDesktopParser(max_age_days=max_age_days) if max_age_days is not None else ClaudeDesktopParser()
        )
        self.codex_parser = CodexParser()
        self.cline_parser = ClineParser()
        self.warp_parser = WarpParser(max_age_days=max_age_days) if max_age_days is not None else WarpParser()
        self.opencode_parser = (
            OpencodeParser(max_age_days=max_age_days) if max_age_days is not None else OpencodeParser()
        )

        self.output_dir = output_dir if output_dir else Path("output")
        self.output_dir.mkdir(exist_ok=True)

    def _emit_error(self, error_payload: Dict[str, Any]) -> None:
        """Append a single-line JSON error record to error.log. Best-effort, never raises."""
        try:
            record = {
                "timestamp": datetime.utcnow().isoformat(timespec="milliseconds") + "Z",
                "host_os": platform.system(),
                "python_version": sys.version.split()[0],
                "pid": os.getpid(),
            }
            record.update(error_payload)
            log_path = self.output_dir / "error.log"
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, separators=(",", ":"), ensure_ascii=False) + "\n")
        except Exception:
            pass

    def _get_default_session_dir(self) -> Path:
        """Get the default directory for session files."""
        xdg_cache_home = os.getenv("XDG_CACHE_HOME")
        if xdg_cache_home:
            cache_dir = Path(xdg_cache_home)
        else:
            cache_dir = Path.home() / ".cache"

        return cache_dir / "adr_sensor"

    def ingest_all(
        self, source_filter: str = "all"
    ) -> Tuple[List[AgentEvent], List[SystemConfiguration]]:
        """Ingest logs from all supported sources.

        Args:
            source_filter: Which source to ingest. One of 'all', 'claude', 'cursor',
                'claude_desktop', 'cline', 'warp', 'codex', 'opencode'.

        Returns:
            Tuple of (agent_events, system_configs).
        """
        all_entries: List[AgentEvent] = []
        system_config_data: List[SystemConfiguration] = []

        print("\n" + "=" * 80)
        print("ADR Sensor Starting...")
        print("=" * 80 + "\n")

        host_os = platform.system()

        for source, label in self.SOURCES:
            if source_filter not in ("all", source):
                continue

            supported_platforms = self.PLATFORM_RESTRICTED_SOURCES.get(source)
            if supported_platforms and host_os not in supported_platforms:
                continue

            print(f"Ingesting {label} logs...")
            try:
                entries = getattr(self, f"{source}_parser").parse_all()
                filtered = [e for e in entries if e.has_meaningful_content()]
                all_entries.extend(filtered)
                print(f"Found {len(filtered)} entries\n")
            except Exception as e:
                print(f"Error ingesting {label} logs: {e}")
                self._emit_error({
                    "source": source,
                    "stage": "parse",
                    "error_type": e.__class__.__name__,
                    "message": str(e),
                    "trace": traceback.format_exc(limit=5),
                })

        return all_entries, system_config_data

    def display_summary(
        self, entries: List[AgentEvent], system_config_data: List[SystemConfiguration]
    ) -> None:
        """Display a summary of ingested logs."""
        if not entries and not system_config_data:
            print("No logs found!")
            return

        by_source: Dict[str, list] = {}
        for entry in entries:
            if entry.source not in by_source:
                by_source[entry.source] = []
            by_source[entry.source].append(entry)

        if system_config_data:
            by_source["system_config"] = system_config_data

        print("\n" + "=" * 80)
        print("INGESTION SUMMARY")
        print("=" * 80 + "\n")

        summary_data = []
        for source, source_entries in by_source.items():
            if source == "system_config":
                summary_data.append([source.upper(), len(source_entries), "N/A", "N/A"])
            else:
                msg_count = sum(len(e.chat_history) for e in source_entries)
                tool_count = sum(
                    sum(len(msg.tools) for msg in e.chat_history if msg.role == "assistant")
                    for e in source_entries
                )
                summary_data.append([source.upper(), len(source_entries), msg_count, tool_count])

        print(
            tabulate(
                summary_data,
                headers=["Source", "Conversations", "Messages", "Tool Usage"],
                tablefmt="grid",
            )
        )
        print()

    def save_to_file(
        self,
        entries: List[AgentEvent],
        system_config_data: List[SystemConfiguration],
        output_format: str = "json",
        output_dir: Optional[Path] = None,
    ) -> List[Path]:
        """Save entries to files.

        Args:
            entries: Agent events to save.
            system_config_data: System configurations to save.
            output_format: 'json' or 'jsonl'.
            output_dir: Override output directory.

        Returns:
            List of saved file paths.
        """
        target_dir = output_dir if output_dir else self.output_dir
        target_dir.mkdir(exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        saved_files = []

        if entries:
            if output_format == "json":
                output_file = target_dir / f"agent_event_logs_{timestamp}.json"
                data = {
                    "timestamp": datetime.now().isoformat(),
                    "total_entries": len(entries),
                    "entries": [entry.get_non_null_fields() for entry in entries],
                }
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
            elif output_format == "jsonl":
                output_file = target_dir / f"agent_event_logs_{timestamp}.jsonl"
                with open(output_file, "w", encoding="utf-8") as f:
                    for entry in entries:
                        f.write(json.dumps(entry.get_non_null_fields(), ensure_ascii=False) + "\n")

            print(f"\nAgent event logs saved to: {output_file}")
            saved_files.append(output_file)

        if system_config_data:
            if output_format == "json":
                config_file = target_dir / f"system_configuration_{timestamp}.json"
                with open(config_file, "w", encoding="utf-8") as f:
                    json.dump(
                        system_config_data[0].to_dict() if system_config_data else {},
                        f,
                        indent=2,
                        ensure_ascii=False,
                    )
            elif output_format == "jsonl":
                config_file = target_dir / f"system_configuration_{timestamp}.jsonl"
                with open(config_file, "w", encoding="utf-8") as f:
                    for config in system_config_data:
                        f.write(json.dumps(config.to_dict(), ensure_ascii=False) + "\n")

            print(f"System configuration saved to: {config_file}")
            saved_files.append(config_file)

        return saved_files

    def save_sessions_to_individual_files(
        self, entries: List[AgentEvent], output_dir: Optional[Path] = None
    ) -> List[Path]:
        """Save each session to its own file for incremental processing.

        Args:
            entries: Agent events to save individually.
            output_dir: Override output directory.

        Returns:
            List of saved file paths.
        """
        if output_dir is None:
            output_dir = self._get_default_session_dir()
        else:
            output_dir = Path(output_dir)

        output_dir.mkdir(parents=True, exist_ok=True)
        saved_files = []

        for entry in entries:
            timestamp_str = format_timestamp_for_filename(entry.timestamp)
            clean_session_id = self._clean_filename(entry.session_id)
            filename = f"adr.{clean_session_id}.{timestamp_str}.json"
            file_path = output_dir / filename

            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(entry.get_non_null_fields(), f, indent=2, ensure_ascii=False)
                saved_files.append(file_path)
                print(f"Saved session: {filename}")
            except Exception as e:
                print(f"Error saving session {filename}: {e}")

        print(f"\nSaved {len(saved_files)} sessions to: {output_dir}")
        return saved_files

    def filter_entries_by_existing_files(
        self, entries: List[AgentEvent], output_dir: Optional[Path] = None
    ) -> List[AgentEvent]:
        """Filter out entries that haven't changed since last processing."""
        existing_files = self._get_existing_session_files(output_dir)

        filtered_entries = []
        for entry in entries:
            session_id = entry.session_id
            if session_id not in existing_files:
                filtered_entries.append(entry)
                continue

            existing_info = existing_files[session_id]
            existing_ts = normalize_timestamp(existing_info["timestamp"]).replace(microsecond=0)
            entry_ts = normalize_timestamp(entry.timestamp).replace(microsecond=0)

            if entry_ts > existing_ts:
                filtered_entries.append(entry)

        return filtered_entries

    def _get_existing_session_files(self, output_dir: Optional[Path] = None) -> Dict[str, Dict[str, Any]]:
        """Get a mapping of session_id to file info for existing session files."""
        if output_dir is None:
            output_dir = self._get_default_session_dir()
        else:
            output_dir = Path(output_dir)

        if not output_dir.exists():
            return {}

        existing_files: Dict[str, Dict[str, Any]] = {}
        for file_path in output_dir.glob("adr.*.json"):
            filename = file_path.name
            if filename.startswith("adr.") and filename.endswith(".json"):
                session_part = filename[4:-5]
                parts = session_part.rsplit(".", 1)
                if len(parts) == 2:
                    session_id = parts[0]
                    file_timestamp = parse_timestamp_from_filename(filename)
                    if file_timestamp:
                        if session_id not in existing_files or file_timestamp > existing_files[session_id]["timestamp"]:
                            existing_files[session_id] = {
                                "file_path": file_path,
                                "timestamp": file_timestamp,
                                "filename": filename,
                            }

        return existing_files

    def _clean_filename(self, session_id: str) -> str:
        """Clean session_id for use in filename."""
        replacements = {
            "\n": "_", "\r": "_", "\t": "_",
            "/": "_", "\\": "_", ":": "_", "*": "_", "?": "_",
            '"': "_", "<": "_", ">": "_", "|": "_", " ": "_",
        }

        clean_id = session_id
        for old_char, new_char in replacements.items():
            clean_id = clean_id.replace(old_char, new_char)

        while "__" in clean_id:
            clean_id = clean_id.replace("__", "_")

        clean_id = clean_id.strip("_")

        max_session_length = 200
        if len(clean_id) > max_session_length:
            clean_id = clean_id[:max_session_length]

        return clean_id
