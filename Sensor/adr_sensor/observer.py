"""
AgentObserver - Main class for observing and analyzing AI agent interactions.

This is the central orchestrator that coordinates all parsers and manages
the ingestion, display, and export of agent telemetry data.
"""

import errno
import hashlib
import json
import os
import platform
import re
import secrets
import stat
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from tabulate import tabulate

from .parsers.claude_desktop_parser import ClaudeDesktopParser
from .parsers.claude_parser import ClaudeParser
from .parsers.cline_parser import ClineParser
from .parsers.codex_parser import CodexParser
from .parsers.copilot_parser import CopilotParser
from .parsers.cursor_parser import CursorParser
from .parsers.opencode_parser import OpencodeParser
from .parsers.warp_parser import WarpParser
from .schemas.agent_event_schema import AgentEvent
from .schemas.system_config_schema import SystemConfiguration
from .utils.timestamp_utils import format_timestamp_for_filename, normalize_timestamp, parse_timestamp_from_filename

_COLLISION_SUFFIX_PATTERN = re.compile(r"_([0-9a-f]{64})(?:_(\d+))?$")


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
        ("copilot", "GitHub Copilot"),
        ("opencode", "opencode"),
    )

    #: Sources that only produce logs on some operating systems. A source absent
    #: from this map is attempted on every platform.
    PLATFORM_RESTRICTED_SOURCES = {
        "claude_desktop": ("Darwin", "Windows"),
    }

    CONTENT_AWARE_INCREMENTAL_SOURCES = frozenset({"codex", "copilot"})

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
        self.copilot_parser = CopilotParser()
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
                'claude_desktop', 'cline', 'warp', 'codex', 'copilot', 'opencode'.

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
        session_file_index = (
            self._build_session_file_index(output_dir)
            if any(entry.source in self.CONTENT_AWARE_INCREMENTAL_SOURCES for entry in entries)
            else {}
        )

        for entry in entries:
            timestamp_str = format_timestamp_for_filename(entry.timestamp)
            filename_session_id = (
                self._session_filename_id(entry.session_id)
                if entry.source in self.CONTENT_AWARE_INCREMENTAL_SOURCES
                else self._clean_filename(entry.session_id)
            )
            filename = f"adr.{filename_session_id}.{timestamp_str}.json"
            file_path = output_dir / filename
            temp_path: Optional[Path] = None
            lock_path: Optional[Path] = None
            lock_fd: Optional[int] = None

            try:
                if entry.source in self.CONTENT_AWARE_INCREMENTAL_SOURCES:
                    lock_path = output_dir / f".adr.{filename_session_id}.lock"
                    lock_fd = self._acquire_session_lock(lock_path)
                    existing_info = self._find_session_file(entry, session_file_index)
                    file_path = self._resolve_session_file_path(
                        output_dir, entry, filename_session_id, timestamp_str, existing_info
                    )
                    filename = file_path.name
                    fresh_target = self._session_file_info(file_path)
                    if (
                        fresh_target is not None
                        and fresh_target["data"].get("session_id") == entry.session_id
                    ):
                        existing_info = self._newer_session_file(existing_info, fresh_target)
                    if self._session_revision_regresses(entry, existing_info):
                        print(f"Skipped stale session: {filename}")
                        continue

                entry_data = entry.get_non_null_fields()
                temp_path, temp_fd = self._create_session_temp(output_dir, filename, file_path)
                with os.fdopen(temp_fd, mode="w", encoding="utf-8") as f:
                    json.dump(entry_data, f, indent=2, ensure_ascii=False)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(temp_path, file_path)
                temp_path = None
                self._sync_session_directory(output_dir)

                if entry.source in self.CONTENT_AWARE_INCREMENTAL_SOURCES:
                    removed_stale_files = self._remove_stale_session_files(
                        entry.session_id,
                        file_path,
                        self._session_file_candidates(entry, session_file_index),
                    )
                    if removed_stale_files:
                        self._sync_session_directory(output_dir)
                    self._index_session_file(session_file_index, file_path, entry_data)

                saved_files.append(file_path)
                print(f"Saved session: {filename}")
            except Exception as e:
                print(f"Error saving session {filename}: {e}")
                self._emit_error(
                    {
                        "source": entry.source,
                        "stage": "save_session",
                        "error_type": e.__class__.__name__,
                        "message": str(e),
                        "session_id": entry.session_id,
                    }
                )
            finally:
                if temp_path is not None and temp_path.exists():
                    try:
                        temp_path.unlink()
                    except OSError as cleanup_error:
                        print(f"Error removing temporary session file {temp_path.name}: {cleanup_error}")
                if lock_fd is not None and lock_path is not None:
                    self._release_session_lock(lock_fd)

        print(f"\nSaved {len(saved_files)} sessions to: {output_dir}")
        return saved_files

    def filter_entries_by_existing_files(
        self, entries: List[AgentEvent], output_dir: Optional[Path] = None
    ) -> List[AgentEvent]:
        """Filter out entries that haven't changed since last processing."""
        existing_files = self._get_existing_session_files(output_dir)
        target_dir = Path(output_dir) if output_dir is not None else self._get_default_session_dir()
        session_file_index = (
            self._build_session_file_index(target_dir)
            if any(entry.source in self.CONTENT_AWARE_INCREMENTAL_SOURCES for entry in entries)
            else {}
        )

        filtered_entries = []
        for entry in entries:
            filename_session_id = (
                self._session_filename_id(entry.session_id)
                if entry.source in self.CONTENT_AWARE_INCREMENTAL_SOURCES
                else self._clean_filename(entry.session_id)
            )
            existing_info = existing_files.get(filename_session_id)
            if entry.source in self.CONTENT_AWARE_INCREMENTAL_SOURCES:
                existing_info = self._find_session_file(entry, session_file_index)

            if existing_info is None:
                filtered_entries.append(entry)
                continue

            if entry.source in self.CONTENT_AWARE_INCREMENTAL_SOURCES:
                if self._session_content_changed(entry, existing_info):
                    existing_revision = self._session_file_revision(existing_info)
                    current_revision = self._entry_session_revision(entry)
                    if existing_revision is None or current_revision is None or current_revision >= existing_revision:
                        filtered_entries.append(entry)
                continue

            existing_ts = normalize_timestamp(existing_info["timestamp"]).replace(microsecond=0)
            entry_ts = normalize_timestamp(entry.timestamp).replace(microsecond=0)

            if entry_ts > existing_ts:
                filtered_entries.append(entry)

        return filtered_entries

    def _session_content_changed(self, entry: AgentEvent, existing_info: Dict[str, Any]) -> bool:
        """Compare complete exported content for sources whose sessions can resume."""
        existing_path = existing_info["file_path"]
        try:
            existing_data = existing_info.get("data")
            if existing_data is None:
                with open(existing_path, encoding="utf-8") as handle:
                    existing_data = json.load(handle)
            if not isinstance(existing_data, dict):
                raise ValueError("existing session file must contain a JSON object")
            current_content = self._session_export_content(entry.get_non_null_fields())
            existing_content = self._session_export_content(existing_data)
            if entry.source == "codex" and "session_context" not in existing_content:
                current_context = current_content.get("session_context")
                if isinstance(current_context, dict) and set(current_context) == {"last_event_at"}:
                    current_content.pop("session_context")
            return current_content != existing_content
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            print(f"Error comparing existing session {existing_path.name}: {exc}")
            self._emit_error(
                {
                    "source": entry.source,
                    "stage": "compare_session",
                    "error_type": exc.__class__.__name__,
                    "message": str(exc),
                    "session_id": entry.session_id,
                }
            )
            return True

    @staticmethod
    def _session_export_content(event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Ignore fields that change only because a snapshot is rewritten."""
        return {key: value for key, value in event_data.items() if key not in {"timestamp", "uuid"}}

    def _find_session_file(
        self,
        entry: AgentEvent,
        session_file_index: Dict[str, List[Dict[str, Any]]],
    ) -> Optional[Dict[str, Any]]:
        """Find the latest snapshot whose stored session ID matches exactly."""
        latest: Optional[Dict[str, Any]] = None
        for candidate_info in self._session_file_candidates(entry, session_file_index):
            candidate = candidate_info["file_path"]
            if not candidate.exists():
                continue
            data = candidate_info.get("data") or self._load_session_file(candidate)
            if data is None or data.get("session_id") != entry.session_id:
                continue
            candidate_info = dict(candidate_info)
            candidate_info["data"] = data
            candidate_info["revision"] = self._session_file_revision(candidate_info)
            latest = self._newer_session_file(latest, candidate_info)
        return latest

    def _session_file_info(self, file_path: Path) -> Optional[Dict[str, Any]]:
        if not file_path.exists():
            return None
        file_timestamp = parse_timestamp_from_filename(file_path.name)
        data = self._load_session_file(file_path)
        if file_timestamp is None or data is None:
            return None
        info = {
            "file_path": file_path,
            "timestamp": file_timestamp,
            "filename": file_path.name,
            "data": data,
        }
        info["revision"] = self._session_file_revision(info)
        return info

    @staticmethod
    def _newer_session_file(
        current: Optional[Dict[str, Any]],
        candidate: Dict[str, Any],
    ) -> Dict[str, Any]:
        if current is None:
            return candidate
        candidate_revision = candidate.get("revision")
        current_revision = current.get("revision")
        candidate_event_count = AgentObserver._session_file_event_count(candidate)
        current_event_count = AgentObserver._session_file_event_count(current)
        if (
            candidate_revision is not None
            and (current_revision is None or candidate_revision > current_revision)
        ) or (
            candidate_revision == current_revision
            and (
                candidate_event_count is not None
                and (current_event_count is None or candidate_event_count > current_event_count)
            )
        ) or (
            candidate_revision == current_revision
            and candidate_event_count == current_event_count
            and candidate["timestamp"] > current["timestamp"]
        ):
            return candidate
        return current

    @staticmethod
    def _create_session_temp(output_dir: Path, filename: str, target_path: Path) -> Tuple[Path, int]:
        """Create a same-directory temporary file with compatible permissions."""
        for _ in range(10):
            temp_path = output_dir / f".{filename}.{secrets.token_hex(8)}.tmp"
            try:
                fd = os.open(temp_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o666)
            except FileExistsError:
                continue

            try:
                if target_path.exists():
                    os.chmod(temp_path, stat.S_IMODE(target_path.stat().st_mode))
            except OSError:
                os.close(fd)
                temp_path.unlink(missing_ok=True)
                raise
            return temp_path, fd
        raise FileExistsError(f"unable to allocate temporary file for {filename}")

    def _build_session_file_index(self, output_dir: Path) -> Dict[str, List[Dict[str, Any]]]:
        """Index filenames once so batch incremental processing stays linear."""
        index: Dict[str, List[Dict[str, Any]]] = {}
        if not output_dir.exists():
            return index

        for file_path in output_dir.glob("adr.*.json"):
            file_timestamp = parse_timestamp_from_filename(file_path.name)
            if file_timestamp is None:
                continue
            filename_session_id = file_path.name[4:-5].rsplit(".", 1)[0]
            info = {
                "file_path": file_path,
                "timestamp": file_timestamp,
                "filename": file_path.name,
            }
            index.setdefault(filename_session_id, []).append(info)
            match = _COLLISION_SUFFIX_PATTERN.search(filename_session_id)
            if match:
                index.setdefault(f"#sha256:{match.group(1)}", []).append(info)
        return index

    def _session_file_candidates(
        self,
        entry: AgentEvent,
        session_file_index: Dict[str, List[Dict[str, Any]]],
    ) -> List[Dict[str, Any]]:
        filename_session_id = self._session_filename_id(entry.session_id)
        legacy_session_id = self._clean_filename(entry.session_id)
        digest = hashlib.sha256(entry.session_id.encode("utf-8")).hexdigest()
        candidates: List[Dict[str, Any]] = []
        seen_paths = set()
        for key in (filename_session_id, legacy_session_id, f"#sha256:{digest}"):
            for info in session_file_index.get(key, []):
                path = info["file_path"]
                if path in seen_paths:
                    continue
                candidate_session_id = path.name[4:-5].rsplit(".", 1)[0]
                if self._filename_id_matches_session(candidate_session_id, entry.session_id):
                    candidates.append(info)
                    seen_paths.add(path)
        return candidates

    def _index_session_file(
        self,
        session_file_index: Dict[str, List[Dict[str, Any]]],
        file_path: Path,
        data: Dict[str, Any],
    ) -> None:
        filename_session_id = file_path.name[4:-5].rsplit(".", 1)[0]
        keys = [filename_session_id]
        match = _COLLISION_SUFFIX_PATTERN.search(filename_session_id)
        if match:
            keys.append(f"#sha256:{match.group(1)}")
        for key in keys:
            session_file_index[key] = [
                info for info in session_file_index.get(key, []) if info["file_path"] != file_path
            ]

        info = {
            "file_path": file_path,
            "timestamp": parse_timestamp_from_filename(file_path.name),
            "filename": file_path.name,
            "data": data,
        }
        session_file_index.setdefault(filename_session_id, []).append(info)
        if match:
            session_file_index.setdefault(f"#sha256:{match.group(1)}", []).append(info)

    def _resolve_session_file_path(
        self,
        output_dir: Path,
        entry: AgentEvent,
        filename_session_id: str,
        timestamp_str: str,
        existing_info: Optional[Dict[str, Any]],
    ) -> Path:
        """Resolve a stable path without overwriting a colliding session ID."""
        preferred = output_dir / f"adr.{filename_session_id}.{timestamp_str}.json"
        if existing_info is not None and format_timestamp_for_filename(existing_info["timestamp"]) == timestamp_str:
            existing_session_part = existing_info["file_path"].name[4:-5].rsplit(".", 1)[0]
            if (
                existing_session_part == filename_session_id
                or existing_session_part.startswith(f"{filename_session_id}_")
            ):
                return existing_info["file_path"]

        if not preferred.exists():
            return preferred
        if self._session_file_has_id(preferred, entry.session_id):
            return preferred

        digest = hashlib.sha256(entry.session_id.encode("utf-8")).hexdigest()
        counter = 0
        while True:
            suffix = digest if counter == 0 else f"{digest}_{counter}"
            prefix = filename_session_id[: 200 - len(suffix) - 1]
            alternate_id = f"{prefix}_{suffix}".strip("_")
            alternate = output_dir / f"adr.{alternate_id}.{timestamp_str}.json"
            if not alternate.exists() or self._session_file_has_id(alternate, entry.session_id):
                return alternate
            counter += 1

    def _session_revision_regresses(
        self, entry: AgentEvent, existing_info: Optional[Dict[str, Any]]
    ) -> bool:
        """Prevent an older concurrent parse from replacing a newer snapshot."""
        if existing_info is None:
            return False
        existing_revision = self._session_file_revision(existing_info)
        current_revision = self._entry_session_revision(entry)
        existing_event_count = self._session_file_event_count(existing_info)
        current_event_count = self._entry_session_event_count(entry)
        return (
            existing_revision is not None
            and current_revision is not None
            and (
                current_revision < existing_revision
                or (
                    current_revision == existing_revision
                    and existing_event_count is not None
                    and current_event_count is not None
                    and current_event_count < existing_event_count
                )
            )
        )

    @staticmethod
    def _entry_session_revision(entry: AgentEvent) -> Optional[datetime]:
        context = entry.session_context or {}
        last_event_at = context.get("last_event_at") if isinstance(context, dict) else None
        if last_event_at is None:
            return None
        try:
            return normalize_timestamp(last_event_at)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _entry_session_event_count(entry: AgentEvent) -> Optional[int]:
        context = entry.session_context or {}
        event_count = context.get("event_count") if isinstance(context, dict) else None
        return event_count if isinstance(event_count, int) and event_count >= 0 else None

    @staticmethod
    def _session_file_event_count(existing_info: Dict[str, Any]) -> Optional[int]:
        data = existing_info.get("data")
        if data is None:
            data = AgentObserver._load_session_file(existing_info["file_path"])
        context = data.get("session_context") if isinstance(data, dict) else None
        event_count = context.get("event_count") if isinstance(context, dict) else None
        return event_count if isinstance(event_count, int) and event_count >= 0 else None

    @staticmethod
    def _session_file_revision(existing_info: Dict[str, Any]) -> Optional[datetime]:
        if "revision" in existing_info:
            revision = existing_info["revision"]
            return revision if isinstance(revision, datetime) else None
        try:
            data = existing_info.get("data")
            if data is None:
                with open(existing_info["file_path"], encoding="utf-8") as handle:
                    data = json.load(handle)
            if not isinstance(data, dict):
                return None
            context = data.get("session_context")
            last_event_at = context.get("last_event_at") if isinstance(context, dict) else None
            return normalize_timestamp(last_event_at or data.get("timestamp") or existing_info["timestamp"])
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
            return None

    @staticmethod
    def _acquire_session_lock(lock_path: Path, timeout_seconds: float = 30.0) -> int:
        """Acquire an OS-managed cross-process lock for one session."""
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            if os.fstat(fd).st_size == 0:
                os.write(fd, b"0")
        except Exception:
            os.close(fd)
            raise

        deadline = time.monotonic() + timeout_seconds
        while True:
            try:
                os.lseek(fd, 0, os.SEEK_SET)
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return fd
            except OSError as exc:
                if exc.errno not in {errno.EACCES, errno.EAGAIN}:
                    os.close(fd)
                    raise
                if time.monotonic() >= deadline:
                    os.close(fd)
                    raise TimeoutError(f"timed out waiting for session lock {lock_path.name}")
                time.sleep(0.05)

    @staticmethod
    def _release_session_lock(lock_fd: int) -> None:
        try:
            os.lseek(lock_fd, 0, os.SEEK_SET)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(lock_fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)

    @staticmethod
    def _sync_session_directory(output_dir: Path) -> None:
        """Persist directory entries after replacing or removing snapshots."""
        if os.name == "nt":
            return
        directory_fd = os.open(output_dir, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    def _remove_stale_session_files(
        self,
        session_id: str,
        keep_path: Path,
        candidates: List[Dict[str, Any]],
    ) -> bool:
        """Remove superseded moving-timestamp snapshots after the replacement succeeds."""
        removed_files = False
        for info in candidates:
            candidate = info["file_path"]
            if candidate == keep_path or not candidate.exists():
                continue
            # Reload immediately before removal: indexed data can be stale after a writer updates a path.
            data = self._load_session_file(candidate)
            if data is None or data.get("session_id") != session_id:
                continue
            try:
                candidate.unlink()
                removed_files = True
            except OSError as exc:
                print(f"Error removing stale session {candidate.name}: {exc}")
                self._emit_error(
                    {
                        "stage": "remove_stale_session",
                        "error_type": exc.__class__.__name__,
                        "message": str(exc),
                        "session_id": session_id,
                    }
                )
        return removed_files

    @staticmethod
    def _session_file_has_id(file_path: Path, session_id: str) -> bool:
        """Verify ownership before migrating or deleting a legacy filename."""
        data = AgentObserver._load_session_file(file_path)
        return data is not None and data.get("session_id") == session_id

    @staticmethod
    def _load_session_file(file_path: Path) -> Optional[Dict[str, Any]]:
        try:
            with open(file_path, encoding="utf-8") as handle:
                data = json.load(handle)
            return data if isinstance(data, dict) else None
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError):
            return None

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

    def _session_filename_id(self, session_id: str) -> str:
        """Preserve existing safe names while disambiguating lossy sanitization."""
        clean_id = self._clean_filename(session_id)
        if clean_id == session_id:
            return clean_id

        digest = hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:12]
        clean_id = clean_id[: 200 - len(digest) - 1]
        return f"{clean_id}_{digest}".strip("_")

    def _filename_id_matches_session(self, filename_session_id: str, session_id: str) -> bool:
        current_id = self._session_filename_id(session_id)
        if filename_session_id in {current_id, self._clean_filename(session_id)}:
            return True

        match = _COLLISION_SUFFIX_PATTERN.search(filename_session_id)
        if not match:
            return False
        digest = hashlib.sha256(session_id.encode("utf-8")).hexdigest()
        if match.group(1) != digest:
            return False

        counter = int(match.group(2)) if match.group(2) is not None else 0
        suffix = digest if counter == 0 else f"{digest}_{counter}"
        prefix = current_id[: 200 - len(suffix) - 1]
        return filename_session_id == f"{prefix}_{suffix}".strip("_")
