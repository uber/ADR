"""
Parser for opencode (https://github.com/sst/opencode) session logs.

opencode persists sessions under its XDG data directory. Notably, opencode uses
the XDG base-directory layout on *all* platforms (including macOS), so the data
directory is ``~/.local/share/opencode`` on both Linux and macOS unless
``$XDG_DATA_HOME`` overrides it. An extra macOS fallback is probed defensively.

Two on-disk storage backends are supported:

1. SQLite (current versions, e.g. 1.x): an ``opencode*.db`` file (normally
   ``opencode.db``, but non-stable release channels write
   ``opencode-<channel>.db`` instead) with ``session`` / ``message`` / ``part``
   tables. The ``message`` and ``part`` rows keep their payloads as JSON blobs
   in a ``data`` column, matching the ``SessionV1.Info`` / ``SessionV1.Part``
   wire schema. These two tables are the actively-maintained, complete
   conversation record for local CLI usage; the newer ``session_message`` /
   ``event`` tables are an additional event-sourced projection used for other
   purposes and were empty in every real session captured while building this
   parser, so they are not read here.

2. JSON file tree (older, pre-SQLite versions): a ``storage/`` directory holding
   one JSON file per session / message / part. Both the newer project-scoped
   layout and the older ``session/info`` layout (including messages with
   embedded parts) are handled.

In every backend the conceptual model is the same:

    session -> messages (role=user|assistant) -> parts (text|reasoning|tool|...)

which is normalized into ``AgentEvent`` / ``ChatMessage`` / ``ToolUsage``.
"""

import json
import os
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..schemas.agent_event_schema import AgentEvent, ChatMessage, ToolUsage
from ..utils.string_utils import truncate_middle
from ..utils.timestamp_utils import normalize_timestamp
from .base_parser import BaseParser

MAX_LOG_AGE_DAYS = 14

# opencode's built-in tool IDs. Some tools keep a legacy wire ID for backwards
# compatibility (the shell tool registers as "bash", web search as "web_search",
# the patch tool as "apply_patch"). "lsp"/"plan_exit"/"execute" are experimental,
# flag-gated tools included for completeness.
#
# Any tool name that is NOT one of these but contains an underscore is treated as
# an MCP tool named "<serverName>_<toolName>", which is how opencode's MCP catalog
# namespaces tools it discovers from configured servers.
BUILTIN_TOOLS = frozenset(
    {
        "invalid",
        "question",
        "bash",
        "read",
        "glob",
        "grep",
        "edit",
        "write",
        "task",
        "webfetch",
        "todowrite",
        "web_search",
        "skill",
        "apply_patch",
        "lsp",
        "plan_exit",
        "execute",
    }
)


class OpencodeParser(BaseParser):
    """Parser for opencode session logs (SQLite and legacy JSON backends)."""

    def __init__(self, max_age_days: int = MAX_LOG_AGE_DAYS):
        self.max_age_days = max_age_days
        self.base_dir, self.backend, self.db_path = self._detect_backend()

    @staticmethod
    def _candidate_base_dirs() -> List[Path]:
        """Candidate opencode data directories, in priority order.

        Each may contain either an ``opencode.db`` (SQLite backend) or a
        ``storage/`` tree (JSON backend). ``$XDG_DATA_HOME`` is honored first.
        """
        candidates: List[Path] = []
        xdg_data_home = os.environ.get("XDG_DATA_HOME")
        if xdg_data_home:
            candidates.append(Path(xdg_data_home) / "opencode")
        # Linux and macOS both default to ~/.local/share via xdg-basedir.
        candidates.append(Path.home() / ".local/share/opencode")
        # Defensive macOS fallback in case a build uses the native app dir.
        candidates.append(Path.home() / "Library/Application Support/opencode")

        seen = set()
        unique: List[Path] = []
        for candidate in candidates:
            if candidate not in seen:
                seen.add(candidate)
                unique.append(candidate)
        return unique

    @staticmethod
    def _find_db_file(base: Path) -> Optional[Path]:
        """Locate the opencode SQLite database under a candidate data directory.

        The ``OPENCODE_DB`` environment variable can override the filename (or be
        an absolute path / ``:memory:``); otherwise the file is ``opencode.db``
        for stable channels or ``opencode-<channel>.db`` for anything else (e.g.
        a nightly build), so we fall back to globbing for that pattern too.
        """
        env_db = os.environ.get("OPENCODE_DB")
        if env_db and env_db != ":memory:":
            candidate = Path(env_db)
            if not candidate.is_absolute():
                candidate = base / env_db
            if candidate.exists():
                return candidate

        default = base / "opencode.db"
        if default.exists():
            return default

        if base.exists():
            for candidate in sorted(base.glob("opencode-*.db")):
                if candidate.exists():
                    return candidate
        return None

    def _detect_backend(self) -> Tuple[Path, Optional[str], Optional[Path]]:
        """Return (base_dir, backend, db_path) where backend is 'sqlite', 'json' or None."""
        for base in self._candidate_base_dirs():
            db_path = self._find_db_file(base)
            if db_path is not None:
                return base, "sqlite", db_path
            storage_dir = base / "storage"
            if storage_dir.exists():
                return base, "json", None

        # Nothing found: report the primary candidate for logging purposes.
        candidates = self._candidate_base_dirs()
        return candidates[0], None, None

    def parse_all(self) -> List[AgentEvent]:
        """Parse all available opencode sessions."""
        if self.backend == "sqlite":
            print(f"[OPENCODE] Reading SQLite logs from {self.db_path}")
            return self._parse_sqlite(self.db_path)

        if self.backend == "json":
            storage_dir = self.base_dir / "storage"
            print(f"[OPENCODE] Reading JSON logs from {storage_dir}")
            return self._parse_json_storage(storage_dir)

        print(f"[OPENCODE] No logs found at {self.base_dir}")
        return []

    # ------------------------------------------------------------------ #
    # SQLite backend
    # ------------------------------------------------------------------ #

    def _parse_sqlite(self, db_path: Path) -> List[AgentEvent]:
        entries: List[AgentEvent] = []
        conn = None
        try:
            # Open read-only so we never disturb a live opencode process.
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row

            sessions = self._get_sqlite_sessions(conn)
            print(f"[OPENCODE] Found {len(sessions)} sessions")

            for session in sessions:
                session_id = session["id"]
                try:
                    messages = self._get_sqlite_messages(conn, session_id)
                    entry = self._session_to_event(
                        session_meta=dict(session),
                        messages=messages,
                        raw_log_path=str(db_path),
                    )
                    if entry and entry.has_meaningful_content():
                        entries.append(entry)
                except Exception as e:
                    print(f"[OPENCODE] Error processing session {session_id}: {e}")
        except Exception as e:
            print(f"[OPENCODE] Error reading database: {e}")
        finally:
            if conn is not None:
                conn.close()

        return entries

    def _get_sqlite_sessions(self, conn: sqlite3.Connection) -> List[sqlite3.Row]:
        """Fetch session rows, filtered by age via time_updated (epoch ms)."""
        cursor = conn.cursor()
        if self.max_age_days > 0:
            cutoff_ms = int((time.time() - (self.max_age_days * 86400)) * 1000)
            cursor.execute(
                "SELECT * FROM session WHERE time_updated >= ? ORDER BY time_updated DESC",
                (cutoff_ms,),
            )
        else:
            cursor.execute("SELECT * FROM session ORDER BY time_updated DESC")
        return cursor.fetchall()

    def _get_sqlite_messages(
        self, conn: sqlite3.Connection, session_id: str
    ) -> List[Tuple[Dict[str, Any], List[Dict[str, Any]]]]:
        """Return ordered [(message_data, [part_data, ...]), ...] for a session."""
        cursor = conn.cursor()

        # Group parts by message_id, preserving chronological order within a message.
        cursor.execute(
            "SELECT id, message_id, data FROM part WHERE session_id = ? ORDER BY time_created ASC, id ASC",
            (session_id,),
        )
        parts_by_message: Dict[str, List[Dict[str, Any]]] = {}
        for row in cursor.fetchall():
            part_data = self._safe_json(row["data"])
            if part_data is None:
                continue
            parts_by_message.setdefault(row["message_id"], []).append(part_data)

        cursor.execute(
            "SELECT id, data FROM message WHERE session_id = ? ORDER BY time_created ASC, id ASC",
            (session_id,),
        )
        messages: List[Tuple[Dict[str, Any], List[Dict[str, Any]]]] = []
        for row in cursor.fetchall():
            message_data = self._safe_json(row["data"])
            if message_data is None:
                continue
            message_data.setdefault("id", row["id"])
            messages.append((message_data, parts_by_message.get(row["id"], [])))
        return messages

    # ------------------------------------------------------------------ #
    # JSON backend (legacy on-disk file tree)
    # ------------------------------------------------------------------ #

    def _parse_json_storage(self, storage_dir: Path) -> List[AgentEvent]:
        entries: List[AgentEvent] = []

        project_scoped = (storage_dir / "message").exists()  # newer layout

        session_files = self._discover_session_files(storage_dir)
        print(f"[OPENCODE] Found {len(session_files)} sessions")

        cutoff_ts = time.time() - (self.max_age_days * 86400) if self.max_age_days > 0 else None

        for session_file in session_files:
            try:
                if cutoff_ts is not None and session_file.stat().st_mtime < cutoff_ts:
                    continue
                session_meta = self._safe_json_file(session_file)
                if not session_meta or not session_meta.get("id"):
                    continue

                messages = self._load_json_messages(storage_dir, session_meta["id"], project_scoped)
                entry = self._session_to_event(
                    session_meta=session_meta,
                    messages=messages,
                    raw_log_path=str(session_file),
                )
                if entry and entry.has_meaningful_content():
                    entries.append(entry)
            except Exception as e:
                print(f"[OPENCODE] Error processing session file {session_file}: {e}")

        return entries

    @staticmethod
    def _discover_session_files(storage_dir: Path) -> List[Path]:
        """Locate session-info JSON files across storage layouts."""
        session_root = storage_dir / "session"
        info_dir = session_root / "info"
        files: List[Path] = []

        if info_dir.exists():
            # Legacy layout: storage/session/info/<sessionID>.json
            files.extend(sorted(info_dir.glob("*.json")))
        elif session_root.exists():
            # Project-scoped layout: storage/session/<projectID>/<sessionID>.json.
            # Skip reserved subdirectories that hold messages/parts.
            reserved = {"message", "part", "info"}
            for project_dir in sorted(session_root.iterdir()):
                if project_dir.is_dir() and project_dir.name not in reserved:
                    files.extend(sorted(project_dir.glob("*.json")))
        return files

    def _load_json_messages(
        self, storage_dir: Path, session_id: str, project_scoped: bool
    ) -> List[Tuple[Dict[str, Any], List[Dict[str, Any]]]]:
        """Return ordered [(message_data, [part_data, ...]), ...] for a session."""
        if project_scoped:
            msg_dir = storage_dir / "message" / session_id
            part_root = storage_dir / "part"
        else:
            msg_dir = storage_dir / "session" / "message" / session_id
            part_root = storage_dir / "session" / "part" / session_id

        def parts_for(message_id: str) -> List[Dict[str, Any]]:
            part_dir = part_root / message_id
            if not part_dir.exists():
                return []
            return [p for p in (self._safe_json_file(f) for f in sorted(part_dir.glob("*.json"))) if p]

        messages: List[Tuple[Dict[str, Any], List[Dict[str, Any]]]] = []
        if not msg_dir.exists():
            return messages

        for msg_file in sorted(msg_dir.glob("*.json")):
            message_data = self._safe_json_file(msg_file)
            if not message_data:
                continue
            message_data.setdefault("id", msg_file.stem)
            # The oldest layout embeds parts directly on the message.
            embedded = message_data.get("parts")
            if isinstance(embedded, list) and embedded:
                parts = embedded
            else:
                parts = parts_for(message_data["id"])
            messages.append((message_data, parts))
        return messages

    # ------------------------------------------------------------------ #
    # Shared normalization
    # ------------------------------------------------------------------ #

    def _session_to_event(
        self,
        session_meta: Dict[str, Any],
        messages: List[Tuple[Dict[str, Any], List[Dict[str, Any]]]],
        raw_log_path: str,
    ) -> Optional[AgentEvent]:
        session_id = session_meta.get("id")
        if not session_id:
            return None

        chat_history: List[ChatMessage] = []
        provider_id: Optional[str] = None
        model_id: Optional[str] = None

        for message_data, parts in messages:
            role = message_data.get("role") or "assistant"

            # Track provider/model from assistant messages for event metadata.
            if role == "assistant":
                provider_id = provider_id or message_data.get("providerID")
                model_id = model_id or message_data.get("modelID")

            content, tools = self._build_content_and_tools(parts)
            if not content and not tools:
                continue

            chat_history.append(
                ChatMessage(
                    role=role,
                    content=content or "[Assistant used tools]",
                    tools=tools,
                    sequence_id=message_data.get("id"),
                )
            )

        if not chat_history:
            return None

        return AgentEvent(
            timestamp=self._session_timestamp(session_meta),
            source="opencode",
            session_id=f"opencode_{self._strip_session_id_prefix(session_id)}",
            project_path=session_meta.get("directory") or session_meta.get("path") or None,
            model=self._resolve_model(session_meta, model_id),
            user_id=self._build_user_id(session_meta, provider_id),
            chat_history=chat_history,
            raw_log_path=raw_log_path,
        )

    def _build_content_and_tools(self, parts: List[Dict[str, Any]]) -> Tuple[str, List[ToolUsage]]:
        """Collapse a message's parts into a text blob and a list of tool usages."""
        text_segments: List[str] = []
        tools: List[ToolUsage] = []

        for part in parts:
            if not isinstance(part, dict):
                continue
            part_type = part.get("type")

            if part_type == "text":
                text = part.get("text")
                if text:
                    text_segments.append(text)
            elif part_type == "reasoning":
                text = part.get("text")
                if text:
                    text_segments.append("[Reasoning]\n" + text)
            elif part_type == "subtask":
                # A user message that triggers a sub-agent (e.g. a slash command
                # bound to an agent). Carries the actual prompt handed to that
                # agent, so it is real conversational content, not structural.
                prompt = part.get("prompt") or part.get("description")
                if prompt:
                    agent_name = part.get("agent")
                    label = f"[Subtask: {agent_name}]" if agent_name else "[Subtask]"
                    text_segments.append(f"{label}\n{prompt}")
            elif part_type == "file":
                # File attachment/reference (image, local file, MCP resource, ...).
                label = part.get("filename") or part.get("url")
                if label:
                    text_segments.append(f"[Attached file: {label}]")
            elif part_type in ("tool", "tool-invocation"):
                tool = self._build_tool_usage(part)
                if tool:
                    tools.append(tool)
            # Structural/non-conversational parts are ignored: step-start,
            # step-finish, snapshot, patch, agent (inline @mention), retry and
            # compaction, plus the legacy-only source-url part.

        return "\n\n".join(text_segments).strip(), tools

    def _build_tool_usage(self, part: Dict[str, Any]) -> Optional[ToolUsage]:
        """Build a ToolUsage from a 'tool' (current) or 'tool-invocation' (legacy) part."""
        if part.get("type") == "tool-invocation":
            # Legacy embedded shape: {"type": "tool-invocation", "toolInvocation": {...}}
            invocation = part.get("toolInvocation") or {}
            tool_name = invocation.get("toolName")
            arguments = invocation.get("args")
            output = invocation.get("result")
            status = "success" if invocation.get("state") == "result" else invocation.get("state")
            error = None
        else:
            # Current shape: {"type": "tool", "tool": name, "callID": .., "state": {...}}
            tool_name = part.get("tool")
            state = part.get("state") or {}
            arguments = state.get("input")
            output = state.get("output")
            raw_status = state.get("status")
            status = "success" if raw_status == "completed" else raw_status
            error = state.get("error")

        if not tool_name:
            return None

        if not isinstance(arguments, dict):
            arguments = {} if arguments is None else {"value": arguments}
        arguments = self._truncate_large_arguments(arguments)

        result = None
        if error:
            result = truncate_middle(str(error), max_length=1000, edge_chars=400)
        elif output is not None:
            result = truncate_middle(str(output), max_length=1000, edge_chars=400)

        tool_type, server_name = self._classify_tool(tool_name)

        return ToolUsage(
            tool_name=tool_name,
            tool_type=tool_type,
            server_name=server_name,
            arguments=arguments,
            result=result,
            status=status,
            error=truncate_middle(str(error), max_length=1000, edge_chars=400) if error else None,
        )

    @staticmethod
    def _classify_tool(tool_name: str) -> Tuple[str, Optional[str]]:
        """Classify a tool as built-in or MCP.

        opencode registers MCP tools as ``<serverName>_<toolName>``. Any tool that
        is not a known built-in and contains an underscore is treated as MCP, using
        the segment before the first underscore as the server name.
        """
        if tool_name in BUILTIN_TOOLS:
            return "function_call", None
        if "_" in tool_name:
            server_name = tool_name.split("_", 1)[0]
            if server_name:
                return "mcp_tool", server_name
        return "function_call", None

    @staticmethod
    def _truncate_large_arguments(arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Truncate large string values in tool arguments to reduce payload size."""
        if not isinstance(arguments, dict):
            return arguments

        truncated: Dict[str, Any] = {}
        for key, value in arguments.items():
            if isinstance(value, str) and len(value) > 1000:
                truncated[key] = truncate_middle(value, max_length=1000, edge_chars=400)
            else:
                truncated[key] = value
        return truncated

    def _resolve_model(self, session_meta: Dict[str, Any], fallback_model_id: Optional[str]) -> Optional[str]:
        """Extract a model name from session metadata, falling back to messages."""
        model = session_meta.get("model")
        if isinstance(model, str) and model:
            # SQLite stores this as a JSON string, e.g. {"id":"...","providerID":"..."}.
            parsed = self._safe_json(model)
            if isinstance(parsed, dict):
                return parsed.get("id") or parsed.get("modelID") or fallback_model_id
            return model
        if isinstance(model, dict):
            return model.get("id") or model.get("modelID") or fallback_model_id
        return fallback_model_id

    @staticmethod
    def _build_user_id(session_meta: Dict[str, Any], provider_id: Optional[str]) -> Optional[str]:
        """Compose a user_id from provider and opencode version, like other parsers."""
        version = session_meta.get("version")
        parts = [p for p in [provider_id, f"opencode/{version}" if version else None] if p]
        return " ".join(parts) if parts else None

    @staticmethod
    def _strip_session_id_prefix(session_id: str) -> str:
        """Strip opencode's own "ses_" ID prefix.

        opencode session IDs always start with "ses_" (mirroring the "msg_"/"prt_"
        prefixes used for messages and parts). Once our own "opencode_" source
        prefix is prepended, the "ses_" segment is pure noise.
        """
        return session_id[len("ses_") :] if session_id.startswith("ses_") else session_id

    @staticmethod
    def _session_timestamp(session_meta: Dict[str, Any]) -> datetime:
        """Best-effort session timestamp (uses last-updated when available)."""
        # SQLite exposes flat epoch-ms columns; JSON nests them under "time".
        ts = session_meta.get("time_updated") or session_meta.get("time_created")
        if ts is None:
            time_obj = session_meta.get("time")
            if isinstance(time_obj, dict):
                ts = time_obj.get("updated") or time_obj.get("created")
        if ts is None:
            return datetime.now(timezone.utc)
        try:
            return normalize_timestamp(ts)
        except (ValueError, TypeError):
            return datetime.now(timezone.utc)

    @staticmethod
    def _safe_json(text: Optional[str]) -> Optional[Any]:
        if not text:
            return None
        try:
            return json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return None

    @staticmethod
    def _safe_json_file(path: Path) -> Optional[Dict[str, Any]]:
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else None
        except (OSError, json.JSONDecodeError):
            return None
