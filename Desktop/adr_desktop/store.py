"""Single-device SQLite store. Session payloads are retained, not redacted or clipped."""

import hashlib
import json
import re
import sqlite3
import threading
import uuid
import zlib
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import (
    CAPTURE_INTERVAL_SECONDS,
    DEFAULT_SETTINGS,
    MAX_JSON_BYTES,
    MAX_STATE_BYTES,
    canonical,
    utcnow,
)
from .conversation_view import context_label, is_setup_message, recover_codex_metadata, session_title
from .credential_activity import session_run_ids
from .policy import project_path

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS snapshots(
    digest TEXT PRIMARY KEY, session_id TEXT NOT NULL, received_at TEXT NOT NULL, payload BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS snapshot_session ON snapshots(session_id,received_at DESC);
CREATE TABLE IF NOT EXISTS sessions(
    id TEXT PRIMARY KEY, source TEXT NOT NULL, source_session_id TEXT NOT NULL,
    project TEXT NOT NULL, model TEXT NOT NULL, title TEXT NOT NULL,
    occurred_at TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
    message_count INTEGER NOT NULL, tool_count INTEGER NOT NULL,
    token_usage TEXT, digest TEXT NOT NULL, partial INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS session_recent ON sessions(occurred_at DESC,id);
CREATE INDEX IF NOT EXISTS session_project ON sessions(project,occurred_at DESC);
CREATE TABLE IF NOT EXISTS session_tools(
    session_id TEXT NOT NULL, name TEXT NOT NULL, count INTEGER NOT NULL,
    PRIMARY KEY(session_id,name)
);
CREATE TABLE IF NOT EXISTS rules(
    id TEXT PRIMARY KEY, path TEXT NOT NULL, action TEXT NOT NULL,
    kind TEXT NOT NULL, label TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit(
    id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, kind TEXT NOT NULL,
    summary TEXT NOT NULL, details TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hook_events(
    id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, harness TEXT NOT NULL,
    session_id TEXT NOT NULL, tool TEXT NOT NULL, decision TEXT NOT NULL,
    reason TEXT NOT NULL, paths TEXT NOT NULL, rule_id TEXT
);
CREATE INDEX IF NOT EXISTS hook_recent ON hook_events(timestamp DESC);
CREATE TABLE IF NOT EXISTS credentials(
    id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, origin TEXT NOT NULL,
    auth_type TEXT NOT NULL, header_name TEXT NOT NULL, username TEXT NOT NULL,
    allowed_paths TEXT NOT NULL, state TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS grants(
    id TEXT PRIMARY KEY, name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
    project TEXT NOT NULL, credentials TEXT NOT NULL, created_at TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS broker_requests(
    id TEXT PRIMARY KEY, grant_id TEXT NOT NULL, credential_id TEXT NOT NULL,
    credential_name TEXT NOT NULL, origin TEXT NOT NULL, path TEXT NOT NULL,
    state TEXT NOT NULL, created_at TEXT NOT NULL, expires_at REAL NOT NULL,
    result TEXT, error TEXT
);
CREATE INDEX IF NOT EXISTS broker_pending ON broker_requests(state,created_at);
CREATE TABLE IF NOT EXISTS history_documents(
    id INTEGER PRIMARY KEY, session_id TEXT NOT NULL UNIQUE REFERENCES sessions(id) ON DELETE CASCADE,
    digest TEXT NOT NULL, body TEXT NOT NULL
);
CREATE VIRTUAL TABLE IF NOT EXISTS history_search USING fts5(
    body, content='history_documents', content_rowid='id', tokenize='unicode61'
);
CREATE TRIGGER IF NOT EXISTS history_search_insert AFTER INSERT ON history_documents BEGIN
    INSERT INTO history_search(rowid,body) VALUES (new.id,new.body);
END;
CREATE TRIGGER IF NOT EXISTS history_search_delete AFTER DELETE ON history_documents BEGIN
    INSERT INTO history_search(history_search,rowid,body) VALUES ('delete',old.id,old.body);
END;
CREATE TRIGGER IF NOT EXISTS history_search_update AFTER UPDATE ON history_documents BEGIN
    INSERT INTO history_search(history_search,rowid,body) VALUES ('delete',old.id,old.body);
    INSERT INTO history_search(rowid,body) VALUES (new.id,new.body);
END;
CREATE TABLE IF NOT EXISTS session_metadata(
    session_id TEXT PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
    parent_id TEXT NOT NULL, forked_from_id TEXT NOT NULL, agent_label TEXT NOT NULL,
    native_title TEXT NOT NULL, kind TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS session_parent ON session_metadata(parent_id);
CREATE TABLE IF NOT EXISTS environment_credentials(
    id TEXT PRIMARY KEY, name TEXT NOT NULL, env_name TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS environment_runs(
    id TEXT PRIMARY KEY, grant_id TEXT NOT NULL, state TEXT NOT NULL,
    created_at TEXT NOT NULL, exit_code INTEGER
);
CREATE TABLE IF NOT EXISTS environment_run_context(
    run_id TEXT PRIMARY KEY REFERENCES environment_runs(id) ON DELETE CASCADE,
    harness TEXT NOT NULL, session_id TEXT NOT NULL, ambiguous INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS credential_session_receipts(
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    run_id TEXT NOT NULL, PRIMARY KEY(session_id,run_id)
);
CREATE INDEX IF NOT EXISTS credential_receipt_run ON credential_session_receipts(run_id);
CREATE TABLE IF NOT EXISTS artifact_scan(
    id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS artifact_blocks(
    id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, harness TEXT NOT NULL,
    session_id TEXT NOT NULL, tool TEXT NOT NULL, indicator_id TEXT NOT NULL, source_id TEXT NOT NULL,
    kind TEXT NOT NULL, generation TEXT NOT NULL, target_display TEXT NOT NULL, source TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS prompt_blocks(
    id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
    harness TEXT NOT NULL, kinds TEXT NOT NULL, aliases TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS session_retrieval(
    session_id TEXT PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
    digest TEXT NOT NULL, started_at TEXT NOT NULL, activity_at TEXT NOT NULL,
    source TEXT NOT NULL, project TEXT NOT NULL, index_version INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS session_activity_recent ON session_retrieval(activity_at DESC,session_id);
CREATE INDEX IF NOT EXISTS session_activity_project ON session_retrieval(project,activity_at DESC,session_id);
CREATE INDEX IF NOT EXISTS session_activity_source ON session_retrieval(source,activity_at DESC,session_id);
CREATE INDEX IF NOT EXISTS session_activity_scope
    ON session_retrieval(project,source,activity_at DESC,session_id);
"""

# Independently versioned, rebuildable projections keep the retained v3 schema
# (including positional legacy sessions inserts) and original timestamps intact.
RETRIEVAL_INDEX_VERSION = 2
# Indexed scope copies must still agree with the authoritative current session;
# a stale projection cannot widen project/source access or expose an old revision.
SESSION_ROWS = """
    session_retrieval r JOIN sessions s ON s.id=r.session_id AND s.digest=r.digest
        AND s.source=r.source AND s.project=r.project
    LEFT JOIN session_metadata m ON m.session_id=s.id
"""
METADATA_FIELDS = """
    r.started_at,r.activity_at,
    coalesce(m.kind,'conversation') AS kind, coalesce(m.agent_label,'') AS agent_label,
    coalesce(m.parent_id,'') AS _parent_id, coalesce(m.forked_from_id,'') AS _forked_from_id
"""


def new_id() -> str:
    return uuid.uuid4().hex


def _timestamp(value: Any) -> str:
    """Normalize captured instants; unknown dates must not acquire capture recency."""
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds")
        except (ValueError, OverflowError):
            pass
    return ""


def _session_times(payload: dict) -> tuple[str, str]:
    """Use only retained capture metadata, never catalog/receipt/last_seen times."""
    started = _timestamp(payload.get("timestamp"))
    context = payload.get("session_context")
    event = _timestamp(context.get("last_event_at")) if isinstance(context, dict) else ""
    # An inconsistent end before the reported start cannot move activity earlier.
    return started, max(started, event)


def _session_date_bounds(since: str = "", before: str = "") -> tuple[str, str]:
    """Normalize explicit instants; the UI sends local calendar days as UTC bounds."""
    bounds = []
    for value in (since, before):
        if not value:
            bounds.append("")
            continue
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError
            normalized = parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds")
        except (ValueError, AttributeError, OverflowError):
            raise ValueError("Choose a valid date range with timezone information") from None
        bounds.append(normalized)
    if all(bounds) and bounds[0] >= bounds[1]:
        raise ValueError("The start date must be before the end of the date range")
    return bounds[0], bounds[1]


def _preview_excerpt(text: str, terms: list[str], length: int = 280) -> str:
    """A bounded, plain-text UI excerpt, never a replacement for retained content."""
    text = " ".join(text.split())
    hits = [position for term in terms if (position := text.casefold().find(term.casefold())) >= 0]
    start = max(0, min(hits) - 70) if hits else 0
    if start:
        space = text.find(" ", start, start + 30)
        if space >= 0:
            start = space + 1
    end = min(len(text), start + length)
    return ("…" if start else "") + text[start:end] + ("…" if end < len(text) else "")


class Store:
    def __init__(self, state_dir: Path):
        self.path = state_dir / "desktop.sqlite3"
        if self.path.is_symlink():
            raise ValueError("The database must not be a symbolic link")
        self.lock = threading.RLock()
        self.db = sqlite3.connect(self.path, check_same_thread=False, timeout=10)
        self.db.row_factory = sqlite3.Row
        version = self.db.execute("PRAGMA user_version").fetchone()[0]
        if version not in (0, 1, 2, 3):
            self.db.close()
            raise RuntimeError("This database was created by a newer ADR Desktop")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript(SCHEMA)
        columns = {row["name"] for row in self.db.execute("PRAGMA table_info(grants)")}
        for name, default in (("kind", "legacy"), ("history_scope", "project"), ("approval_mode", "ask")):
            if name not in columns:
                self.db.execute(f"ALTER TABLE grants ADD COLUMN {name} TEXT NOT NULL DEFAULT '{default}'")
        columns = {row["name"] for row in self.db.execute("PRAGMA table_info(hook_events)")}
        if "credential_kinds" not in columns:
            self.db.execute("ALTER TABLE hook_events ADD COLUMN credential_kinds TEXT NOT NULL DEFAULT '[]'")
        if "phase" not in columns:
            self.db.execute("ALTER TABLE hook_events ADD COLUMN phase TEXT NOT NULL DEFAULT 'pre'")
        if "approval_requested" not in columns:
            self.db.execute(
                "ALTER TABLE hook_events ADD COLUMN approval_requested INTEGER NOT NULL DEFAULT 0"
            )
            # Recover only known legacy outcomes, never infer approvals from
            # arbitrary reason text or the current state of a rule.
            self.db.execute(
                """UPDATE hook_events SET approval_requested=1 WHERE decision='ask'
                   OR (decision='pass' AND reason='Allowed once in ADR')"""
            )
        self.db.execute(
            """CREATE INDEX IF NOT EXISTS hook_intervention_recent ON hook_events(id DESC)
               WHERE decision IN ('deny','ask') OR approval_requested=1"""
        )
        self.db.execute("PRAGMA user_version=3")
        self.db.commit()
        if __import__("os").name != "nt":
            self.path.chmod(0o600)
        for key, value in DEFAULT_SETTINGS.items():
            with self.transaction() as connection:
                connection.execute("INSERT OR IGNORE INTO settings VALUES (?,?)", (key, canonical(value)))
        # Early previews offered seconds-based polling. Move only that preference
        # to a supported cadence, preserving capture consent and all user data.
        interval = json.loads(self.one("SELECT value FROM settings WHERE key='interval_seconds'")["value"])
        if interval not in CAPTURE_INTERVAL_SECONDS:
            self.setting("interval_seconds", DEFAULT_SETTINGS["interval_seconds"])
        self._backfill_session_metadata()
        self._backfill_session_retrieval()

    @staticmethod
    def _identity(source, username, source_id):
        return hashlib.sha256(canonical([source, username, source_id]).encode()).hexdigest()[:32]

    def _write_session_metadata(self, connection, identifier, payload, recovered=None):
        previous = connection.execute(
            "SELECT * FROM session_metadata WHERE session_id=?", (identifier,)
        ).fetchone()
        previous = dict(previous) if previous else {}
        context = payload.get("session_context")
        context = {**(recovered or {}), **(context if isinstance(context, dict) else {})}

        def relation(field, stored):
            value = context.get(field)
            if not isinstance(value, str) or not value or len(value) > 2048:
                return previous.get(stored, "")
            if payload["source"] == "gemini" and not value.startswith("gemini_"):
                value = "gemini_" + value
            result = self._identity(payload["source"], payload.get("username", ""), value)
            return result if result != identifier else ""

        parent = relation("parent_session_id", "parent_id")
        fork = relation("forked_from_session_id", "forked_from_id")
        # Explicit but malformed/cyclic lineage must never hide a conversation.
        ancestor, seen = parent, {identifier}
        for _ in range(64):
            if not ancestor:
                break
            if ancestor in seen:
                parent = ""
                break
            seen.add(ancestor)
            row = connection.execute(
                "SELECT parent_id FROM session_metadata WHERE session_id=?", (ancestor,)
            ).fetchone()
            ancestor = row["parent_id"] if row else ""
        else:
            parent = ""
        kind = context.get("session_kind") or previous.get("kind", "conversation")
        kind = "subagent" if parent else "fork" if fork else kind
        if kind not in ("conversation", "subagent", "fork"):
            kind = "conversation"
        label = context_label(context) or previous.get("agent_label", "")
        native_title = context.get("session_title")
        if not isinstance(native_title, str) or not native_title.strip() or len(native_title) > 1000:
            native_title = previous.get("native_title", "")
        connection.execute(
            """INSERT INTO session_metadata(
                   session_id,parent_id,forked_from_id,agent_label,native_title,kind
               ) VALUES (?,?,?,?,?,?)
               ON CONFLICT(session_id) DO UPDATE SET parent_id=excluded.parent_id,
               forked_from_id=excluded.forked_from_id,agent_label=excluded.agent_label,
               native_title=excluded.native_title,kind=excluded.kind""",
            (identifier, parent, fork, label, native_title, kind),
        )
        title = session_title(payload, native_title=native_title, kind=kind, agent_label=label)
        connection.execute("UPDATE sessions SET title=? WHERE id=?", (title, identifier))

    def _backfill_session_metadata(self):
        # Derived fields only: snapshots, grants, capture settings and message IDs
        # are untouched. Each batch is restartable if the app exits mid-migration.
        after = ""
        while True:
            rows = self.rows(
                """SELECT s.id,s.digest,p.payload FROM sessions s JOIN snapshots p ON p.digest=s.digest
                   LEFT JOIN session_metadata m ON m.session_id=s.id
                   WHERE s.id>? AND m.session_id IS NULL ORDER BY s.id LIMIT 20""",
                (after,),
            )
            if not rows:
                return
            payloads = [json.loads(zlib.decompress(row["payload"])) for row in rows]
            recovered = recover_codex_metadata(payloads)
            with self.transaction() as connection:
                for row, payload in zip(rows, payloads):
                    self._write_session_metadata(
                        connection, row["id"], payload, recovered.get(payload["session_id"])
                    )
                    self._index_session(connection, row["id"], row["digest"], payload)
            after = rows[-1]["id"]

    def _annotate_sessions(self, rows, *, project=None):
        """Dates belong to this session; related titles/counts respect exact project scope."""
        if not rows:
            return rows
        identifiers = [row["id"] for row in rows]
        references = {
            row[key] for row in rows for key in ("_parent_id", "_forked_from_id") if row[key]
        }
        available = {}
        if references:
            placeholders = ",".join("?" for _ in references)
            scope = " AND project=?" if project is not None else ""
            available = {
                row["id"]: row for row in self.rows(
                    f"SELECT id,title FROM sessions WHERE id IN ({placeholders}){scope}",
                    [*references, *([project] if project is not None else [])],
                )
            }
        placeholders = ",".join("?" for _ in identifiers)
        scope = " AND s.project=?" if project is not None else ""
        counts = {
            row["parent_id"]: row["n"] for row in self.rows(
                f"""SELECT m.parent_id,count(*) AS n FROM session_metadata m
                    JOIN sessions s ON s.id=m.session_id
                    WHERE m.parent_id IN ({placeholders}){scope} GROUP BY m.parent_id""",
                [*identifiers, *([project] if project is not None else [])],
            )
        }
        for row in rows:
            # app.js already consumes occurred_at for Updated row/detail dates.
            # This alias is a projection only; sessions.occurred_at stays original.
            row["occurred_at"] = row["activity_at"]
            row["parent"] = available.get(row.pop("_parent_id"))
            row["forked_from"] = available.get(row.pop("_forked_from_id"))
            row["child_count"] = counts.get(row["id"], 0)
        return rows

    @staticmethod
    def _history_text(payload: dict) -> str:
        parts = [str(payload.get("project_path") or ""), str(payload.get("model") or "")]
        for message in payload["chat_history"]:
            parts.append(str(message.get("content") or ""))
            for tool in message.get("tools") or []:
                if isinstance(tool, dict):
                    parts.append(canonical(tool))
        return "\n".join(parts)

    def _index_session(self, connection, identifier, digest, payload):
        current = connection.execute(
            """SELECT s.source,s.project,s.title,coalesce(m.native_title,'') AS native_title,
                      coalesce(m.agent_label,'') AS agent_label
               FROM sessions s LEFT JOIN session_metadata m ON m.session_id=s.id
               WHERE s.id=? AND s.digest=?""", (identifier, digest),
        ).fetchone()
        if not current:
            return
        # One current document per session: every word may match any of its
        # fields, but never a parent's, child's, fork's or superseded revision's.
        body = "\n".join((
            self._history_text(payload), current["title"], current["native_title"], current["agent_label"],
        ))
        connection.execute(
            """INSERT INTO history_documents(session_id,digest,body) VALUES (?,?,?)
               ON CONFLICT(session_id) DO UPDATE SET digest=excluded.digest,body=excluded.body""",
            (identifier, digest, body),
        )
        connection.execute("DELETE FROM credential_session_receipts WHERE session_id=?", (identifier,))
        connection.executemany(
            "INSERT INTO credential_session_receipts(session_id,run_id) VALUES (?,?)",
            [(identifier, run_id) for run_id in sorted(session_run_ids(payload))],
        )
        started, activity = _session_times(payload)
        connection.execute(
            """INSERT INTO session_retrieval(
                   session_id,digest,started_at,activity_at,source,project,index_version
               ) VALUES (?,?,?,?,?,?,?)
               ON CONFLICT(session_id) DO UPDATE SET digest=excluded.digest,
               started_at=excluded.started_at,activity_at=excluded.activity_at,
               source=excluded.source,project=excluded.project,index_version=excluded.index_version""",
            (identifier, digest, started, activity, current["source"], current["project"],
             RETRIEVAL_INDEX_VERSION),
        )

    def _backfill_session_retrieval(self):
        # Receipt times and legacy occurred_at may have been fabricated for invalid
        # timestamps. Derive activity only from the selected retained payload.
        # The per-row version is committed with FTS/activity in restartable batches;
        # keyset traversal avoids rescanning all completed rows for every batch.
        after = ""
        while True:
            rows = self.rows(
                """SELECT s.id,s.digest,p.payload FROM sessions s
                   JOIN snapshots p ON p.digest=s.digest
                   LEFT JOIN history_documents h ON h.session_id=s.id
                   LEFT JOIN session_retrieval r ON r.session_id=s.id
                   WHERE s.id>? AND (h.id IS NULL OR h.digest<>s.digest
                       OR r.session_id IS NULL OR r.digest<>s.digest OR r.index_version<>?
                       OR r.source<>s.source OR r.project<>s.project)
                   ORDER BY s.id LIMIT 20""",
                (after, RETRIEVAL_INDEX_VERSION),
            )
            if not rows:
                return
            with self.transaction() as connection:
                for row in rows:
                    payload = json.loads(zlib.decompress(row["payload"]))
                    self._index_session(connection, row["id"], row["digest"], payload)
            after = rows[-1]["id"]

    @contextmanager
    def transaction(self):
        with self.lock:
            try:
                yield self.db
                self.db.commit()
            except BaseException:
                self.db.rollback()
                raise

    def rows(self, query: str, values=()) -> list[dict]:
        with self.lock:
            return [dict(row) for row in self.db.execute(query, values).fetchall()]

    def one(self, query: str, values=()) -> dict | None:
        result = self.rows(query, values)
        return result[0] if result else None

    def execute(self, query: str, values=()) -> int:
        with self.transaction() as connection:
            return connection.execute(query, values).rowcount

    def settings(self) -> dict:
        return {row["key"]: json.loads(row["value"]) for row in self.rows("SELECT * FROM settings")}

    def setting(self, key: str, value: Any) -> None:
        self.execute(
            "INSERT INTO settings VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, canonical(value)),
        )

    def audit(self, kind: str, summary: str, details: dict | None = None):
        self.execute(
            "INSERT INTO audit(timestamp,kind,summary,details) VALUES (?,?,?,?)",
            (utcnow(), kind, summary, canonical(details or {})),
        )

    def ingest(self, payload: dict) -> bool:
        """Full-content hashing includes tool results, including changed same-UUID snapshots."""
        source = payload.get("source")
        source_id = payload.get("session_id")
        messages = payload.get("chat_history")
        if (
            not isinstance(source, str)
            or not source
            or len(source) > 80
            or not isinstance(source_id, str)
            or not source_id
            or len(source_id) > 2048
            or not isinstance(messages, list)
            or not all(isinstance(message, dict) for message in messages)
        ):
            raise ValueError("Expected an ADR Sensor session with source, session_id, and chat_history")
        encoded = canonical(payload).encode("utf-8")
        if len(encoded) > MAX_JSON_BYTES:
            raise ValueError("Session exceeds 8 MiB; it was not stored or clipped")
        if self.bytes_used() > MAX_STATE_BYTES:
            raise ValueError("The local 1 GiB storage limit was reached; clear history before resuming")
        session_id = self._identity(source, payload.get("username", ""), source_id)
        digest = hashlib.sha256(encoded).hexdigest()
        timestamp, activity = _session_times(payload)
        now = utcnow()
        title = session_title(payload)
        tools = Counter()
        for message in messages:
            for tool in message.get("tools") or []:
                if isinstance(tool, dict):
                    tools[str(tool.get("tool_name") or "Unknown tool")[:200]] += 1
        usage = payload.get("token_usage")
        partial = bool(payload.get("is_truncated") or payload.get("is_chunked"))
        project = str(payload.get("project_path") or "")
        try:
            if project and (Path(project).expanduser().is_absolute() or project.startswith("file:")):
                project = project_path(project)
        except (OSError, ValueError, RuntimeError):
            # Preserve non-local or unresolvable reported projects for display;
            # they do not become a broader MCP grant.
            pass
        with self.transaction() as connection:
            inserted = connection.execute(
                "INSERT OR IGNORE INTO snapshots VALUES (?,?,?,?)",
                (digest, session_id, now, zlib.compress(encoded)),
            ).rowcount
            if not inserted:
                connection.execute("UPDATE sessions SET last_seen=? WHERE id=?", (now, session_id))
                return False
            previous = connection.execute(
                "SELECT activity_at FROM session_retrieval WHERE session_id=?", (session_id,)
            ).fetchone()
            # Resumed captures share a start time. A late, unseen older snapshot
            # must be retained without replacing the current content or its index.
            # Equal activity still allows corrections with unchanged upstream UUIDs.
            if previous and previous["activity_at"] > activity:
                return True
            connection.execute(
                """INSERT INTO sessions(
                       id,source,source_session_id,project,model,title,occurred_at,first_seen,last_seen,
                       message_count,tool_count,token_usage,digest,partial
                   ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET
                   project=excluded.project,model=excluded.model,title=excluded.title,
                   occurred_at=excluded.occurred_at,last_seen=excluded.last_seen,
                   message_count=excluded.message_count,tool_count=excluded.tool_count,
                   token_usage=excluded.token_usage,digest=excluded.digest,partial=excluded.partial""",
                (
                    session_id,
                    source,
                    source_id,
                    project,
                    str(payload.get("model") or ""),
                    title,
                    timestamp,
                    now,
                    now,
                    len(messages),
                    sum(tools.values()),
                    canonical(usage) if isinstance(usage, dict) else None,
                    digest,
                    int(partial),
                ),
            )
            self._write_session_metadata(connection, session_id, payload)
            connection.execute("DELETE FROM session_tools WHERE session_id=?", (session_id,))
            connection.executemany(
                "INSERT INTO session_tools VALUES (?,?,?)",
                [(session_id, name, count) for name, count in tools.items()],
            )
            self._index_session(connection, session_id, digest, payload)
        return True

    def _session_previews(self, rows, *, query=""):
        """Read only this result page, one snapshot at a time; keep full data untouched."""
        terms = re.findall(r"\w+", query, re.UNICODE)
        for row in rows:
            snapshot = self.one(
                """SELECT p.payload FROM snapshots p JOIN sessions s ON s.digest=p.digest
                   WHERE s.id=?""", (row["id"],),
            )
            if not snapshot:
                continue
            payload = json.loads(zlib.decompress(snapshot["payload"]))
            best, best_score = None, (-1, -1, -1)

            def consider(value, label, index, priority, tool_index=None):
                nonlocal best, best_score
                text = value if isinstance(value, str) else canonical(value)
                if not text.strip():
                    return
                folded = text.casefold()
                hits = sum(term.casefold() in folded for term in terms)
                if terms and not hits:
                    return
                score = (hits, priority, index)
                if score > best_score:
                    best_score = score
                    best = {
                        "text": _preview_excerpt(text, terms), "label": label,
                        "message_index": index, "tool_index": tool_index,
                    }

            for index, message in enumerate(payload["chat_history"]):
                setup = is_setup_message(message)
                text = message.get("content")
                if text and (terms or not setup) and text != "[Assistant decided to use a tool]":
                    assistant = message.get("role") == "assistant"
                    label = "Session setup" if setup else "Answer" if assistant else "Your request"
                    consider(text, label, index, 0 if setup else 3 if assistant else 2)
                if not terms:
                    continue
                for tool_index, tool in enumerate(message.get("tools") or []):
                    if not isinstance(tool, dict):
                        continue
                    name = tool.get("tool_name") or "Tool"
                    for key, label in (
                        ("result", f"{name} result"), ("arguments", f"{name} input"),
                        ("error", f"{name} error"), ("tool_name", "Tool name"),
                    ):
                        if tool.get(key) is not None:
                            consider(tool[key], label, index, 1, tool_index)
            if best:
                row["preview"] = best
            elif query:
                row["preview"] = {
                    "text": _preview_excerpt(row.get("snippet") or row["title"], terms),
                    "label": "Session details", "message_index": None, "tool_index": None,
                }

    def session_filters(self):
        """Owner UI facets, not an agent-discovery or filesystem scan."""
        return {
            "projects": self.rows(
                """SELECT project,count(*) AS sessions FROM sessions WHERE project<>''
                   GROUP BY project ORDER BY project COLLATE NOCASE"""
            ),
            "sources": [row["source"] for row in self.rows(
                "SELECT DISTINCT source FROM sessions ORDER BY source"
            )],
        }

    def search_history(
        self, query: str, *, source="", project: str | None = None, limit=20, offset=0,
        since="", before="", sort="relevance", previews=False,
    ):
        if not isinstance(query, str) or not 1 <= len(query.strip()) <= 200:
            raise ValueError("Enter between 1 and 200 characters to search")
        terms = re.findall(r"\w+", query, re.UNICODE)
        if not terms or len(terms) > 32:
            raise ValueError("Search using up to 32 words")
        # Keywords are literals, never caller-supplied FTS operators or SQL.
        match = " AND ".join('"' + term.replace('"', '""') + '"' for term in terms)
        conditions = ["history_search MATCH ?"]
        values: list[Any] = [match]
        if source:
            conditions.append("r.source=?")
            values.append(source)
        if project is not None:
            conditions.append("r.project=?")
            values.append(project)
        since, before = _session_date_bounds(since, before)
        if since or before:
            conditions.append("r.activity_at<>''")
        for value, operator in ((since, ">="), (before, "<")):
            if value:
                conditions.append(f"r.activity_at{operator}?")
                values.append(value)
        if sort not in ("relevance", "newest"):
            raise ValueError("Choose relevance or newest first")
        where = " AND ".join(conditions)
        joined = f"""{SESSION_ROWS}
                    JOIN history_documents h ON h.session_id=s.id AND h.digest=s.digest
                    JOIN history_search ON history_search.rowid=h.id"""
        limit, offset = min(max(int(limit), 1), 50), min(max(int(offset), 0), 100000)
        total = self.one(
            f"SELECT count(*) AS n FROM {joined} WHERE {where}", values,
        )["n"]
        rows = self.rows(
            f"""SELECT s.id,s.source,s.title,s.project,s.model,
                       s.message_count,s.tool_count,{METADATA_FIELDS},
                       snippet(history_search,0,'','',' … ',36) AS snippet
                FROM {joined} WHERE {where}
                ORDER BY {"bm25(history_search)," if sort == "relevance" else ""}
                         r.activity_at DESC,r.session_id LIMIT ? OFFSET ?""",
            [*values, limit, offset],
        )
        for row in rows:
            clipped = len(row["snippet"]) > 800
            row["is_excerpt"] = True
            row["snippet_truncated"] = clipped or " … " in row["snippet"]
            row["snippet"] = row["snippet"][:800]
            if clipped:
                row["snippet"] += "…"
            # Presentation metadata is bounded; full originals remain in snapshots.
            row["project"] = row["project"][:8192]
            row["model"] = row["model"][:200]
        if previews:
            self._session_previews(rows, query=query)
        return {
            "items": self._annotate_sessions(rows, project=project),
            "total": total,
            "offset": offset,
            "limit": limit,
            "next_offset": offset + len(rows) if offset + len(rows) < total else None,
        }

    def sessions(
        self, *, source="", query="", limit=50, offset=0, project: str | None = None,
        grouped=False, parent=None, since="", before="", previews=False,
    ):
        conditions = ["1=1"]
        values: list[Any] = []
        if source:
            conditions.append("r.source=?")
            values.append(source)
        if query:
            conditions.append("(s.title LIKE ? OR s.project LIKE ? OR s.model LIKE ?)")
            values.extend([f"%{query}%"] * 3)
        if project is not None:
            # Project grants are exact, not an untrusted string-prefix directory grant.
            conditions.append("r.project=?")
            values.append(project)
        since, before = _session_date_bounds(since, before)
        if since or before:
            conditions.append("r.activity_at<>''")
        for value, operator in ((since, ">="), (before, "<")):
            if value:
                conditions.append(f"r.activity_at{operator}?")
                values.append(value)
        if parent is not None:
            conditions.append("m.parent_id=?")
            values.append(parent)
        elif grouped:
            scope = " AND p.project=?" if project is not None else ""
            conditions.append(
                f"NOT EXISTS (SELECT 1 FROM sessions p WHERE p.id=m.parent_id{scope})"
            )
            if project is not None:
                values.append(project)
        where = " AND ".join(conditions)
        joined = SESSION_ROWS
        total = self.one(f"SELECT count(*) AS n FROM {joined} WHERE {where}", values)["n"]
        limit, offset = min(max(int(limit), 1), 100), max(int(offset), 0)
        rows = self.rows(
            f"""SELECT s.*,{METADATA_FIELDS} FROM {joined} WHERE {where}
                ORDER BY r.activity_at DESC,r.session_id LIMIT ? OFFSET ?""",
            [*values, limit, offset],
        )
        for row in rows:
            row["token_usage"] = json.loads(row["token_usage"]) if row["token_usage"] else None
        if previews:
            self._session_previews(rows)
        return {
            "items": self._annotate_sessions(rows, project=project), "total": total,
            "offset": offset, "limit": limit,
            "next_offset": offset + len(rows) if offset + len(rows) < total else None,
        }

    def session_children(self, identifier, *, project=None, limit=30, offset=0):
        parent = self.one("SELECT project FROM sessions WHERE id=?", (identifier,))
        if not parent or (project is not None and parent["project"] != project):
            return None
        return self.sessions(parent=identifier, project=project, limit=limit, offset=offset)

    def session(self, session_id: str, *, project: str | None = None) -> dict | None:
        row = self.one(
            f"SELECT s.*,{METADATA_FIELDS} FROM {SESSION_ROWS} WHERE s.id=?",
            (session_id,),
        )
        if not row or (project is not None and row["project"] != project):
            return None
        snapshot = self.one("SELECT payload FROM snapshots WHERE digest=?", (row["digest"],))
        row["payload"] = json.loads(zlib.decompress(snapshot["payload"]))
        row["token_usage"] = json.loads(row["token_usage"]) if row["token_usage"] else None
        row["revisions"] = self.one("SELECT count(*) AS n FROM snapshots WHERE session_id=?", (session_id,))[
            "n"
        ]
        self._annotate_sessions([row], project=project)
        row["presentation"] = {
            "setup_message_indexes": [
                index for index, message in enumerate(row["payload"]["chat_history"])
                if is_setup_message(message)
            ]
        }
        return row

    def overview(self):
        totals = self.one(
            """SELECT count(*) AS sessions,coalesce(sum(message_count),0) AS messages,
               coalesce(sum(tool_count),0) AS tools,count(DISTINCT source) AS agents,
               count(DISTINCT nullif(project,'')) AS projects FROM sessions"""
        )
        totals["rules"] = self.one("SELECT count(*) AS n FROM rules")["n"]
        totals["credentials"] = self.one(
            """SELECT (SELECT count(*) FROM credentials WHERE state='active')
               + (SELECT count(*) FROM environment_credentials WHERE state='active') AS n"""
        )["n"]
        totals["pending"] = self.one("SELECT count(*) AS n FROM broker_requests WHERE state='pending'")["n"]
        conversations = self.sessions(grouped=True, limit=6)
        totals["conversations"] = conversations["total"]
        totals["subagents"] = self.one(
            "SELECT count(*) AS n FROM session_metadata WHERE kind='subagent'"
        )["n"]
        return {
            "totals": totals,
            "sources": self.rows(
                f"""SELECT s.source,count(*) AS sessions,sum(s.tool_count) AS tools,
                    max(r.activity_at) AS latest FROM {SESSION_ROWS}
                    GROUP BY s.source ORDER BY sessions DESC"""
            ),
            "days": self.rows(
                f"""SELECT substr(r.activity_at,1,10) AS day,count(*) AS sessions FROM {SESSION_ROWS}
                    WHERE r.activity_at<>'' GROUP BY day ORDER BY day DESC LIMIT 14"""
            )[::-1],
            "top_tools": self.rows(
                "SELECT name,sum(count) AS count FROM session_tools GROUP BY name ORDER BY count DESC LIMIT 8"
            ),
            "recent": conversations["items"],
        }

    def bytes_used(self):
        return sum(
            path.stat().st_size for path in (self.path, Path(str(self.path) + "-wal")) if path.exists()
        )

    def purge_history(self):
        with self.transaction() as connection:
            for table in ("history_documents", "session_tools", "sessions", "snapshots"):
                connection.execute(f"DELETE FROM {table}")
        with self.lock:
            self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self.db.execute("VACUUM")
        self.audit("history_deleted", "Collected session history deleted by the user")

    def close(self):
        with self.lock:
            self.db.close()
