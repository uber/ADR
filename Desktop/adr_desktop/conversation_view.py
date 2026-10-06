"""Derived conversation presentation. Never rewrite retained sensor payloads."""

import json
import os
import re
import sqlite3
import stat
from pathlib import Path

from adr_sensor.utils.codex_context import codex_session_context

SETUP_TAGS = (
    "environment_context", "recommended_plugins", "skills_instructions",
    "permissions_instructions", "collaboration_mode", "apps_instructions",
    "local-command-caveat",
)
SETUP_PREFIX = re.compile(r"^\s*<(" + "|".join(SETUP_TAGS) + r")>[\s\S]*?</\1>\s*")
AGENTS_PREFIX = re.compile(
    r"^\s*# AGENTS\.md instructions[^\n]*\n\s*<INSTRUCTIONS>[\s\S]*?</INSTRUCTIONS>\s*"
)
MAX_METADATA_BYTES = 512 * 1024


def user_request(content) -> str:
    """Skip known harness envelopes, not arbitrary XML or actual repeated requests."""
    if not isinstance(content, str):
        return ""
    text = content.strip()
    for _ in range(64):
        match = SETUP_PREFIX.match(text) or AGENTS_PREFIX.match(text)
        if not match:
            break
        text = text[match.end():].strip()
    return text


def is_setup_message(message: dict) -> bool:
    # A tool-bearing record must remain visible even if its text resembles setup.
    if message.get("tools"):
        return False
    role = message.get("role")
    return role in ("system", "developer") or (
        role == "user" and bool(message.get("content")) and not user_request(message["content"])
    )


def session_title(payload: dict, *, native_title="", kind="", agent_label="") -> str:
    if kind == "subagent" and agent_label:
        title = agent_label
    else:
        # Some catalogs use a truncated raw setup message as their title; it no
        # longer has a closing tag, so don't mistake it for a human-written name.
        native = native_title.strip() if isinstance(native_title, str) else ""
        setup_title = native.startswith("# AGENTS.md instructions") or any(
            native.startswith(f"<{tag}>") for tag in SETUP_TAGS
        )
        title = "" if setup_title else user_request(native)
        if not title:
            title = next(
                (text for message in payload["chat_history"]
                 if message.get("role") == "user" and (text := user_request(message.get("content")))),
                "Untitled session",
            )
    return " ".join(title.split())[:120]


def context_label(context: dict) -> str:
    path = context.get("agent_path")
    if isinstance(path, str) and path.strip("/"):
        return path.strip("/").rsplit("/", 1)[-1].replace("_", " ")[:120]
    for key in ("agent_role", "agent_nickname", "agent_id"):
        if isinstance(context.get(key), str) and context[key].strip():
            return context[key].strip()[:120]
    return ""


def recover_codex_metadata(payloads: list[dict]) -> dict[str, dict]:
    """Read only metadata for already-captured Codex sessions during migration.

    No new conversations, transcript bodies, settings, or permissions are captured.
    Missing/locked catalogs and moved logs simply leave a session ungrouped.
    """
    wanted = {
        payload["session_id"].removeprefix("codex_"): payload
        for payload in payloads
        if payload.get("source") == "codex" and payload.get("session_id", "").startswith("codex_")
    }
    if not wanted:
        return {}
    try:
        root = Path(os.environ.get("CODEX_HOME") or Path.home() / ".codex").expanduser().resolve()
        catalogs = sorted(root.glob("state_*.sqlite"))
    except (OSError, RuntimeError, ValueError):
        return {}
    metadata = {}
    for catalog in catalogs:
        connection = None
        try:
            if not catalog.resolve().is_relative_to(root):
                continue
            connection = sqlite3.connect(catalog.resolve().as_uri() + "?mode=ro", uri=True, timeout=0)
            connection.row_factory = sqlite3.Row
            columns = {row[1] for row in connection.execute("PRAGMA table_info(threads)")}
            if "id" not in columns:
                continue
            possible = (
                "id", "name", "title", "source", "agent_path", "agent_nickname", "agent_role", "rollout_path",
            )
            selected = [name for name in possible if name in columns]
            fields = ",".join(f'"{name}"' for name in selected)
            placeholders = ",".join("?" for _ in wanted)
            for row in connection.execute(
                f"SELECT {fields} FROM threads WHERE id IN ({placeholders})", tuple(wanted)
            ):
                metadata[row["id"]] = dict(row)
        except (OSError, sqlite3.Error, RuntimeError, ValueError):
            continue
        finally:
            if connection is not None:
                connection.close()
    recovered = {}
    for identifier, payload in wanted.items():
        record = metadata.get(identifier, {})
        raw_path = record.get("rollout_path") or payload.get("raw_log_path")
        try:
            if isinstance(raw_path, str) and raw_path:
                path = Path(raw_path)
                if not path.is_absolute():
                    path = root / path
                path = path.resolve()
                if path.suffix == ".jsonl" and path.is_relative_to(root):
                    descriptor = os.open(
                        path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
                    )
                    with os.fdopen(descriptor, "rb") as stream:
                        if stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                            line = stream.readline(MAX_METADATA_BYTES + 1)
                            if len(line) <= MAX_METADATA_BYTES:
                                event = json.loads(line)
                                header = event.get("payload") if isinstance(event, dict) else None
                                if (
                                    isinstance(event, dict) and event.get("type") == "session_meta"
                                    and isinstance(header, dict) and header.get("id") == identifier
                                ):
                                    record = {**record, **header}
        except (OSError, ValueError, RuntimeError, RecursionError):
            pass
        if record:
            recovered[payload["session_id"]] = codex_session_context({**record, "id": identifier})
    return recovered
