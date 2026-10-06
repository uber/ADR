"""Normalize Codex thread metadata without interpreting conversation content."""

import json
from collections.abc import Mapping
from typing import Any, Dict


def _text(value: Any, limit: int = 512) -> str:
    return value.strip() if isinstance(value, str) and 0 < len(value.strip()) <= limit else ""


def codex_session_context(metadata: Mapping) -> Dict[str, str]:
    """Keep explicit lineage; similar prompts are never evidence of a relationship."""
    identifier = _text(metadata.get("id"), 2048)
    source = metadata.get("source")
    if isinstance(source, str) and len(source) <= 32768:
        try:
            source = json.loads(source)
        except (ValueError, RecursionError):
            source = None
    subagent = source.get("subagent") if isinstance(source, Mapping) else None
    spawn = subagent.get("thread_spawn") if isinstance(subagent, Mapping) else None
    spawn = spawn if isinstance(spawn, Mapping) else {}
    context = {"session_kind": "conversation"}
    parent = _text(spawn.get("parent_thread_id"), 2048)
    fork = _text(metadata.get("forked_from_id"), 2048)
    if fork and fork != identifier:
        context.update(session_kind="fork", forked_from_session_id=f"codex_{fork}")
    if subagent is not None:
        context["session_kind"] = "subagent"
    if parent and parent != identifier:
        context.update(session_kind="subagent", parent_session_id=f"codex_{parent}")
    for key in ("agent_path", "agent_nickname", "agent_role"):
        value = _text(metadata.get(key)) or _text(spawn.get(key))
        if value:
            context[key] = value
    title = _text(metadata.get("name"), 1000) or _text(metadata.get("title"), 1000)
    if title:
        context["session_title"] = title
    return context
