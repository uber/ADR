"""The content of every artifact the harness creates.

Kept apart from the recipes because the bytes are the interesting part: what a
skill file or a hook actually contains is what the collector reads, and a
change here is a change to what is being measured.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Mapping, Optional

from ..manifest import CANARY_REF, Entry

#: `body` in a create block names a template, not the bytes. Writing the name
#: itself leaves a file that exists and says nothing - which looks installed
#: and is not, and is exactly the sort of thing a scan would report oddly.
TEMPLATES = {
    "skill": """---
name: {slug}
description: {name} — planted by the ADR Discovery harness ({entry_id}).
---

# {name}

Planted by the ADR Discovery test harness as manifest entry {entry_id}.

## Usage

Invoke this skill to exercise the collector's skill discovery.
""",
    "command": """---
description: {name} ({entry_id})
---

# /{slug}

Planted by the ADR Discovery test harness as manifest entry {entry_id}.
""",
    "command_toml": """# Planted by the ADR Discovery test harness as manifest entry {entry_id}.
description = "{name}"
prompt = \"\"\"
Run the {slug} check and report what changed.
\"\"\"
""",
    "output_style": """---
name: {slug}
description: {name} ({entry_id})
---

Answer in as few words as the question allows.
""",
    "subagent": """---
name: {slug}
description: {name} — planted by manifest entry {entry_id}.
tools: Read, Grep
---

You are {name}, planted by the ADR Discovery test harness.
""",
    "instructions": """# {name}

Instructions planted by the ADR Discovery test harness as manifest entry
{entry_id}. Present so the collector has a programmable surface to find.
""",
    "backup_script": """#!/usr/bin/env bash
# {name} — manifest entry {entry_id}, planted by the ADR Discovery harness.
set -euo pipefail
cp -a "$HOME/.claude.json" "$HOME/.claude.json.bak"
""",
    "llm_wrapper": """#!/usr/bin/env bash
# {name} — manifest entry {entry_id}.
# An in-house wrapper: probable AI, unclassified. Belongs in triage, not in
# an inventory, which is the whole point of this row.
set -euo pipefail
exec curl -sS https://llm.internal.example/v1/chat -d "{{\"prompt\": \"$*\"}}"
""",
    "plugin": """# {name}

Plugin directory planted by manifest entry {entry_id}.
""",
}

#: Deliberately broken, so the collector meets a bundle it cannot parse.
MALFORMED = '{{"name": "{slug}", "version": "1.0.0", "server": {{ "command": '


def _slug(entry: "Entry") -> str:
    return entry.name.lower().replace(" ", "-").replace("/", "-")


def substitute(text: str, canaries: Mapping[str, str]) -> str:
    """Replace every ``{{canary:name}}`` with the value planted for this run.

    An unresolved reference is left alone rather than blanked: a canary the
    manifest declared and the run never planted should be visible in the
    artifact, not silently erased into a passing check.
    """
    def replace(match) -> str:
        return canaries.get(match.group(1), match.group(0))

    return CANARY_REF.sub(replace, text)


def declaration(entry: Entry) -> Dict[str, Any]:
    """The config document one ``declare`` row leaves at its site."""
    block = entry.declare
    server: Dict[str, Any] = {}
    if block.get("command"):
        server["command"] = block["command"]
        if block.get("args"):
            server["args"] = list(block["args"])
    if block.get("url"):
        server["url"] = block["url"]
    if block.get("transport"):
        server["type"] = block["transport"]
    if block.get("env"):
        server["env"] = dict(block["env"])
    if block.get("headers"):
        server["headers"] = dict(block["headers"])

    name = block.get("server_name") or entry.id.lower()
    key = block.get("container") or "mcpServers"
    return {key: {name: server}}


def artifact(entry: Entry) -> str:
    """The bytes one ``create`` row writes.

    ``body`` names a template. Emitting the name verbatim would leave a
    SKILL.md whose entire content is the word ``skill``.
    """
    block = entry.create
    marker = str(block.get("body") or "").strip()
    fields = {"name": entry.name, "entry_id": entry.id, "slug": _slug(entry)}

    if marker == "hook":
        return json.dumps(hook(entry), indent=2, sort_keys=True)
    if marker == "malformed_bundle":
        return MALFORMED.format(**fields)
    if marker in TEMPLATES:
        return TEMPLATES[marker].format(**fields)
    if marker:
        return f"# {entry.name}\n# manifest entry {entry.id} ({marker})\n"
    return f"# {entry.name}\n# manifest entry {entry.id}\n"


def hook(entry: Entry) -> Dict[str, Any]:
    """A settings hook, in the shape the setting actually takes."""
    block = entry.create
    event = str(block.get("event") or "PreToolUse")
    command = str(block.get("command") or "true")
    return {"hooks": {event: [{"matcher": "*",
                               "hooks": [{"type": "command", "command": command}]}]}}


def body_for(entry: Entry, canaries: Optional[Mapping[str, str]] = None) -> str:
    from .writers import emit, format_for

    canaries = canaries or {}
    if entry.shape == "declare":
        path = entry.path_for("linux") or "config.json"
        text = emit(declaration(entry), format_for(path))
    else:
        text = artifact(entry)
    return substitute(text, canaries)


__all__ = ["MALFORMED", "TEMPLATES", "artifact", "body_for", "declaration",
           "hook", "substitute"]
