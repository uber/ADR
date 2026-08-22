"""The content of every file the harness creates.

Kept in one module because these are fixtures, not code: what matters is that a
skill looks enough like a skill for the collector's parser to accept it, and
that every one of them is recognizably a test artifact so nobody finds one on a
machine later and wonders what it is.

Nothing here is realistic beyond what detection requires. A skill with a real
prompt in it would be a prompt somebody could run.
"""

import json
from typing import Any, Dict

MARKER = "ADR end-to-end test artifact - safe to delete"

_FRONT_MATTER = """---
name: %(name)s
description: %(description)s
version: 1.0.0
---

# %(title)s

%(marker)s
"""


def skill(name: str) -> str:
    return _FRONT_MATTER % {"name": name, "description": "e2e fixture skill",
                            "title": name, "marker": MARKER}


def command(name: str) -> str:
    return _FRONT_MATTER % {"name": name, "description": "e2e fixture command",
                            "title": name, "marker": MARKER}


def command_toml(name: str) -> str:
    return 'description = "e2e fixture command"\nprompt = "%s"\n' % MARKER


def subagent(name: str) -> str:
    return _FRONT_MATTER % {"name": name, "description": "e2e fixture subagent",
                            "title": name, "marker": MARKER}


def output_style(name: str) -> str:
    return _FRONT_MATTER % {"name": name, "description": "e2e fixture output style",
                            "title": name, "marker": MARKER}


def instructions(name: str) -> str:
    return "# %s\n\n%s\n" % (name, MARKER)


def plugin(name: str) -> Dict[str, str]:
    """A plugin is a directory, so it returns the files it is made of."""
    return {"plugin.json": json.dumps({"name": name, "version": "1.0.0",
                                       "description": MARKER}, indent=2) + "\n",
            "README.md": "# %s\n\n%s\n" % (name, MARKER)}


def hook(event: str, command_line: str) -> Dict[str, Any]:
    """The fragment merged into a settings file.

    Merged rather than written whole: S-13 and S-16 both land in
    ``~/.claude/settings.json``, and a recipe that overwrote would silently
    delete the entry the previous one made and turn it into a miss.
    """
    return {"hooks": {event: [{"matcher": "*", "hooks": [
        {"type": "command", "command": command_line}]}]}}


def malformed_bundle() -> str:
    """A bundle manifest that declares nothing runnable.

    Valid JSON, recognizably a bundle, and with no server in it - so a collector
    that reports it as a server is inventing one, and a collector that says
    nothing has silently dropped a malformed file it should have flagged.
    """
    return json.dumps({"manifest_version": "0.2", "name": "broken-bundle",
                       "version": "0.0.1", "description": MARKER,
                       "server": {}}, indent=2) + "\n"


def backup_script() -> str:
    """N-07: a shell script whose *path* contains "mcp" and whose contents have
    nothing to do with MCP."""
    return ("#!/bin/sh\n# %s\n# Copies a directory. Named to look like MCP; it is not.\n"
            "tar -czf \"$HOME/backup.tgz\" \"$HOME/documents\" 2>/dev/null || true\n" % MARKER)


def llm_wrapper() -> str:
    """N-10: an in-house AI wrapper the catalog has never heard of.

    It must look enough like AI tooling to be worth reviewing - it posts a
    prompt to a completion endpoint - and must not be classifiable, because the
    question is whether an unknown tool reaches the review queue instead of
    being confidently mislabelled or silently dropped.
    """
    return ("#!/bin/sh\n# %s\n"
            "# In-house wrapper around the corporate LLM gateway.\n"
            "curl -s -X POST \"$CORP_LLM_ENDPOINT/v1/completions\" \\\n"
            "  -H 'Content-Type: application/json' \\\n"
            "  -d \"{\\\"prompt\\\": \\\"$*\\\", \\\"max_tokens\\\": 256}\"\n" % MARKER)


def probe_server() -> str:
    """The trivial stdio MCP server every M-SITE row declares.

    Never actually spoken to except by M-SP-01, which starts it to prove an
    undeclared server is noticed. It exists so that the declarations point at
    something real: a command that does not exist is a different test.
    """
    return ("#!/usr/bin/env node\n// %s\n"
            "process.stdin.resume();\n"
            "process.stdin.on('data', () => {});\n" % MARKER)


def shell_export(variable: str, value: str) -> str:
    return "\n# %s\nexport %s=%s\n" % (MARKER, variable, value)
