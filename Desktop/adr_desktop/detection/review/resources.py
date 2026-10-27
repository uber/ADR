"""The review part's prompts, config and SQL, kept as files in the folders next to this module."""

import json
import re
from pathlib import Path

ROOT = Path(__file__).parent


def prompt(name):
    return (ROOT / "prompts" / f"{name}.txt").read_text().strip()


def config(name):
    return json.loads((ROOT / "config" / f"{name}.json").read_text())


def statements():
    """Every statement in sql/*.sql by name; each one starts with a `-- name: <name>` line."""
    found = {}
    for path in sorted((ROOT / "sql").glob("*.sql")):
        parts = re.split(r"^-- name: (\w+)$", path.read_text(), flags=re.M)
        for name, body in zip(parts[1::2], parts[2::2]):
            if name in found:
                raise ValueError(f"Duplicate SQL statement name {name}")
            found[name] = body.strip()
    return found
