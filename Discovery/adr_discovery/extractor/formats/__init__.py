"""Real parsers, always.

Every defect in the last two review rounds that reached production
behaviour came from hand-rolled parsing of structured input: TOML split on
punctuation, flags split on the first separator, image references split on
a colon, URLs split before the port. Each function below hands the bytes to
a parser that understands the grammar.
"""

from __future__ import annotations

import json as _json
import plistlib as _plistlib
import tomllib as _tomllib

from . import yaml as _yaml

Unrepresentable = _yaml.Unrepresentable


def parse(text: str, fmt: str) -> dict:
    if fmt == "json":
        return _json.loads(text)
    if fmt == "toml":
        return _tomllib.loads(text)
    if fmt in ("yaml", "yml", "workflow"):
        return _yaml.loads(text)
    raise ValueError(f"no parser for format {fmt!r}")


def parse_bytes(data: bytes, fmt: str) -> dict:
    if fmt == "plist":
        return _plistlib.loads(data)
    return parse(data.decode("utf-8", errors="replace"), fmt)


def format_for(path: str) -> str | None:
    lowered = path.lower()
    if lowered.endswith(".json") or lowered.endswith(".jsonc"):
        return "json"
    if lowered.endswith(".toml"):
        return "toml"
    if lowered.endswith(".plist"):
        return "plist"
    if "/.github/workflows/" in lowered and (lowered.endswith(".yml") or lowered.endswith(".yaml")):
        return "workflow"
    if lowered.endswith(".yaml") or lowered.endswith(".yml"):
        return "yaml"
    return None
