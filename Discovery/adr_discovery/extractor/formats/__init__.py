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
        try:
            return _json.loads(text)
        except _json.JSONDecodeError:
            # VS Code's mcp.json, Zed's settings.json and every `.jsonc` file
            # are JSON with comments and trailing commas. Strict JSON is tried
            # first, so a document that parses as JSON is read unchanged.
            return _json.loads(_strip_jsonc(text))
    if fmt == "toml":
        return _tomllib.loads(text)
    if fmt in ("yaml", "yml", "workflow"):
        return _yaml.loads(text)
    raise ValueError(f"no parser for format {fmt!r}")


def _strip_jsonc(text: str) -> str:
    """Drop `//` and `/* */` comments, then trailing commas, outside strings."""
    return _drop_trailing_commas(_drop_comments(text))


def _drop_comments(text: str) -> str:
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == '"':
            end = _string_end(text, i)
            out.append(text[i:end])
            i = end
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end < 0 else end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
            out.append(" ")
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _drop_trailing_commas(text: str) -> str:
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == '"':
            end = _string_end(text, i)
            out.append(text[i:end])
            i = end
            continue
        if ch == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j < n and text[j] in "}]":
                i += 1
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def _string_end(text: str, start: int) -> int:
    """Index just past the string literal opening at `start`."""
    i, n = start + 1, len(text)
    while i < n:
        if text[i] == "\\":
            i += 2
        elif text[i] == '"':
            return i + 1
        else:
            i += 1
    return n


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
