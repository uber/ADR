"""Emitting the three config formats the declaration sites use.

Only writers, never parsers. The harness composes files the collector then
reads, so a hand-rolled writer for a subset it fully controls is safe in a way
a hand-rolled parser would not be - and it keeps the harness on the standard
library, which is what lets it run from this directory with nothing installed.

The one exception is JSON merging, where an existing file must be read back:
S-13 and S-16 both write ``~/.claude/settings.json``, and a writer that
overwrote would delete the earlier entry and report it as a miss.
"""

import json
from typing import Any, Dict, List


def merge(base: Dict[str, Any], addition: Dict[str, Any]) -> Dict[str, Any]:
    """Recursive merge, with lists concatenated rather than replaced."""
    out = dict(base)
    for key, value in addition.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = merge(out[key], value)
        elif isinstance(value, list) and isinstance(out.get(key), list):
            out[key] = out[key] + value
        else:
            out[key] = value
    return out


def as_json(document: Dict[str, Any]) -> str:
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def as_toml(document: Dict[str, Any]) -> str:
    """The subset Codex's ``config.toml`` needs: nested tables of scalars.

    Deliberately narrow. It emits what this manifest declares and raises on
    anything else, because a writer that silently degrades an unsupported value
    would produce a config the collector reads differently from the one the
    manifest describes.
    """
    lines: List[str] = []
    _toml_table(document, [], lines)
    return "\n".join(lines) + "\n"


def _toml_table(table: Dict[str, Any], prefix: List[str], lines: List[str]) -> None:
    scalars = {key: value for key, value in table.items() if not isinstance(value, dict)}
    tables = {key: value for key, value in table.items() if isinstance(value, dict)}
    if prefix and (scalars or not tables):
        lines.append("[%s]" % ".".join(_toml_key(part) for part in prefix))
    for key, value in scalars.items():
        lines.append("%s = %s" % (_toml_key(key), _toml_value(value)))
    for key, value in tables.items():
        if scalars or prefix:
            lines.append("")
        _toml_table(value, prefix + [key], lines)


def _toml_key(key: str) -> str:
    if key and all(character.isalnum() or character in "-_" for character in key):
        return key
    return json.dumps(key)


def _toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, list):
        return "[%s]" % ", ".join(_toml_value(item) for item in value)
    raise TypeError("no TOML spelling for %r" % type(value).__name__)


def as_yaml(document: Dict[str, Any]) -> str:
    """The subset Goose's ``config.yaml`` needs: nested maps, lists of scalars.

    Block style throughout, with every string quoted. Quoting unconditionally
    costs nothing and removes the whole class of bug where a value like ``yes``
    or ``2025-08-21`` parses as something other than the string it was written
    as.
    """
    lines: List[str] = []
    _yaml_node(document, 0, lines)
    return "\n".join(lines) + "\n"


def _yaml_node(node: Any, indent: int, lines: List[str]) -> None:
    pad = "  " * indent
    for key, value in node.items():
        if isinstance(value, dict):
            lines.append("%s%s:" % (pad, key))
            _yaml_node(value, indent + 1, lines)
        elif isinstance(value, list):
            lines.append("%s%s:" % (pad, key))
            for item in value:
                lines.append("%s  - %s" % (pad, _yaml_scalar(item)))
        else:
            lines.append("%s%s: %s" % (pad, key, _yaml_scalar(value)))


def _yaml_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(str(value))
