"""Config emitters for the declaration sites.

Three formats because the sites use three formats. Written by hand rather than
pulled from a dependency: the harness must emit exactly what a user's editor
would leave behind, including the shapes a strict library would refuse.
"""

from __future__ import annotations

import json
from typing import Any, Mapping

INDENT = "  "


def to_json(document: Mapping[str, Any]) -> str:
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def to_toml(document: Mapping[str, Any]) -> str:
    """Enough TOML for the config sites, and no more."""
    lines: list[str] = []
    scalars = {k: v for k, v in document.items() if not isinstance(v, Mapping)}
    tables = {k: v for k, v in document.items() if isinstance(v, Mapping)}

    for key, value in scalars.items():
        lines.append(f"{key} = {_toml_value(value)}")
    for key, table in tables.items():
        lines.append("")
        lines.append(f"[{key}]")
        lines.extend(_toml_table(table))
    return "\n".join(lines).strip() + "\n"


def _toml_table(table: Mapping[str, Any], prefix: str = "") -> list[str]:
    lines: list[str] = []
    for key, value in table.items():
        if isinstance(value, Mapping):
            lines.append("")
            lines.append(f"[{prefix}{key}]" if prefix else f"[{key}]")
            lines.extend(_toml_table(value, prefix=f"{prefix}{key}."))
        else:
            lines.append(f"{key} = {_toml_value(value)}")
    return lines


def _toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_toml_value(v) for v in value) + "]"
    return json.dumps(str(value))


def to_yaml(document: Mapping[str, Any]) -> str:
    return "\n".join(_yaml_lines(document, 0)).strip() + "\n"


def _yaml_lines(value: Any, depth: int) -> list[str]:
    pad = INDENT * depth
    if isinstance(value, Mapping):
        lines: list[str] = []
        for key, item in value.items():
            if isinstance(item, (Mapping, list, tuple)) and item:
                lines.append(f"{pad}{key}:")
                lines.extend(_yaml_lines(item, depth + 1))
            else:
                lines.append(f"{pad}{key}: {_yaml_scalar(item)}")
        return lines
    if isinstance(value, (list, tuple)):
        return [f"{pad}- {_yaml_scalar(item)}" for item in value]
    return [f"{pad}{_yaml_scalar(value)}"]


def _yaml_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value)
    return json.dumps(text) if text.strip() != text or not text else text


def emit(document: Mapping[str, Any], fmt: str) -> str:
    writers = {"json": to_json, "toml": to_toml, "yaml": to_yaml, "yml": to_yaml}
    if fmt not in writers:
        raise ValueError(f"no writer for format {fmt!r}; known formats are {sorted(writers)}")
    return writers[fmt](document)


def format_for(path: str) -> str:
    lowered = path.lower()
    for suffix, fmt in ((".json", "json"), (".toml", "toml"), (".yaml", "yaml"), (".yml", "yaml")):
        if lowered.endswith(suffix):
            return fmt
    return "json"


__all__ = ["emit", "format_for", "to_json", "to_toml", "to_yaml"]
