"""YAML frontmatter, read under an allowlist.

A skill file is two things stacked: a small block of operational metadata,
and a body of prose that tells an agent what to do. The body is business
context and C2 forbids reading it, so this parser stops at the closing
delimiter and never returns what follows.

The key allowlist is the second half of the same rule. `description` is
deliberately absent: it is the field most likely to describe what a team
does, and knowing a skill exists and what it is permitted to touch is the
whole of what an inventory needs.

Real-world frontmatter is ordinary YAML, and most of it is in keys this
parser has no business reading (`description: |` followed by a paragraph,
nested maps, anchors). So the file is first split into top-level entries
without interpreting any value; only allowlisted entries are then parsed,
and everything else is skipped whole. An allowlisted key whose value is
outside what is supported still raises, so a wrong value is never reported.
"""

from __future__ import annotations

import re

from .yaml import Unrepresentable, typed_scalar

DELIMITER = "---"
#: Long multi-line descriptions push the closing delimiter well past the
#: first screen; the byte cap, not this, bounds the cost of reading one.
MAX_FRONTMATTER_LINES = 200
MAX_FRONTMATTER_BYTES = 64 * 1024

#: Operational metadata only. Anything not named here is not read.
ALLOWED_KEYS: frozenset[str] = frozenset(
    {"name", "model", "allowed-tools", "allowed_tools", "tools",
     "disable-model-invocation", "argument-hint", "version", "kind"}
)

#: Keys whose value is a list of tool names.
LIST_KEYS: frozenset[str] = frozenset({"allowed-tools", "allowed_tools", "tools"})

_KEY = re.compile(r"""^(?P<key>"[^"]*"|'[^']*'|[^\s:#'"-][^:]*?)\s*:(?:\s+(?P<rest>.*))?$""")
_BLOCK_SCALAR = re.compile(r"^([|>])[0-9+-]*\s*(?:#.*)?$")
_UNREADABLE_START = ("&", "*", "!", "<<")


class NoFrontmatter(ValueError):
    """The file does not open with a frontmatter block."""


def parse(text: str) -> dict:
    """Return the allowlisted keys, and nothing else."""
    return parse_with_notes(text)[0]


def parse_with_notes(text: str) -> tuple[dict, tuple[str, ...]]:
    """The allowlisted keys, plus the names of keys skipped as unreadable.

    Raises for a block that never closes or an allowlisted key whose value
    cannot be represented, so a failure is a recorded error and not a wrong
    value. A skipped key is a note, never an error.
    """
    lines = text.lstrip("﻿").splitlines()
    if not lines or lines[0].strip() != DELIMITER:
        raise NoFrontmatter("file does not open with a frontmatter delimiter")

    block: list[str] = []
    size = 0
    for line in lines[1 : MAX_FRONTMATTER_LINES + 1]:
        if line.rstrip() == DELIMITER:
            return _read(block)
        size += len(line) + 1
        if size > MAX_FRONTMATTER_BYTES:
            raise Unrepresentable(f"frontmatter larger than {MAX_FRONTMATTER_BYTES} bytes")
        block.append(line)

    raise Unrepresentable(f"frontmatter not closed within {MAX_FRONTMATTER_LINES} lines")


def _entries(block: list[str]) -> list[tuple[str | None, str, list[str]]]:
    """Top-level (key, inline value, continuation lines); no value is read.

    A line that is not a key at column 0 and not a continuation is junk and
    comes back with key None.
    """
    out: list[tuple[str | None, str, list[str]]] = []
    for line in block:
        stripped = line.strip()
        indented = line[:1] in (" ", "\t")
        if not stripped:
            if out:
                out[-1][2].append("")
            continue
        if indented or stripped == "-" or stripped.startswith("- "):
            if out:
                out[-1][2].append(line)
            continue
        if stripped.startswith("#"):
            continue
        match = _KEY.match(line.rstrip())
        if match is None:
            out.append((None, stripped, []))
            continue
        key = match.group("key").strip()
        if key[:1] in "\"'" and key[-1:] == key[:1]:
            key = key[1:-1]
        out.append((key, _strip_comment(match.group("rest") or ""), []))
    return out


def _read(block: list[str]) -> tuple[dict, tuple[str, ...]]:
    values: dict[str, object] = {}
    skipped: list[str] = []
    for key, rest, continuation in _entries(block):
        if key is None:
            skipped.append("<unparseable line>")
            continue
        if key not in ALLOWED_KEYS:
            if _is_complex(rest, continuation):
                skipped.append(key)
            continue
        value = _value(key, rest, continuation)
        if value is _SKIP:
            skipped.append(key)
        else:
            values[key] = value
    return values, tuple(skipped)


_SKIP = object()


def _is_complex(rest: str, continuation: list[str]) -> bool:
    return any(line.strip() for line in continuation) or rest[:1] in ("|", ">", "&", "*", "!", "[", "{")


def _value(key: str, rest: str, continuation: list[str]):
    content = [line for line in continuation if line.strip()]
    is_list = key in LIST_KEYS

    block_scalar = _BLOCK_SCALAR.match(rest)
    if block_scalar:
        # Consumed whole; lines past the header are the body of the scalar.
        parts = [line.strip() for line in content]
        return _scalar_or_list(parts, is_list, joiner=", " if is_list else " ")
    if rest[:1] in ("|", ">"):
        raise Unrepresentable(f"{key}: malformed block scalar header")

    if rest[:1] in _UNREADABLE_START or rest.startswith(_UNREADABLE_START):
        raise Unrepresentable(f"{key}: anchor, alias or tag outside the supported subset")

    if rest[:1] == "[":
        text = " ".join([rest, *(_strip_comment(line.strip()) for line in content)])
        items = _flow_items(key, text)
        return items if is_list else _SKIP

    if rest[:1] == "{":
        if is_list:
            raise Unrepresentable(f"{key}: flow mapping where a list belongs")
        return _SKIP

    if not rest:
        if not content:
            return None
        items = _block_items(key, content)
        if items is None:
            if is_list:
                raise Unrepresentable(f"{key}: nested mapping where a list belongs")
            return _SKIP
        return items if is_list else _SKIP

    # A plain or quoted scalar, possibly continued on the following lines.
    text = " ".join([rest, *(_strip_comment(line.strip()) for line in content if not line.strip().startswith("#"))])
    return typed_scalar(text.strip())


def _scalar_or_list(parts: list[str], is_list: bool, joiner: str):
    text = joiner.join(part for part in parts if part)
    if is_list:
        return [item.strip() for item in text.split(",") if item.strip()]
    return text or None


def _block_items(key: str, content: list[str]) -> list[str] | None:
    """`- item` lines. None when the block is not a sequence of scalars."""
    items: list[str] = []
    for line in content:
        stripped = _strip_comment(line.strip())
        if not stripped:
            continue
        if stripped == "-":
            continue
        if not stripped.startswith("- "):
            return None
        item = stripped[2:].strip()
        if item[:1] in _UNREADABLE_START or item.startswith(_UNREADABLE_START):
            raise Unrepresentable(f"{key}: anchor, alias or tag in list")
        if item[:1] in ("[", "{") or re.match(r"""^[^'"\[{(]*?:(\s|$)""", item):
            return None
        items.append(str(typed_scalar(item)))
    return items


def _flow_items(key: str, text: str) -> list[str]:
    """`[a, "b", c(d:*)]` -> items. Nested collections are refused."""
    text = text.strip()
    if not text.endswith("]"):
        raise Unrepresentable(f"{key}: unterminated flow list")
    inner = text[1:-1]
    items: list[str] = []
    buf: list[str] = []
    quote = ""
    depth = 0
    for ch in inner:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = ""
            continue
        if ch in "\"'":
            quote = ch
        elif ch in "[{":
            raise Unrepresentable(f"{key}: nested collection in flow list")
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            items.append("".join(buf))
            buf = []
            continue
        buf.append(ch)
    if quote:
        raise Unrepresentable(f"{key}: unterminated quote in flow list")
    items.append("".join(buf))
    out = []
    for item in items:
        item = item.strip()
        if item[:1] in _UNREADABLE_START:
            raise Unrepresentable(f"{key}: anchor, alias or tag in flow list")
        if item:
            out.append(str(typed_scalar(item)))
    return out


def _strip_comment(text: str) -> str:
    """Drop a trailing ` # comment` that sits outside quotes."""
    quote = ""
    for index, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = ""
        elif ch in "\"'" and (index == 0 or text[index - 1] in " \t[,("):
            quote = ch
        elif ch == "#" and (index == 0 or text[index - 1] in " \t"):
            return text[:index].rstrip()
    return text.strip()
