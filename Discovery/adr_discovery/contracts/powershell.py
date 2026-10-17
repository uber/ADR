"""A deliberately small read-only profile recognizer, never a PS evaluator."""

from __future__ import annotations

import re

_ASSIGNMENT = re.compile(r"^\s*\$env:([A-Za-z_][A-Za-z0-9_]*)\s*=", re.I)


def environment_names(text: str) -> tuple[str, ...]:
    """Direct $env:NAME assignments outside comments and multiline strings.

    Dynamic names, expressions and SetEnvironmentVariable are not evaluated.
    Right-hand sides are inspected only for lexical boundaries, never kept.
    """
    names: set[str] = set()
    block = 0
    quote = ""
    here = ""
    for line in text.splitlines():
        if here:
            if line.startswith(here + "@"):
                here = ""
            continue
        if not block and not quote:
            match = _ASSIGNMENT.match(line)
            if match:
                names.add(match.group(1).upper())
        i = 0
        while i < len(line):
            pair = line[i:i + 2]
            char = line[i]
            if block:
                if pair == "<#":
                    block += 1
                    i += 2
                elif pair == "#>":
                    block -= 1
                    i += 2
                else:
                    i += 1
            elif quote:
                if char == "`" and quote == '"':
                    i += 2
                elif char == quote:
                    if i + 1 < len(line) and line[i + 1] == quote:
                        i += 2
                    else:
                        quote = ""
                        i += 1
                else:
                    i += 1
            elif pair == "<#":
                block = 1
                i += 2
            elif char == "#":
                break
            elif pair in ('@"', "@'") and not line[i + 2:].strip():
                here = pair[1]
                break
            elif char in "\"'":
                quote = char
                i += 1
            elif char == "`":
                i += 2
            else:
                i += 1
    return tuple(sorted(names))
