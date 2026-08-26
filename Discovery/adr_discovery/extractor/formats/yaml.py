"""A YAML subset that refuses rather than guesses.

The last hand-rolled parser standing, written to fail in the only honest
direction: a construct outside the subset raises, so the record becomes a
recorded error instead of a plausible wrong value. Silent mis-parsing of
structured input produced every production defect in the last two review
rounds, and a subset parser that guesses is precisely that engine.

Supported  nested mappings by indentation, block sequences of scalars and
           of mappings, quoted and bare scalars, booleans, integers,
           floats, null, `#` comments
Refused    anchors, aliases, tags, flow collections, multi-line scalars,
           multiple documents, merge keys
"""

from __future__ import annotations

REFUSED_PREFIXES = ("&", "*", "!", "<<", "---", "...")
REFUSED_CHARS = ("{", "[")


class Unrepresentable(ValueError):
    """Outside the subset. Never mis-parse it instead."""


def loads(text: str) -> dict:
    lines: list[tuple[int, int, str]] = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split(" #", 1)[0].rstrip() if " #" in raw else raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        lines.append((lineno, len(line) - len(line.lstrip()), line.strip()))

    value, consumed = _block(lines, 0, lines[0][1] if lines else 0)
    if consumed != len(lines):
        raise Unrepresentable(f"line {lines[consumed][0]}: indentation does not resolve")
    return value if isinstance(value, dict) else {"": value}


def _block(lines, i: int, indent: int):
    """Parse every line at `indent`, returning the value and lines consumed."""
    if i < len(lines) and lines[i][2].startswith("- "):
        return _sequence(lines, i, indent)
    return _mapping(lines, i, indent)


def _sequence(lines, i: int, indent: int):
    """Block sequence. An item is a scalar, or a mapping introduced on the
    dash line and continued at the column just past it."""
    out: list = []
    while i < len(lines) and lines[i][1] == indent and lines[i][2].startswith("- "):
        lineno, _, body = lines[i]
        rest = body[2:].strip()
        i += 1

        if ":" not in rest:
            out.append(_scalar(rest, lineno))
            continue

        # `- uses: x` opens a mapping whose first key sits two columns in.
        item_indent = indent + 2
        block = [(lineno, item_indent, rest)]
        while i < len(lines) and lines[i][1] > indent:
            block.append(lines[i])
            i += 1
        value, consumed = _mapping(block, 0, item_indent)
        if consumed != len(block):
            raise Unrepresentable(f"line {block[consumed][0]}: indentation does not resolve")
        out.append(value)
    return out, i


def _mapping(lines, i: int, indent: int):
    out: dict = {}
    while i < len(lines):
        lineno, depth, body = lines[i]
        if depth < indent:
            break
        if depth > indent:
            raise Unrepresentable(f"line {lineno}: unexpected indentation")
        _guard(body, lineno)
        if ":" not in body:
            raise Unrepresentable(f"line {lineno}: not a mapping entry")
        key, _, rest = body.partition(":")
        key, rest = key.strip(), rest.strip()
        i += 1
        if rest:
            out[key] = _scalar(rest, lineno)
            continue
        if i < len(lines) and lines[i][1] > indent:
            out[key], i = _block(lines, i, lines[i][1])
        else:
            out[key] = None
    return out, i


def _guard(body: str, lineno: int) -> None:
    if body.startswith(REFUSED_PREFIXES):
        raise Unrepresentable(f"line {lineno}: construct outside the supported subset")
    tail = body.split(":", 1)[-1]
    if any(c in tail for c in REFUSED_CHARS):
        raise Unrepresentable(f"line {lineno}: flow collection outside the supported subset")


def _scalar(token: str, lineno: int):
    if token.startswith(REFUSED_PREFIXES) or any(c in token for c in REFUSED_CHARS):
        raise Unrepresentable(f"line {lineno}: scalar outside the supported subset")
    if len(token) >= 2 and token[0] == token[-1] and token[0] in "\"'":
        return token[1:-1]
    low = token.lower()
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    if low in ("null", "~", ""):
        return None
    try:
        return int(token)
    except ValueError:
        pass
    try:
        return float(token)
    except ValueError:
        return token
