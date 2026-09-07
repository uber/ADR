"""YAML frontmatter, read under an allowlist.

A skill file is two things stacked: a small block of operational metadata,
and a body of prose that tells an agent what to do. The body is business
context and C2 forbids reading it, so this parser stops at the closing
delimiter and never returns what follows.

The key allowlist is the second half of the same rule. `description` is
deliberately absent: it is the field most likely to describe what a team
does, and knowing a skill exists and what it is permitted to touch is the
whole of what an inventory needs.
"""

from __future__ import annotations

from .yaml import Unrepresentable, loads

DELIMITER = "---"
MAX_FRONTMATTER_LINES = 60

#: Operational metadata only. Anything not named here is not read.
ALLOWED_KEYS: frozenset[str] = frozenset(
    {"name", "model", "allowed-tools", "allowed_tools", "tools",
     "disable-model-invocation", "argument-hint", "version", "kind"}
)


class NoFrontmatter(ValueError):
    """The file does not open with a frontmatter block."""


def parse(text: str) -> dict:
    """Return the allowlisted keys, and nothing else.

    Raises rather than guessing, so a file whose frontmatter cannot be
    represented becomes a recorded error instead of a wrong value.
    """
    lines = text.splitlines()
    if not lines or lines[0].strip() != DELIMITER:
        raise NoFrontmatter("file does not open with a frontmatter delimiter")

    block: list[str] = []
    for line in lines[1 : MAX_FRONTMATTER_LINES + 1]:
        if line.strip() == DELIMITER:
            document = loads("\n".join(block))
            return {k: v for k, v in document.items() if k in ALLOWED_KEYS}
        block.append(line)

    raise Unrepresentable(
        f"frontmatter not closed within {MAX_FRONTMATTER_LINES} lines"
    )
