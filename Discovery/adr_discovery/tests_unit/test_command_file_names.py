"""A command file is named by its stem, whatever its suffix.

Gemini CLI loads `commands/review.toml` as `/review`, exactly as Claude
Code loads `commands/review.md`.
"""

from __future__ import annotations

from adr_discovery.contracts.records import Candidate, Kind
from adr_discovery.extractor import extract


def test_toml_and_markdown_commands_are_named_by_stem(world):
    world.file("/Users/a/.gemini/commands/review.toml", 'description = "x"\nprompt = "y"\n')
    world.file("/Users/a/.gemini/commands/deploy.md", "body")

    result = extract(world.gate(), Candidate("marker_dir", "/Users/a/.gemini/commands", "sweep"))

    assert {d.kind for d in result.declarations} == {Kind.COMMAND}
    assert sorted(d.name for d in result.declarations) == ["deploy", "review"]
