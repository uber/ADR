"""Ordinary YAML in frontmatter must not cost the record."""

from __future__ import annotations

import pytest

from adr_discovery.extractor.formats.frontmatter import (
    NoFrontmatter,
    Unrepresentable,
    parse,
    parse_with_notes,
)


def fm(*lines, eol="\n"):
    return eol.join(["---", *lines, "---", "body that must never be returned"]) + eol


def test_block_scalar_description_is_skipped_and_allowlisted_keys_survive():
    text = fm(
        "name: terse", "description: |", "  Speak tersely.", "  Second line: with colon.", "model: sonnet"
    )

    values, skipped = parse_with_notes(text)

    assert values == {"name": "terse", "model": "sonnet"}
    assert skipped == ("description",)


def test_folded_description_is_skipped():
    values, skipped = parse_with_notes(fm("description: >-", "  folded", "  text", "", "  more", "name: x"))

    assert values == {"name": "x"} and skipped == ("description",)


@pytest.mark.parametrize(
    "line", ["tools: [Read, Write]", "allowed-tools: [Read, Write]", "allowed_tools: [ Read ,Write ]"]
)
def test_flow_list_of_scalars(line):
    (value,) = parse(fm(line)).values()

    assert value == ["Read", "Write"]


def test_flow_list_with_quoted_patterns_and_colons():
    values = parse(fm("allowed-tools: [\"Bash(git:*)\", Read, 'Edit']"))

    assert values["allowed-tools"] == ["Bash(git:*)", "Read", "Edit"]


def test_flow_list_spanning_lines():
    values = parse(fm("tools: [Read,", "  Write,", "  Grep]"))

    assert values["tools"] == ["Read", "Write", "Grep"]


@pytest.mark.parametrize("indent", ["  ", ""])
def test_block_list(indent):
    values = parse(
        fm(
            "tools:",
            f"{indent}- Read",
            f"{indent}- Bash(git:*)",
            f"{indent}# note",
            f"{indent}- 'Write'",
            "name: n",
        )
    )

    assert values == {"tools": ["Read", "Bash(git:*)", "Write"], "name": "n"}


def test_block_scalar_for_an_allowlisted_key_is_consumed_not_failed():
    values = parse(fm("name: >", "  folded", "  name", "tools: |", "  Read", "  Write"))

    assert values == {"name": "folded name", "tools": ["Read", "Write"]}


def test_quoted_strings_with_colons_and_hashes():
    values = parse(fm('name: "a: b # not a comment"', "model: 'x:y'  # trailing comment"))

    assert values == {"name": "a: b # not a comment", "model": "x:y"}


def test_comments_and_blank_lines():
    values = parse(fm("# leading", "", "name: n  # why", "tools: Read, Write # inline"))

    assert values == {"name": "n", "tools": "Read, Write"}


def test_crlf_line_endings():
    text = fm("name: n", "tools: [Read, Write]", "description: |", "  hi", eol="\r\n")

    assert parse(text) == {"name": "n", "tools": ["Read", "Write"]}


def test_nested_map_and_anchor_on_other_keys_are_skipped():
    values, skipped = parse_with_notes(
        fm("metadata:", "  author: me", "  tags: [a, b]", "base: &anchor", "  x: 1", "name: n")
    )

    assert values == {"name": "n"}
    assert skipped == ("metadata", "base")


def test_an_anchor_on_an_allowlisted_key_still_fails():
    with pytest.raises(Unrepresentable):
        parse(fm("name: &anchor"))


def test_a_long_description_does_not_push_the_closing_delimiter_out():
    text = fm("name: n", "description: |", *[f"  line {i}" for i in range(120)], "model: m")

    assert parse(text) == {"name": "n", "model": "m"}


def test_an_unclosed_block_fails_and_the_byte_cap_holds():
    with pytest.raises(Unrepresentable):
        parse("---\nname: n\n" + "x: y\n" * 400)
    with pytest.raises(Unrepresentable):
        parse(fm("name: n", "description: |", *["  " + "x" * 1000] * 80))


def test_bodies_and_descriptions_are_never_returned():
    values = parse(fm("description: |", "  SECRET business context", "name: n"))

    assert "SECRET" not in repr(values) and "body that must" not in repr(values)


def test_no_frontmatter_is_still_reported():
    with pytest.raises(NoFrontmatter):
        parse("just prose\n")


def test_a_skill_with_a_block_scalar_description_is_a_declaration(world):
    from adr_discovery.contracts.records import Candidate
    from adr_discovery.extractor import extract

    world.file(
        "/Users/a/.claude/skills/s/SKILL.md",
        fm("name: s", "description: |", "  anything", "allowed-tools:", "  - Read", "  - Write"),
    )
    world.file("/Users/a/.claude/agents/a.md", fm("name: a", "tools: [Read, Grep]", "description: >", "  x"))

    skill = extract(world.gate(), Candidate("marker_dir", "/Users/a/.claude/skills", "sweep"))
    agent = extract(world.gate(), Candidate("marker_dir", "/Users/a/.claude/agents", "sweep"))

    assert skill.errors == () and agent.errors == ()
    assert skill.declarations[0].raw["allowed_tools"] == ("Read", "Write")
    assert agent.declarations[0].raw["allowed_tools"] == ("Read", "Grep")


def test_skipped_keys_become_a_coverage_note_not_an_error(world):
    from adr_discovery.contracts.records import Candidate
    from adr_discovery.extractor import extract

    world.file("/Users/a/.claude/commands/c.md", fm("name: c", "description: |", "  long"))
    gate = world.gate()

    result = extract(gate, Candidate("marker_dir", "/Users/a/.claude/commands", "sweep"))

    assert result.errors == () and len(result.declarations) == 1
    probes = [p for p in gate.ledger.freeze().probes if p.name == "frontmatter"]
    assert len(probes) == 1 and probes[0].status == "ran" and "description" in probes[0].detail
