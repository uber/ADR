"""M3 -- directory-shaped surfaces.

Skills, commands, agent definitions, output styles and plugins are files in
a structure a host application loads. They are the Skills target, and the
rule that governs them is C2: their existence and their permissions are
inventory, their prose is not.
"""

from __future__ import annotations

from adr_discovery.contracts.records import Candidate, Kind
from adr_discovery.extractor import extract

SKILL_BODY = """---
name: deploy-runbook
allowed-tools: Bash, Read
model: opus
---

# Deploy runbook

Internal: call the payments team before touching the ledger service.
"""


def read(world, path):
    return extract(world.gate(), Candidate(kind="marker_dir", path=path, source="sweep"))


def test_a_skill_directory_becomes_declarations(world):
    world.file("/Users/a/.claude/skills/deploy-runbook/SKILL.md", SKILL_BODY)
    world.file("/Users/a/.claude/skills/other/SKILL.md", "---\nname: other\n---\nbody\n")

    result = read(world, "/Users/a/.claude/skills")

    assert result.declared == 2
    assert {d.kind for d in result.declarations} == {Kind.SKILL}
    assert {d.name for d in result.declarations} == {"deploy-runbook", "other"}


def test_the_permissions_are_kept_and_the_prose_is_not(world):
    world.file("/Users/a/.claude/skills/deploy-runbook/SKILL.md", SKILL_BODY)

    (declaration,) = read(world, "/Users/a/.claude/skills").declarations

    assert declaration.raw["allowed_tools"] == ("Bash", "Read")
    assert declaration.raw["model"] == "opus"
    blob = repr(declaration)
    assert "payments team" not in blob and "ledger service" not in blob


def test_description_is_not_read_even_when_present(world):
    """The field most likely to describe what a team does is not on the
    allowlist, so it cannot reach a snapshot."""
    world.file("/Users/a/.claude/skills/s/SKILL.md",
               "---\nname: s\ndescription: reconcile the EMEA merchant ledger\n---\nbody\n")

    (declaration,) = read(world, "/Users/a/.claude/skills").declarations

    assert "EMEA" not in repr(declaration)
    assert "description" not in declaration.raw


def test_commands_and_agents_and_output_styles(world):
    world.file("/Users/a/.claude/commands/ship.md", "---\nname: ship\n---\ngo\n")
    world.file("/Users/a/.claude/agents/reviewer.md", "---\nname: reviewer\nmodel: sonnet\n---\ngo\n")
    world.file("/Users/a/.claude/output-styles/terse.md", "---\nname: terse\n---\ngo\n")

    kinds = {}
    for surface in ("commands", "agents", "output-styles"):
        result = read(world, f"/Users/a/.claude/{surface}")
        assert result.declared == 1, surface
        kinds[surface] = result.declarations[0].kind

    assert kinds == {"commands": Kind.COMMAND, "agents": Kind.AGENT_DEFINITION,
                     "output-styles": Kind.OUTPUT_STYLE}


def test_one_broken_skill_does_not_remove_its_siblings(world):
    world.file("/Users/a/.claude/skills/good/SKILL.md", "---\nname: good\n---\nbody\n")
    world.dir("/Users/a/.claude/skills/empty")          # no SKILL.md at all
    world.file("/Users/a/.claude/skills/bad/SKILL.md", "---\nname: &anchor\n---\nbody\n")

    result = read(world, "/Users/a/.claude/skills")

    assert result.declared == 3
    assert len(result.declarations) == 1
    assert len(result.errors) == 2


def test_a_file_without_frontmatter_still_counts(world):
    """A command that is plain markdown is still a command."""
    world.file("/Users/a/.claude/commands/bare.md", "just prose, no frontmatter\n")

    (declaration,) = read(world, "/Users/a/.claude/commands").declarations

    assert declaration.name == "bare"
    assert declaration.raw["allowed_tools"] == ()


def test_a_repository_marker_declares_nothing(world):
    """`.git` locates a repository. It is not a surface with records."""
    world.dir("/Users/a/proj/.git")

    result = read(world, "/Users/a/proj/.git")

    assert result.declared == 0 and result.declarations == ()
