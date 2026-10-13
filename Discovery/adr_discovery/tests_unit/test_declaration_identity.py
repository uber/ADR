"""Declarations are identified by what they are and where they sit, not by name."""

from __future__ import annotations

import json

from adr_discovery.contracts.records import Kind
from adr_discovery.pipeline import discover
from adr_discovery.reporter import to_json
from adr_discovery.reporter.snapshot import from_dict


def _of(snapshot, kind):
    return [a for a in snapshot.assets if a.kind is kind]


def test_two_instruction_files_are_two_assets(world, catalog):
    world.dir("/Users/a")
    world.file("/Users/a/proj1/CLAUDE.md", "# one\n")
    world.file("/Users/a/proj2/CLAUDE.md", "# two\n")

    found = _of(discover(world.gate(), catalog), Kind.INSTRUCTIONS)

    assert {a.install_path for a in found} == {
        "/Users/a/proj1/CLAUDE.md",
        "/Users/a/proj2/CLAUDE.md",
    }
    assert len({a.asset_id for a in found}) == 2


def test_same_named_skills_in_different_plugins_are_two_assets(world, catalog):
    world.dir("/Users/a")
    for plugin in ("p1", "p2"):
        world.file(
            f"/Users/a/.claude/plugins/{plugin}/skills/index/SKILL.md",
            f"---\nname: index\ndescription: {plugin}\n---\nbody\n",
        )

    skills = [a for a in _of(discover(world.gate(), catalog), Kind.SKILL) if a.name == "index"]

    assert len(skills) == 2
    assert len({a.asset_id for a in skills}) == 2
    assert len({a.install_path for a in skills}) == 2


def test_same_mcp_name_in_two_configs_is_two_assets_each_with_its_own_risk(world, catalog):
    world.dir("/Users/a")
    world.json(
        "/Users/a/.claude.json", {"mcpServers": {"shared": {"command": "npx", "args": ["-y", "pkg@1.2.3"]}}}
    )
    world.json(
        "/Users/a/proj/.mcp.json", {"mcpServers": {"shared": {"command": "npx", "args": ["-y", "pkg"]}}}
    )

    servers = [a for a in _of(discover(world.gate(), catalog), Kind.MCP_SERVER) if a.name == "shared"]

    assert len(servers) == 2
    by_path = {a.install_path: a for a in servers}
    assert by_path["/Users/a/.claude.json"].risk.pinned is True
    assert by_path["/Users/a/proj/.mcp.json"].risk.pinned is False


def test_rescan_gives_identical_asset_ids(world, catalog):
    world.dir("/Users/a")
    world.file("/Users/a/proj1/CLAUDE.md", "# one\n")
    world.file("/Users/a/proj2/CLAUDE.md", "# two\n")
    world.file("/Users/a/.claude/skills/index/SKILL.md", "---\nname: index\n---\nbody\n")
    world.json("/Users/a/.claude.json", {"mcpServers": {"s": {"command": "x"}}})

    first = discover(world.gate(), catalog)
    second = discover(world.gate(), catalog)

    assert sorted(a.asset_id for a in first.assets) == sorted(a.asset_id for a in second.assets)
    assert len(first.assets) == len({a.asset_id for a in first.assets})


def test_version_change_does_not_change_the_asset_id(world, catalog):
    world.dir("/Users/a")
    world.file("/Users/a/.claude/plugins/p/plugin.json", json.dumps({"name": "p", "version": "1"}))
    first = discover(world.gate(), catalog)
    world.file("/Users/a/.claude/plugins/p/plugin.json", json.dumps({"name": "p", "version": "2"}))
    second = discover(world.gate(), catalog)

    assert {a.asset_id for a in _of(first, Kind.PLUGIN)} == {a.asset_id for a in _of(second, Kind.PLUGIN)}


def test_ci_agents_in_two_jobs_are_two_assets(world, catalog):
    workflow = """on: push
jobs:
  one:
    steps:
      - uses: anthropics/claude-code-action@v1
  two:
    steps:
      - uses: anthropics/claude-code-action@v1
"""
    world.dir("/Users/a")
    world.file("/Users/a/proj/.github/workflows/ci.yml", workflow)

    agents = _of(discover(world.gate(), catalog), Kind.CI_AGENT)

    assert len(agents) == 2


def test_schema_version_is_bumped_and_round_trips(world, catalog):
    snapshot = discover(world.gate(), catalog)

    assert snapshot.schema_version == "1.1"
    assert from_dict(json.loads(to_json(snapshot))).schema_version == "1.1"
