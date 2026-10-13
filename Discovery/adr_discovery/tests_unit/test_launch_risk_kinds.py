"""Launch risk belongs to process-launching kinds only."""

from __future__ import annotations

from adr_discovery.contracts.records import Kind
from adr_discovery.pipeline import discover
from adr_discovery.reporter import to_dict

EMPTY_RISK = {
    "pinned": None,
    "factors": [],
    "credential_kinds": [],
    "env_names": [],
    "transport": None,
    "destinations": [],
    "unattended": False,
}


def test_file_shaped_assets_carry_no_launch_risk(world, catalog):
    world.dir("/Users/a")
    world.file("/Users/a/CLAUDE.md", "# rules\n")
    world.file("/Users/a/.claude/skills/s/SKILL.md", "---\nname: s\n---\nbody\n")
    world.file("/Users/a/.claude/commands/c.md", "do it\n")
    world.file("/Users/a/.claude/agents/a.md", "---\nname: a\n---\nbody\n")

    document = to_dict(discover(world.gate(), catalog))

    kinds = {"instructions", "skill", "command", "agent_definition"}
    rows = [r for r in document["assets"] if r["kind"] in kinds]
    assert {r["kind"] for r in rows} == kinds
    for row in rows:
        assert row["risk"] == EMPTY_RISK, row["kind"]


def test_mcp_servers_and_hooks_still_get_launch_risk(world, catalog):
    world.dir("/Users/a")
    world.json("/Users/a/.claude.json", {"mcpServers": {"s": {"command": "npx", "args": ["pkg"]}}})
    world.json(
        "/Users/a/.claude/settings.json",
        {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "notify"}]}]}},
    )

    snapshot = discover(world.gate(), catalog)

    for kind in (Kind.MCP_SERVER, Kind.HOOK):
        (asset,) = [a for a in snapshot.assets if a.kind is kind]
        assert asset.risk.transport == "stdio"
        assert asset.risk.credential_kinds == ("inherited",)
