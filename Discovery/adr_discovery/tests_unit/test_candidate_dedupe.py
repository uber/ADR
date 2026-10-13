"""A config file reached by two enumeration sources is read once."""

from __future__ import annotations

from adr_discovery.contracts.records import Kind
from adr_discovery.enumerator import enumerate_candidates
from adr_discovery.pipeline import discover

CLAUDE_JSON = {
    "mcpServers": {"alpha": {"command": "npx", "args": ["a"]}, "beta": {"url": "https://beta.example/mcp"}}
}


def _world(world):
    world.dir("/Users/alice")
    world.json("/Users/alice/.claude.json", CLAUDE_JSON)
    return world


def test_the_file_really_is_reached_by_both_sources(world):
    candidates = enumerate_candidates(_world(world).gate())

    sources = {c.source for c in candidates if c.path == "/Users/alice/.claude.json"}
    assert "app_state:config" in sources and "sweep" in sources


def test_one_declaration_and_one_evidence_entry_per_server(world, catalog):
    snapshot = discover(_world(world).gate(), catalog)

    servers = {a.name: a for a in snapshot.assets if a.kind is Kind.MCP_SERVER}
    assert set(servers) == {"alpha", "beta"}
    for asset in servers.values():
        paths = [e.path for e in asset.evidence if e.path.endswith(".claude.json")]
        assert paths == ["/Users/alice/.claude.json"]
        assert not any(f.startswith("merged_") for f in asset.flags)


def test_a_symlinked_alias_of_the_same_file_is_read_once(world, catalog):
    _world(world)
    world.symlink("/Users/alice/work/.mcp.json", "/Users/alice/.claude.json")

    snapshot = discover(world.gate(), catalog)

    alpha = [a for a in snapshot.assets if a.name == "alpha"]
    assert len(alpha) == 1 and len(alpha[0].evidence) == 1


def test_an_instruction_file_and_its_link_are_one_asset_named_by_the_file(world, catalog):
    """`CLAUDE.md -> AGENTS.md`: one file two agents load; the link is kept as evidence."""
    world.dir("/Users/alice")
    world.file("/Users/alice/proj/AGENTS.md", "# rules\n")
    world.symlink("/Users/alice/proj/CLAUDE.md", "/Users/alice/proj/AGENTS.md")

    snapshot = discover(world.gate(), catalog)

    (asset,) = [a for a in snapshot.assets if a.kind is Kind.INSTRUCTIONS]
    assert asset.install_path == "/Users/alice/proj/AGENTS.md"
    links = [e for e in asset.evidence if e.proof.startswith("links to")]
    assert [e.path for e in links] == ["/Users/alice/proj/CLAUDE.md"]


def test_the_link_met_first_does_not_rename_the_asset(world, catalog):
    world.dir("/Users/alice")
    world.file("/Users/alice/proj/rules.md", "# rules\n")
    # Only the link carries a marker name, so it is the only path enumerated.
    world.symlink("/Users/alice/proj/CLAUDE.md", "/Users/alice/proj/rules.md")

    (asset,) = [a for a in discover(world.gate(), catalog).assets if a.kind is Kind.INSTRUCTIONS]

    assert asset.install_path == "/Users/alice/proj/rules.md"
    assert [e.path for e in asset.evidence if e.proof.startswith("links to")] == ["/Users/alice/proj/CLAUDE.md"]
