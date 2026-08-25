"""The composition root, end to end over a fixture world.

These assert on the seams the per-module cases cannot see: that a
declaration and the process running it become one asset, that an
instruction file never becomes one, and that the snapshot's coverage
accounts for what the scan could not reach.
"""

from __future__ import annotations

import json

from adr_discovery.contracts.records import Kind, Liveness
from adr_discovery.judge import Policy
from adr_discovery.pipeline import discover
from adr_discovery.reporter import stats, to_json


def endpoint(world):
    world.dir("/Users/alice")
    world.exe("/opt/homebrew/bin/claude", "2.1.234")
    world.file("/Users/alice/.claude/settings.json", "{}")
    world.json("/Users/alice/work/proj/.mcp.json", {"mcpServers": {
        "github": {"command": "npx", "args": ["-y", "server-github"]},
        "files": {"command": "npx", "args": ["-y", "@mcp/server-filesystem@1.4.2"]},
        "legacy": {"url": "http://legacy.example.com/sse"},
        "broken": "not a mapping",
    }})
    world.file("/Users/alice/work/proj/CLAUDE.md", "# steering prose")
    world.surface("packages", [{"manager": "npm", "name": "@anthropic-ai/claude-code",
                                "version": "2.1.234", "path": "/opt/homebrew/bin/claude"}])
    world.surface("processes", [{"pid": 900, "exe": "/opt/homebrew/bin/claude",
                                 "argv": ["claude", "-p"], "ppid": 1, "user": "alice"}])
    return world


def test_a_binary_and_the_process_running_it_are_one_asset(world, catalog):
    snapshot = discover(endpoint(world).gate(), catalog)

    agents = [a for a in snapshot.assets if a.kind is Kind.CLI_AGENT]

    assert len(agents) == 1, "the false split M5 exists to stop"
    assert agents[0].liveness is Liveness.RUNNING
    assert agents[0].version == "2.1.234"


def test_an_instruction_file_becomes_inventory_without_collecting_its_body(world, catalog):
    snapshot = discover(endpoint(world).gate(), catalog)

    instructions = [a for a in snapshot.assets if a.kind is Kind.INSTRUCTIONS]
    assert [a.install_path for a in instructions] == ["/Users/alice/work/proj/CLAUDE.md"]
    assert "steering prose" not in to_json(snapshot)


def test_a_malformed_record_does_not_remove_its_siblings(world, catalog):
    snapshot = discover(endpoint(world).gate(), catalog)

    servers = {a.name for a in snapshot.assets if a.kind is Kind.MCP_SERVER}

    assert servers == {"github", "files", "legacy"}


def test_findings_are_narrow(world, catalog):
    snapshot = discover(endpoint(world).gate(), catalog, Policy())

    rules = sorted(f.rule for f in snapshot.findings)

    assert rules == ["plaintext_transport", "unpinned_mcp_server"]
    assert all(f.asset_id for f in snapshot.findings)


def test_the_snapshot_carries_its_coverage(world, catalog):
    gate = endpoint(world).gate()

    snapshot = discover(gate, catalog)

    assert not snapshot.coverage.is_complete, "surfaces this fixture cannot supply must be named"
    assert "exec_journal" in [u.provider for u in snapshot.coverage.unavailable]
    assert snapshot.coverage.out_of_scope


def test_an_empty_world_still_produces_a_snapshot(world, catalog):
    snapshot = discover(world.gate(), catalog, hostname="clean-host")

    assert snapshot.assets == ()
    assert snapshot.hostname == "clean-host"
    assert json.loads(to_json(snapshot))["coverage"]["out_of_scope"]
    assert stats(snapshot)["asset_count"] == 0
