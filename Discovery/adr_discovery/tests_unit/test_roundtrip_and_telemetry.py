"""Reading a snapshot back, and the one signal an endpoint cannot produce.

The delta is the product, so a snapshot that can only be written is a
snapshot that can only be filed away. And `last_used` is the join that
turns a configured-but-never-invoked server from a threat into a cleanup
candidate -- it comes from session telemetry, not from the filesystem.
"""

from __future__ import annotations

import json

from adr_discovery.contracts.records import Kind, Liveness
from adr_discovery.pipeline import discover
from adr_discovery.reporter import diff, from_dict, to_json


def endpoint(world):
    world.dir("/Users/alice")
    world.binary("/opt/homebrew/bin/claude", "#!/bin/sh\necho 2.1.234\n")
    world.surface("packages", [{"manager": "npm", "name": "@anthropic-ai/claude-code",
                                "version": "2.1.234", "path": "/opt/homebrew/bin/claude"}])
    world.json("/Users/alice/proj/.mcp.json", {"mcpServers": {
        "github": {"command": "npx", "args": ["-y", "server-github"]}}})
    return world


def test_a_snapshot_survives_the_round_trip(world, catalog):
    original = discover(endpoint(world).gate(), catalog, hostname="host-a")

    restored = from_dict(json.loads(to_json(original)))

    assert restored.hostname == original.hostname
    assert len(restored.assets) == len(original.assets)
    assert {a.asset_id for a in restored.assets} == {a.asset_id for a in original.assets}
    assert {a.kind for a in restored.assets} == {a.kind for a in original.assets}
    assert restored.coverage.out_of_scope == original.coverage.out_of_scope


def test_a_round_tripped_snapshot_diffs_cleanly_against_itself(world, catalog):
    """Two scans of an unchanged machine must produce no delta, which is a
    statement about `asset_id` holding still through serialization."""
    original = discover(endpoint(world).gate(), catalog, hostname="host-a")
    restored = from_dict(json.loads(to_json(original)))

    delta = diff(restored, original)

    assert delta.is_empty, [c.kind for c in delta.changes]


def test_a_real_change_survives_serialization(world, catalog):
    before = discover(endpoint(world).gate(), catalog, hostname="host-a")
    world.binary("/opt/homebrew/bin/claude", "#!/bin/sh\necho 2.2.0\n")
    world.surface("packages", [{"manager": "npm", "name": "@anthropic-ai/claude-code",
                                "version": "2.2.0", "path": "/opt/homebrew/bin/claude"}])
    after = discover(world.gate(), catalog, hostname="host-a")

    delta = diff(from_dict(json.loads(to_json(before))), after)

    assert [c.kind for c in delta.of("version_changed")] == ["version_changed"]
    assert delta.of("appeared") == () and delta.of("disappeared") == ()


def test_telemetry_supplies_last_used(world, catalog):
    snapshot = discover(endpoint(world).gate(), catalog,
                        telemetry={"claude-code": "2026-08-21T09:12:00+00:00"})

    (agent,) = [a for a in snapshot.assets if a.kind is Kind.CLI_AGENT]
    assert agent.last_used == "2026-08-21T09:12:00+00:00"


def test_configured_but_never_invoked_stays_distinct(world, catalog):
    """A declared server with no telemetry is a cleanup candidate, not a
    threat -- and the two must not look the same in a snapshot."""
    snapshot = discover(endpoint(world).gate(), catalog,
                        telemetry={"claude-code": "2026-08-21T09:12:00+00:00"})

    (server,) = [a for a in snapshot.assets if a.kind is Kind.MCP_SERVER]
    assert server.liveness is Liveness.DECLARED_ONLY
    assert server.last_used is None
