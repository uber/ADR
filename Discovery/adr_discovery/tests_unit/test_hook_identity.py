"""Hook identity is stable under insertion; event and matcher are emitted."""

from __future__ import annotations

import json

from adr_discovery.contracts.records import Kind
from adr_discovery.pipeline import discover
from adr_discovery.reporter import to_dict, to_json
from adr_discovery.reporter.snapshot import from_dict

SETTINGS = "/Users/a/.claude/settings.json"


def _hooks(*entries):
    """entries: (event, matcher, command)"""
    grouped: dict = {}
    for event, matcher, command in entries:
        grouped.setdefault(event, []).append(
            {"matcher": matcher, "hooks": [{"type": "command", "command": command}]}
        )
    return {"hooks": grouped}


def _scan(world, catalog, *entries):
    world.dir("/Users/a")
    world.json(SETTINGS, _hooks(*entries))
    snapshot = discover(world.gate(), catalog)
    return snapshot, [a for a in snapshot.assets if a.kind is Kind.HOOK]


BASE = [
    ("PreToolUse", "Bash", "audit --event pre"),
    ("PostToolUse", "Edit|Write", "fmt --check"),
    ("Stop", None, "notify done"),
]


def test_inserting_a_hook_does_not_change_the_others(world, catalog, tmp_path):
    _, before = _scan(world, catalog, *BASE)
    ids = {a.name: a.asset_id for a in before}

    _, after = _scan(world, catalog, ("PreToolUse", "Bash", "new-first-hook"), *BASE)

    assert len(after) == 4
    for name, asset_id in ids.items():
        assert {a.name: a.asset_id for a in after}[name] == asset_id


def test_hooks_with_distinct_commands_are_distinct_assets(world, catalog):
    _, hooks = _scan(world, catalog, ("PreToolUse", "Bash", "a"), ("PreToolUse", "Bash", "b"))

    assert len({a.asset_id for a in hooks}) == 2
    assert len({a.name for a in hooks}) == 2


def test_the_name_is_readable_and_the_identity_is_path_prefixed(world, catalog):
    _, hooks = _scan(world, catalog, ("PostToolUse", "Edit|Write", "fmt --check"))

    (hook,) = hooks
    assert hook.name.startswith("PostToolUse hook [Edit|Write] ")
    assert hook.identity.startswith(f"hook:{SETTINGS}:")


def test_event_and_matcher_are_in_the_snapshot_and_the_command_is_not(world, catalog):
    snapshot, hooks = _scan(world, catalog, *BASE)

    document = to_dict(snapshot)
    rows = {r["hook_event"]: r for r in document["assets"] if r["kind"] == "hook"}
    assert rows["PreToolUse"]["hook_matcher"] == "Bash"
    assert rows["PostToolUse"]["hook_matcher"] == "Edit|Write"
    assert rows["Stop"]["hook_matcher"] is None
    blob = to_json(snapshot)
    assert "audit --event pre" not in blob and "notify done" not in blob


def test_round_trip_keeps_event_and_matcher(world, catalog):
    snapshot, _ = _scan(world, catalog, *BASE)

    again = from_dict(json.loads(to_json(snapshot)))

    assert again.assets == snapshot.assets


def test_non_hooks_carry_no_hook_fields(world, catalog):
    world.dir("/Users/a")
    world.json("/Users/a/.claude.json", {"mcpServers": {"s": {"command": "node"}}})

    snapshot = discover(world.gate(), catalog)

    (server,) = [a for a in snapshot.assets if a.kind is Kind.MCP_SERVER]
    assert server.hook_event is None and server.hook_matcher is None
