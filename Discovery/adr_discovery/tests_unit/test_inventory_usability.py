"""Inventory identity and scan limits must remain understandable to a local user."""

from __future__ import annotations

import plistlib

import pytest

from adr_discovery.contracts.records import Candidate, Kind
from adr_discovery.enumerator import enumerate_candidates
from adr_discovery.extractor import extract
from adr_discovery.identifier import identify
from adr_discovery.pipeline import _declarations_by_asset, discover
from adr_discovery.reporter.snapshot import from_dict, to_dict
from adr_discovery.world.budget import Budget
from adr_discovery.world.platform.darwin import DarwinProviders


@pytest.mark.parametrize("root", ["/Applications", "/Users/alice/Applications"])
def test_codex_desktop_is_identified_from_system_or_user_application_registry(world, catalog, root):
    path = root + "/ChatGPT.app"
    world.file(path + "/Contents/Info.plist", plistlib.dumps({
        "CFBundleIdentifier": "com.openai.codex",
        "CFBundleName": "ChatGPT",
        "CFBundleShortVersionString": "1.2.3",
    }).decode())
    gate = world.gate(providers=DarwinProviders())
    applications = gate.applications()
    assert applications.ok
    (application,) = applications.value
    verdict = identify(gate, Candidate(
        "application", application.path, "application_registry",
        detail={"ident": application.ident, "version": application.version},
    ), catalog)
    assert verdict.is_concluded
    assert verdict.catalog_id == "codex-desktop"
    assert verdict.kind is Kind.APP
    assert verdict.version == "1.2.3"


@pytest.mark.parametrize("install", [
    "/usr/local/lib/node_modules/@openai/codex",
    "/Users/alice/.npm-global/lib/node_modules/@openai/codex",
    "/Users/alice/AppData/Roaming/npm/node_modules/@openai/codex",
])
def test_codex_package_remains_a_cli_not_a_desktop_application(world, catalog, install):
    candidate = Candidate(
        "package", install, "package:npm", detail={"name": "@openai/codex", "version": "1.2.3"},
    )
    verdict = identify(world.gate(), candidate, catalog)
    assert verdict.is_concluded
    assert verdict.kind is Kind.CLI_AGENT
    assert verdict.catalog_id == "codex-cli"


def test_config_directory_does_not_claim_a_codex_installation(world, catalog):
    world.dir("/Users/alice/.codex")
    snapshot = discover(world.gate(), catalog)
    assert not any(asset.catalog_id in ("codex-cli", "codex-desktop") for asset in snapshot.assets)


def test_standalone_codex_is_visible_but_not_claimed_as_a_verified_install(world, catalog):
    executable = "/Users/alice/.codex/packages/standalone/current/bin/codex"
    world.binary(executable, "untrusted synthetic executable; never execute")
    world.symlink("/Users/alice/.local/bin/codex", executable)
    snapshot = discover(world.gate(), catalog)
    assert not any(asset.catalog_id == "codex-cli" for asset in snapshot.assets)
    matches = [item for item in snapshot.review_queue if item.suspected_catalog_id == "codex-cli"]
    assert len(matches) == 1
    assert matches[0].suspected_name == "Codex CLI"
    assert matches[0].candidate_kind == "binary"
    assert matches[0].path == executable
    decoded = from_dict(to_dict(snapshot))
    assert decoded.review_queue[0].suspected_name == snapshot.review_queue[0].suspected_name
    assert decoded.review_queue[0].candidate_kind == snapshot.review_queue[0].candidate_kind


def test_walk_stops_when_budget_is_spent_instead_of_opening_every_queued_folder(world):
    for number in range(100):
        world.file(f"/wide/d{number}/child", "")
    gate = world.gate(budget=Budget(max_entries=50))
    list(gate.walk("/wide"))
    assert gate.budget.entries_used == 50
    records = gate.ledger.freeze().boundaries_hit
    assert len(records) == 2
    assert any("queued locations not checked" in record.detail for record in records)


def test_walk_reserves_shared_entries_for_directory_extraction(world):
    for number in range(100):
        world.file(f"/wide/child{number}", "")
    world.file("/skills/example/SKILL.md", "---\nname: Example\n---\nPrivate skill body")
    gate = world.gate(budget=Budget(max_entries=30, reserved_walk_entries=10))
    assert len(list(gate.walk("/wide"))) == 20
    result = extract(gate, Candidate("marker_dir", "/skills", "app_state:surface"))
    assert [item.name for item in result.declarations] == ["Example"]
    assert gate.budget.entries_used == 21
    assert gate.budget.entries_used <= gate.budget.max_entries
    assert "Private skill body" not in repr(result)


def test_reserve_keeps_existing_positional_budget_arguments():
    budget = Budget(1024, 100, 3, 2.0, 4096, 2048, 10.0)
    assert budget.max_depth == 3
    assert budget.max_seconds == 10.0
    assert budget.reserved_walk_entries == 0


def test_dependency_tree_is_pruned_before_it_spends_walk_budget(world):
    world.file("/Users/alice/project/node_modules/dependency/nested/.mcp.json", "{}")
    world.file("/Users/alice/project/.mcp.json", '{"mcpServers": {}}')
    gate = world.gate()
    candidates = enumerate_candidates(gate)
    assert any(item.path == "/Users/alice/project/.mcp.json" for item in candidates)
    assert not any("node_modules" in item.path for item in candidates if item.source == "sweep")
    assert any(
        item.boundary == "scope_excluded" and item.path.endswith("node_modules")
        for item in gate.ledger.freeze().boundaries_hit
    )


def test_prioritized_agent_configs_and_skill_roots_survive_an_exhausted_sweep(world):
    world.json("/Users/alice/.claude/settings.json", {})
    world.json("/Users/alice/.codex/hooks.json", {})
    world.json("/Users/alice/.copilot/mcp-config.json", {})
    world.file("/Users/alice/.codex/skills/example/SKILL.md", "---\nname: Example\n---")
    gate = world.gate(budget=Budget(max_entries=1), env={"HOME": "/Users/alice"})
    paths = {item.path for item in enumerate_candidates(gate)}
    assert "/Users/alice/.claude/settings.json" in paths
    assert "/Users/alice/.codex/hooks.json" in paths
    assert "/Users/alice/.copilot/mcp-config.json" in paths
    assert "/Users/alice/.codex/skills" in paths


@pytest.mark.parametrize(("command", "title"), [
    ("python3 /opt/hooks/audit.py --token SYNTHETIC-CANARY", "audit.py · After tool use"),
    ("/usr/local/bin/adr-desktop hook --config /profile/client.json", "ADR protection · After tool use"),
    ("/opt/adr/bin/adr-hook --harness claude", "ADR protection · After tool use"),
    ("TOKEN=SYNTHETIC-CANARY /usr/bin/audit --event post", "audit · After tool use"),
    ("bash -c 'echo SYNTHETIC-CANARY'", "bash · After tool use"),
])
def test_hook_names_use_executables_and_events_not_flag_values(world, command, title):
    path = "/Users/alice/.claude/settings.json"
    world.json(path, {"hooks": {"PostToolUse": [{"hooks": [{"type": "command", "command": command}]}]}})
    result = extract(world.gate(), Candidate("marker_file", path, "app_state:config"))
    (hook,) = result.declarations
    assert hook.name == title
    assert hook.raw["hook_id"] == 0
    assert "SYNTHETIC-CANARY" not in hook.name
    if "--token" in command or command.startswith("TOKEN="):
        assert "SYNTHETIC-CANARY" not in hook.command


def test_readable_hook_names_do_not_merge_distinct_callbacks(world, catalog):
    world.json("/Users/alice/.claude/settings.json", {
        "hooks": {"PostToolUse": [{"hooks": [
            {"type": "command", "command": "audit --first"},
            {"type": "command", "command": "audit --second"},
        ]}]},
    })
    snapshot = discover(world.gate(), catalog)
    hooks = [asset for asset in snapshot.assets if asset.kind is Kind.HOOK]
    assert len(hooks) == 2
    assert {asset.name for asset in hooks} == {"audit · After tool use"}
    assert len({asset.asset_id for asset in hooks}) == 2
    candidate = Candidate("marker_file", "/Users/alice/.claude/settings.json", "app_state:config")
    declarations = extract(world.gate(), candidate).declarations
    matched = _declarations_by_asset(tuple(hooks), [(candidate, item) for item in declarations])
    assert {item.command for item in matched.values()} == {"audit --first", "audit --second"}


def test_adr_hook_status_message_produces_a_specific_bounded_title(world):
    path = "/Users/alice/.codex/hooks.json"
    world.json(path, {"hooks": {"PreToolUse": [{"hooks": [{
        "type": "command",
        "command": "/opt/ADRCore hook",
        "statusMessage": "ADR: check file access",
    }]}]}})
    result = extract(world.gate(), Candidate("marker_file", path, "app_state:config"))
    assert result.declarations[0].name == "ADR file protection · Before tool use"


def test_codex_plugin_manifest_is_a_valid_inventory_surface(world):
    path = "/Users/alice/.codex/plugins"
    world.json(path + "/example/.codex-plugin/plugin.json", {"name": "example"})
    result = extract(world.gate(), Candidate("marker_dir", path, "app_state:surface"))
    assert len(result.declarations) == 1
    assert result.declarations[0].kind is Kind.PLUGIN
