"""M2 -- enumerator.

Run without a catalog. That is the contract: a candidate set that changes
when the catalog changes is not an enumerator, it is a lookup.
"""

from __future__ import annotations

from adr_discovery.catalog.load import EMPTY
from adr_discovery.enumerator import enumerate_candidates
from adr_discovery.world.budget import Budget


def paths(candidates, kind=None):
    return {c.path for c in candidates if kind is None or c.kind == kind}


def test_u2_01_a_repo_outside_every_known_root_is_found(world):
    world.file("/opt/checkouts/svc/.git/HEAD", "ref: refs/heads/main")
    world.file("/opt/checkouts/svc/.mcp.json", "{}")
    gate = world.gate()

    found = enumerate_candidates(gate)

    assert "/opt/checkouts/svc/.git" in paths(found)
    assert "/opt/checkouts/svc/.mcp.json" in paths(found)


def test_u2_02_a_marker_one_level_deeper_is_found(world):
    world.file("/Users/alice/work/team/proj/.claude/settings.json", "{}")
    gate = world.gate()

    assert any(p.endswith("proj/.claude") for p in paths(enumerate_candidates(gate)))


def test_u2_03_enumeration_does_not_consult_the_catalog(world):
    """The load-bearing case. Any change that makes this fail has put
    identification back inside enumeration."""
    world.file("/Users/alice/proj/.claude/settings.json", "{}")
    world.file("/Users/alice/proj/.mcp.json", "{}")

    with_catalog = enumerate_candidates(world.gate())
    without = enumerate_candidates(world.gate())

    assert paths(with_catalog) == paths(without)
    assert len(EMPTY) == 0


def test_u2_04_budget_exhaustion_is_reported(world):
    for i in range(300):
        world.file(f"/Users/alice/proj/f{i}.txt", "x")
    gate = world.gate(budget=Budget(max_entries=50))

    enumerate_candidates(gate)

    assert any(b.boundary == "budget_exhausted" for b in gate.ledger.freeze().boundaries_hit)


def test_u2_05_one_budget_is_shared_across_roots(world):
    for root in ("/Users/alice/src", "/Users/alice/work", "/opt"):
        for i in range(80):
            world.file(f"{root}/p{i}/f.txt", "x")
    gate = world.gate(budget=Budget(max_entries=100))

    enumerate_candidates(gate)

    assert gate.budget.entries_used <= 100, "each root must not get its own ceiling"


def test_u2_06_home_is_swept_before_breadth(world):
    world.file("/Users/alice/.claude/settings.json", "{}")
    world.file("/opt/thing/.claude/settings.json", "{}")
    gate = world.gate()

    swept = [c.path for c in enumerate_candidates(gate) if c.source == "sweep"]
    home = next(i for i, p in enumerate(swept) if p.startswith("/Users/alice/."))
    system = next(i for i, p in enumerate(swept) if p.startswith("/opt/"))

    assert home < system


def test_u2_08_an_outbound_connection_is_a_candidate(world):
    world.surface("sockets", [
        {"proto": "tcp", "state": "ESTABLISHED", "remote_host": "api.anthropic.com",
         "remote_port": 443, "pid": 8812},
    ])
    gate = world.gate()

    found = enumerate_candidates(gate)
    peers = [c for c in found if c.kind == "network_peer"]

    assert [p.path for p in peers] == ["api.anthropic.com"]
    assert peers[0].detail["pid"] == 8812


def test_u2_09_the_resolver_cache_covers_a_window_not_an_instant(world):
    world.surface("dns", [{"hostname": "api.openai.com"}, {"hostname": "example.com"}])
    gate = world.gate()

    peers = [c.path for c in enumerate_candidates(gate) if c.kind == "dns_peer"]

    assert peers == ["api.openai.com"], "a tool that ran an hour ago must still be visible"


def test_u2_10_an_absent_journal_is_unavailable_not_empty(world):
    gate = world.gate()

    enumerate_candidates(gate)
    coverage = gate.ledger.freeze()

    assert "exec_journal" in [u.provider for u in coverage.unavailable]
    assert any(p.name == "exec_journal" and p.status == "degraded" for p in coverage.probes)


def test_u2_11_a_short_lived_run_survives_in_the_journal(world):
    world.surface("execjournal", [
        {"exe": "/opt/agents/nightly", "argv": ["nightly", "-p"], "ppid": 1,
         "parent_exe": "/usr/sbin/cron", "started": "2026-08-22T03:12:00Z"},
    ])
    gate = world.gate()

    events = [c for c in enumerate_candidates(gate) if c.kind == "exec_event"]

    assert len(events) == 1
    assert events[0].detail["argv"] == ("nightly", "-p")
    assert events[0].detail["parent_exe"] == "/usr/sbin/cron"


def test_u2_12_an_instruction_file_is_a_programmable_surface(world):
    world.file("/Users/alice/proj/CLAUDE.md", "# steering prose")
    gate = world.gate()

    found = [c for c in enumerate_candidates(gate) if c.path.endswith("CLAUDE.md")]

    assert [c.kind for c in found] == ["instruction_file"]


def test_critical_host_configs_do_not_depend_on_the_sweep_budget(world):
    world.file("/Users/alice/.claude.json", '{"mcpServers": {}}')
    world.file("/etc/adr/managed-mcp.json", '{"mcpServers": {}}')
    gate = world.gate(budget=Budget(max_entries=1))

    found = enumerate_candidates(gate)

    assert "/Users/alice/.claude.json" in paths(found, "marker_file")
    assert "/etc/adr/managed-mcp.json" in paths(found, "marker_file")


def test_u2_07_registries_answer_before_the_sweep_spends_anything(world):
    """Most of the search is over before it starts.

    A binary the package database already lists must not cost sweep
    entries to locate -- the ordering is the optimisation, and without an
    assertion it is only an intention.
    """
    world.dir("/Users/alice")
    world.binary("/opt/homebrew/bin/claude", "#!/bin/sh\necho 2.1.234\n")
    world.surface("packages", [{"manager": "npm", "name": "@anthropic-ai/claude-code",
                                "version": "2.1.234", "path": "/opt/homebrew/bin/claude"}])
    gate = world.gate()

    from adr_discovery.enumerator.sources.registries import from_packages

    from_registry = from_packages(gate)
    spent_on_registries = gate.budget.entries_used

    assert [c.path for c in from_registry] == ["/opt/homebrew/bin/claude"]
    assert spent_on_registries == 0, "querying an index must not consume the sweep ceiling"
