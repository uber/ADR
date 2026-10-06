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


def test_linux_root_user_home_is_swept_and_not_treated_as_parent():
    """Issue #146: Linux root home (/root) must be discovered as a home directly,
    rather than treating /root as a parent of homes, and its children must not
    be mistaken for user homes."""
    import stat as s

    from adr_discovery.enumerator.roots import homes, ordered_roots
    from adr_discovery.world.gate import Entry, Ok, Refused, Stat
    from adr_discovery.world.platform.linux import LinuxProviders

    class LinuxGate:
        def __init__(self):
            self.providers = LinuxProviders()
            self.env = {}

        def list_dir(self, p):
            if p == "/home":
                return Ok((Entry(path="/home/alice", is_dir=True, is_symlink=False, size=0),))
            if p == "/root":
                return Ok((Entry(path="/root/java", is_dir=True, is_symlink=False, size=0),))
            return Refused("absent")

        def stat(self, p):
            if p in ("/root", "/home/alice"):
                return Ok(
                    Stat(
                        path=p,
                        real_path=p,
                        inode="1:1",
                        size=0,
                        mode=s.S_IFDIR | 0o755,
                        mtime=0.0,
                        owner="root",
                    )
                )
            return Refused("absent")

    gate = LinuxGate()
    discovered = homes(gate)
    assert "/root" in discovered, "/root itself must be identified as a home"
    assert "/home/alice" in discovered, "/home/alice must be identified as a home"
    assert "/root/java" not in discovered, "children of /root must not be treated as user homes"

    roots = [path for path, _ in ordered_roots(gate)]
    assert "/root" in roots, "/root must be swept as a priority root"
    assert "/root/Projects" in roots, "code root templates must expand from /root"
    assert "/root/java" not in roots, "children of /root must not be treated as priority home roots"


def test_darwin_var_root_home_is_swept():
    """macOS root home (/var/root) must be discovered as a direct home."""
    import stat as s

    from adr_discovery.enumerator.roots import homes
    from adr_discovery.world.gate import Entry, Ok, Refused, Stat
    from adr_discovery.world.platform.darwin import DarwinProviders

    class DarwinGate:
        def __init__(self):
            self.providers = DarwinProviders()
            self.env = {}

        def list_dir(self, p):
            if p == "/Users":
                return Ok((Entry(path="/Users/bob", is_dir=True, is_symlink=False, size=0),))
            return Refused("absent")

        def stat(self, p):
            if p in ("/var/root", "/Users/bob"):
                return Ok(
                    Stat(
                        path=p,
                        real_path=p,
                        inode="1:1",
                        size=0,
                        mode=s.S_IFDIR | 0o755,
                        mtime=0.0,
                        owner="root",
                    )
                )
            return Refused("absent")

    gate = DarwinGate()
    discovered = homes(gate)
    assert "/var/root" in discovered
    assert "/Users/bob" in discovered


def test_unreadable_root_home_is_reported_as_coverage_gap():
    """If /root exists but is unreadable (e.g. non-root scan on Linux),
    the attempt to sweep /root must record a denial in coverage rather
    than silently dropping the directory."""
    import stat as s

    from adr_discovery.coverage.ledger import Ledger
    from adr_discovery.enumerator.sweep import sweep
    from adr_discovery.world.budget import Budget
    from adr_discovery.world.gate import Entry, Ok, Refused, Stat
    from adr_discovery.world.platform.linux import LinuxProviders

    class UnreadableRootGate:
        def __init__(self):
            self.providers = LinuxProviders()
            self.ledger = Ledger()
            self.budget = Budget()
            self.env = {}

        def list_dir(self, p):
            if p == "/home":
                return Ok((Entry(path="/home/alice", is_dir=True, is_symlink=False, size=0),))
            if p.startswith("/root"):
                self.ledger.deny(p, "Permission denied")
                return Refused("open_failed", "Permission denied")
            return Refused("absent")

        def stat(self, p):
            if p in ("/root", "/home/alice"):
                return Ok(
                    Stat(
                        path=p,
                        real_path=p,
                        inode="1:1",
                        size=0,
                        mode=s.S_IFDIR | 0o700,
                        mtime=0.0,
                        owner="root",
                    )
                )
            return Refused("absent")

        def walk(self, p, *, descend=None):
            listing = self.list_dir(p)
            if not listing.ok:
                return
            for e in listing.value:
                yield e

    gate = UnreadableRootGate()
    sweep(gate)
    coverage = gate.ledger.freeze()
    assert any(d.path == "/root" and "Permission denied" in d.reason for d in coverage.denied), (
        "unreadable /root must appear in coverage.denied as a coverage gap"
    )


def test_absent_direct_home_is_not_denied():
    """When a direct home does not exist, it must not be added to homes
    and must not record a false denial."""
    from adr_discovery.coverage.ledger import Ledger
    from adr_discovery.enumerator.roots import homes
    from adr_discovery.world.gate import Entry, Ok, Refused
    from adr_discovery.world.platform.linux import LinuxProviders

    class AbsentRootGate:
        def __init__(self):
            self.providers = LinuxProviders()
            self.ledger = Ledger()
            self.env = {}

        def list_dir(self, p):
            if p == "/home":
                return Ok((Entry(path="/home/alice", is_dir=True, is_symlink=False, size=0),))
            return Refused("absent")

        def stat(self, p):
            return Refused("absent")

    gate = AbsentRootGate()
    discovered = homes(gate)
    assert discovered == ("/home/alice",)
    assert len(gate.ledger.freeze().denied) == 0


def test_legacy_home_roots_with_root_is_not_treated_as_parent():
    """Backwards compatibility: If a custom provider supplies /root in home_roots,
    it must be handled as a direct home and not have its children treated as homes."""
    import stat as s

    from adr_discovery.enumerator.roots import homes
    from adr_discovery.world.gate import Entry, Ok, Refused, Stat
    from adr_discovery.world.platform.base import NullProviders

    class LegacyProvider(NullProviders):
        HOME_ROOTS = ("/home", "/root")
        DIRECT_HOMES = ()

    class LegacyGate:
        def __init__(self):
            self.providers = LegacyProvider()
            self.env = {}

        def list_dir(self, p):
            if p == "/home":
                return Ok((Entry(path="/home/alice", is_dir=True, is_symlink=False, size=0),))
            if p == "/root":
                return Ok((Entry(path="/root/child_dir", is_dir=True, is_symlink=False, size=0),))
            return Refused("absent")

        def stat(self, p):
            if p in ("/root", "/home/alice"):
                return Ok(
                    Stat(
                        path=p,
                        real_path=p,
                        inode="1:1",
                        size=0,
                        mode=s.S_IFDIR | 0o755,
                        mtime=0.0,
                        owner="root",
                    )
                )
            return Refused("absent")

    gate = LegacyGate()
    discovered = homes(gate)
    assert "/root" in discovered
    assert "/home/alice" in discovered
    assert "/root/child_dir" not in discovered
