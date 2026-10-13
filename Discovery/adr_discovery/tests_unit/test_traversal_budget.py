"""Traversal cost: what the sweep spends its budget on.

Each case builds a small tree on disk and drives the real gate over it, so
the budget numbers are the ones a live scan would produce.
"""

from __future__ import annotations

from adr_discovery.contracts.records import Kind
from adr_discovery.enumerator import enumerate_candidates
from adr_discovery.enumerator.sweep import sweep
from adr_discovery.pipeline import discover
from adr_discovery.world.budget import Budget


def _paths(candidates, suffix: str) -> list[str]:
    return [c.path for c in candidates if c.path.endswith(suffix)]


def _boundaries(gate, kind: str):
    return [b for b in gate.ledger.freeze().boundaries_hit if b.boundary == kind]


def test_excluded_tree_costs_no_budget(world):
    for i in range(3000):
        world.file(f"/Users/alice/.cache/blob/f{i}", "x")
    world.file("/Users/alice/.claude/skills/x/SKILL.md", "---\nname: x\n---\n")
    gate = world.gate(budget=Budget(max_entries=200))

    found = enumerate_candidates(gate)

    assert gate.budget.entries_used < 50, "a skipped tree must not be listed or charged"
    assert _paths(found, "/.claude/skills")
    assert not _boundaries(gate, "budget_exhausted")


CACHEDIR_TAG = "Signature: 8a477f597d28d172789f06886806bc55\n# a cache\n"


def test_tagged_cache_dir_is_not_descended(world):
    world.file("/Users/alice/build/CACHEDIR.TAG", CACHEDIR_TAG)
    world.file("/Users/alice/build/inner/skills/s/SKILL.md", "x")
    world.file("/Users/alice/proj/.claude/settings.json", "{}")
    gate = world.gate()

    found = enumerate_candidates(gate)

    assert not any("/build/inner" in c.path for c in found)
    assert _paths(found, "/proj/.claude")
    assert {b.path for b in _boundaries(gate, "cache_dir")} == {"/Users/alice/build"}


def test_untagged_lookalike_is_still_walked(world):
    world.file("/Users/alice/build/CACHEDIR.TAG", "not the signature\n")
    world.file("/Users/alice/build/inner/skills/s/SKILL.md", "x")
    gate = world.gate()

    found = enumerate_candidates(gate)

    assert _paths(found, "/build/inner/skills")
    assert not _boundaries(gate, "cache_dir")


def test_fan_out_directory_yields_entries_but_not_subtrees(world):
    for i in range(60):
        world.file(f"/Users/alice/store/d{i:02d}/deep/skills/s", "x")
    world.file("/Users/alice/store/.claude/settings.json", "{}")
    gate = world.gate(budget=Budget(max_entries=50_000, max_children=50))

    found = enumerate_candidates(gate)

    assert _paths(found, "/store/.claude"), "entries of the large directory are still read"
    assert not any("/deep" in c.path for c in found)
    hits = _boundaries(gate, "fan_out")
    assert {b.path for b in hits} == {"/Users/alice/store"}
    assert all("61 children" in b.detail for b in hits)


def test_one_huge_subtree_does_not_starve_a_deep_sibling(world):
    for i in range(20):
        for j in range(20):
            for k in range(20):
                world.file(f"/Users/alice/big/a{i:02d}/b{j:02d}/f{k:02d}", "x")
    world.file("/Users/alice/small/a/b/c/d/.claude/settings.json", "{}")
    gate = world.gate(budget=Budget(max_entries=300))

    found = enumerate_candidates(gate)

    assert _paths(found, "/small/a/b/c/d/.claude"), "the deep sibling must still be reached"
    assert gate.budget.entries_used <= 300
    assert _boundaries(gate, "budget_exhausted"), "the huge subtree is recorded as cut"


def _crowd(world, home: str, siblings: int = 30) -> None:
    """Many busy top-level directories, each taking its fair turn."""
    for i in range(siblings):
        for j in range(10):
            for k in range(10):
                world.file(f"{home}/d{i:02d}/s{j}/f{k}", "x")


def test_state_roots_are_walked_before_the_generic_sweep(world):
    home = "/Users/alice"
    _crowd(world, home)
    world.file(f"{home}/.claude/plugins/cache/m/p/1.0/skills/s/SKILL.md", "x")
    gate = world.gate(budget=Budget(max_entries=1000))

    found = enumerate_candidates(gate)

    swept = [c for c in found if c.source == "sweep" and c.path.endswith("/1.0/skills")]
    assert swept, "a plugin-cache skill must not depend on the home sweep reaching it"
    assert gate.budget.entries_used <= 1000


def test_generic_sweep_leaves_the_reserved_entries(world):
    _crowd(world, "/Users/alice")
    gate = world.gate(budget=Budget(max_entries=2000, reserved_walk_entries=500))

    enumerate_candidates(gate)

    assert gate.budget.entries_used <= 1500
    assert gate.budget.entry_cap == 2000, "a stage ceiling must not outlive its stage"


def test_nested_root_is_not_listed_twice(world):
    for i in range(5):
        world.file(f"/home/u/proj/p{i}/f", "x")
    world.file("/home/other/f", "x")
    gate = world.gate()
    visited: set[str] = set()

    first = [e.path for e in gate.walk("/home/u", seen=visited)]
    used = gate.budget.entries_used
    second = [e.path for e in gate.walk("/home", seen=visited)]

    assert sorted(second) == ["/home/other", "/home/other/f", "/home/u"]
    assert not any(p.startswith("/home/u/") for p in second)
    assert gate.budget.entries_used == used + 3, "only /home and /home/other are newly charged"
    assert len(first) == 11


def test_sweep_lists_each_directory_once(world):
    for i in range(5):
        world.file(f"/Users/alice/src/p{i}/f", "x")
        world.file(f"/Users/alice/.claude/skills/s{i}/SKILL.md", "x")
    gate = world.gate()
    listed: list[str] = []
    real = gate.list_dir

    def recording(path, **kw):
        listed.append(path)
        return real(path, **kw)

    gate.list_dir = recording

    sweep(gate)

    # Home discovery itself re-lists the home parents; the walks must not.
    walked = [p for p in listed if p not in ("/Users", "/home")]
    for path in ("/Users/alice", "/Users/alice/src", "/Users/alice/.claude/skills"):
        assert walked.count(path) == 1, path
    assert len(walked) == len(set(walked))


def test_surfaces_are_still_read_after_the_sweep_spends_its_share(world, catalog):
    for i in range(60):
        for j in range(40):
            world.file(f"/Users/alice/big/d{i:02d}/f{j:02d}", "x")
    world.file(
        "/Users/alice/.claude/skills/s/SKILL.md",
        "---\nname: s\ndescription: a skill\n---\nbody\n",
    )
    world.file("/Users/alice/.claude/commands/c.md", "---\ndescription: a command\n---\nbody\n")
    gate = world.gate(budget=Budget(max_entries=1500))

    snapshot = discover(gate, catalog)

    kinds = {a.kind for a in snapshot.assets}
    assert Kind.SKILL in kinds and Kind.COMMAND in kinds
    assert gate.budget.entries_used <= 1500


def test_retained_listing_is_not_charged_twice(world):
    for i in range(10):
        world.file(f"/Users/alice/.claude/skills/s{i}/SKILL.md", "x")
    gate = world.gate()

    list(gate.walk("/Users/alice", retain=lambda p: p.endswith("/skills")))
    used = gate.budget.entries_used
    again = gate.list_dir("/Users/alice/.claude/skills")

    assert again.ok and len(again.value) == 10
    assert gate.budget.entries_used == used
