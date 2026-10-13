"""Sweep only what no registry indexes.

Repositories, agent directories and skill folders are found by traversal
keyed on markers, not on remembered paths. This is the only part of M2 that
can ruin the budget, so it carries the budget.
"""

from __future__ import annotations

from ..contracts.records import Candidate, Priority
from .markers import is_loose_executable, marker_kind
from .roots import in_scope, ordered_roots, state_roots


def sweep(gate, include_dependency_caches: bool = False) -> tuple[Candidate, ...]:
    """State roots first, then breadth-ordered priority roots, one ceiling.

    Marker matching is a name test on entries already being listed, not a
    second pass -- the walk is the cost, and this adds nothing to it.
    """
    out: list[Candidate] = []
    seen: set[str] = set()
    #: Directories already listed, shared by every walk below so nested
    #: roots and state roots inside a home are each charged once.
    visited: set[str] = set()
    budget = gate.budget

    def descend(path: str) -> bool:
        return in_scope(path, include_dependency_caches)

    def retain(path: str) -> bool:
        # Surface directories are listed again by extraction; keep the answer.
        return marker_kind(path.rsplit("/", 1)[-1]) == "marker_dir"

    def scan(root: str, priority: Priority) -> None:
        for entry in gate.walk(root, descend=descend, seen=visited, retain=retain):
            if not in_scope(entry.path, include_dependency_caches):
                continue
            name = entry.path.rsplit("/", 1)[-1]
            kind = marker_kind(name, entry.path)
            if kind is None and is_loose_executable(entry, name):
                # A tarball unpacked into /opt, a binary copied out of a
                # container: no package record, no marker beside it. The
                # walk is already listing this entry, so noticing costs
                # nothing beyond the name test that follows it.
                kind = "binary"
            if kind is None or entry.path in seen:
                continue
            seen.add(entry.path)
            out.append(
                Candidate(
                    kind=kind,
                    path=entry.path,
                    source="sweep",
                    priority=priority,
                    detail={"marker": name, "is_dir": entry.is_dir, "name": name},
                )
            )

    # Agent state roots get the first claim: what lives under them (plugin
    # caches, skills, commands) is deep, and a home directory full of other
    # things must not decide whether it is reached. They are capped at a
    # share of the ceiling so a state root that is itself huge cannot take
    # the rest.
    state_cap = min(
        budget.entries_used + int(budget.max_entries * budget.state_root_share),
        budget.max_entries - budget.reserved_walk_entries,
    )
    with budget.ceiling(state_cap):
        for root in state_roots(gate):
            if budget.entries_exhausted:
                gate.ledger.boundary(root, "budget_exhausted", "state root not swept")
                continue
            scan(root, Priority.HOME)

    with budget.ceiling(budget.max_entries - budget.reserved_walk_entries):
        for root, priority in ordered_roots(gate):
            if budget.entries_exhausted:
                gate.ledger.boundary(root, "budget_exhausted", "root not swept")
                continue
            scan(root, priority)
    return tuple(out)
