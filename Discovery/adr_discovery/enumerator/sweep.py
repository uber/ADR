"""Sweep only what no registry indexes.

Repositories, agent directories and skill folders are found by traversal
keyed on markers, not on remembered paths. This is the only part of M2 that
can ruin the budget, so it carries the budget.
"""

from __future__ import annotations

from ..contracts.records import Candidate
from .markers import is_loose_executable, marker_kind
from .roots import in_scope, ordered_roots


def sweep(gate, include_dependency_caches: bool = False) -> tuple[Candidate, ...]:
    """Breadth-ordered over priority roots, under one shared ceiling.

    Marker matching is a name test on entries already being listed, not a
    second pass -- the walk is the cost, and this adds nothing to it.
    """
    out: list[Candidate] = []
    seen: set[str] = set()

    for root, priority in ordered_roots(gate):
        if gate.budget.entries_exhausted:
            gate.ledger.boundary(root, "budget_exhausted", "root not swept")
            continue
        probe = gate.list_dir(root)
        if not probe.ok:
            continue
        for entry in gate.walk(root):
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
    return tuple(out)
