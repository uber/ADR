"""M2 -- where should we look.

Answers that question once, for the whole pipeline. Nothing downstream may
decide it for itself, and nothing here knows what any particular tool is:
`enumerate_candidates` is run with an empty catalog in its own test set,
and must produce the same candidates it produces with a full one.
"""

from __future__ import annotations

from ..contracts.records import Candidate
from .roots import homes
from .sources.appstate import from_app_state
from .sources.binaries import from_binaries
from .sources.execjournal import from_exec_journal
from .sources.modelstores import from_model_stores
from .sources.network import from_network
from .sources.registries import from_applications, from_kernel, from_packages
from .sweep import sweep

__all__ = ["enumerate_candidates"]


def enumerate_candidates(gate, include_dependency_caches: bool = False) -> tuple[Candidate, ...]:
    """Registries first, then the sweep.

    The order is the optimisation: most of the search is over before the
    walk starts, and every registry hit arrives with provenance attached.
    """
    found: list[Candidate] = []

    # Half one -- ask what already has the answer.
    found.extend(from_packages(gate))
    found.extend(from_applications(gate))
    kernel = from_kernel(gate)
    found.extend(kernel)
    found.extend(from_network(gate, kernel))
    found.extend(from_exec_journal(gate))
    found.extend(from_app_state(gate, homes(gate)))
    found.extend(from_binaries(gate, homes(gate)))
    found.extend(from_model_stores(gate, homes(gate)))

    registry_entries = gate.budget.entries_used

    # Half two -- sweep only what no registry indexes.
    found.extend(sweep(gate, include_dependency_caches))

    gate.ledger.probe(
        "enumerator", "ran",
        f"{len(found)} candidates; {registry_entries} entries before the sweep",
    )
    return tuple(found)
