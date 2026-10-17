"""Budgets live in M1, not in callers.

A caller cannot forget a limit it does not set. One ceiling is shared by
the whole scan rather than one per probe, because five private budgets
cannot be reasoned about and, in aggregate, are not a budget at all.
"""

from __future__ import annotations

import os
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Iterator


@dataclass(slots=True)
class Budget:
    """Ceilings for one scan. Mutable only in the consumed counters."""

    max_read_bytes: int = 4 * 1024 * 1024
    max_entries: int = 200_000
    max_depth: int = 12
    #: A directory listing more entries than this is a store, not a place
    #: anyone keeps agents: its own entries are read, its subtrees are not.
    max_children: int = 5000
    #: Windows PowerShell's first launch includes host and JSON JIT startup.
    #: Explicit caller limits still replace this platform default unchanged.
    max_subprocess_seconds: float = field(default_factory=lambda: 10.0 if os.name == "nt" else 5.0)
    max_subprocess_output_bytes: int = 4 * 1024 * 1024
    #: The whole scan, wall clock. Plane A promises seconds, and a promise
    #: with no ceiling behind it is a hope.
    max_seconds: float = 120.0
    #: Entries the generic sweep leaves untouched for stages that list
    #: directories after it (extraction, manifest reads, app-state
    #: listings). Left unset it is 10% of `max_entries`; pass 0 to give the
    #: whole ceiling to the sweep.
    reserved_walk_entries: int | None = None
    #: Most of the ceiling the known agent state roots may claim, walked
    #: before the generic sweep. A cap, not a reservation: what they do not
    #: use stays available to everything after them.
    state_root_share: float = 0.25
    #: Folder hashing (`Gate.hash_tree`) is charged here, not to the entry
    #: ceiling or the read cap: hashing what the sweep found must not starve
    #: the sweep. The per-tree caps are the limits `archive` enforces when it
    #: reads a zip, so any tree hashed here can also be archived.
    max_hash_bytes: int = 1024 * 1024 * 1024
    max_tree_files: int = 10_000
    max_tree_file_bytes: int = 20 * 1024 * 1024
    max_tree_bytes: int = 100 * 1024 * 1024

    entries_used: int = field(default=0, init=False)
    hash_bytes_used: int = field(default=0, init=False)
    _ceiling: int | None = field(default=None, init=False, repr=False)
    started: float = field(default_factory=time.monotonic, init=False)

    def __post_init__(self) -> None:
        if self.reserved_walk_entries is None:
            self.reserved_walk_entries = self.max_entries // 10

    @property
    def entry_cap(self) -> int:
        """The ceiling in force: `max_entries`, or a lower stage ceiling."""
        return self.max_entries if self._ceiling is None else min(self.max_entries, self._ceiling)

    @contextmanager
    def ceiling(self, absolute: int) -> Iterator[None]:
        """Lower the entry cap for one stage; never raises it.

        Consumption still lands on the one shared counter, so a stage cap is
        a way of ordering claims on the budget, not a second budget.
        """
        previous = self._ceiling
        self._ceiling = absolute if previous is None else min(previous, absolute)
        try:
            yield
        finally:
            self._ceiling = previous

    def take_entries(self, n: int = 1) -> bool:
        """Consume from the shared entry ceiling. False once exhausted."""
        if self.entries_used >= self.entry_cap:
            return False
        self.entries_used += n
        return True

    def take_hash_bytes(self, n: int) -> bool:
        """Claim `n` bytes of the hashing budget, all or nothing."""
        if self.hash_bytes_used + n > self.max_hash_bytes:
            return False
        self.hash_bytes_used += n
        return True

    @property
    def entries_exhausted(self) -> bool:
        return self.entries_used >= self.entry_cap

    @property
    def seconds_used(self) -> float:
        return time.monotonic() - self.started

    @property
    def time_exhausted(self) -> bool:
        return self.seconds_used >= self.max_seconds

    @property
    def entries_remaining(self) -> int:
        return max(0, self.entry_cap - self.entries_used)
