"""Budgets live in M1, not in callers.

A caller cannot forget a limit it does not set. One ceiling is shared by
the whole scan rather than one per probe, because five private budgets
cannot be reasoned about and, in aggregate, are not a budget at all.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass(slots=True)
class Budget:
    """Ceilings for one scan. Mutable only in the consumed counters."""

    max_read_bytes: int = 4 * 1024 * 1024
    max_entries: int = 200_000
    max_depth: int = 12
    max_subprocess_seconds: float = 5.0
    max_strings_bytes: int = 512 * 1024
    #: The whole scan, wall clock. Plane A promises seconds, and a promise
    #: with no ceiling behind it is a hope.
    max_seconds: float = 120.0

    entries_used: int = field(default=0, init=False)
    started: float = field(default_factory=time.monotonic, init=False)

    def take_entries(self, n: int = 1) -> bool:
        """Consume from the shared entry ceiling. False once exhausted."""
        if self.entries_used >= self.max_entries:
            return False
        self.entries_used += n
        return True

    @property
    def entries_exhausted(self) -> bool:
        return self.entries_used >= self.max_entries

    @property
    def seconds_used(self) -> float:
        return time.monotonic() - self.started

    @property
    def time_exhausted(self) -> bool:
        return self.seconds_used >= self.max_seconds

    @property
    def entries_remaining(self) -> int:
        return max(0, self.max_entries - self.entries_used)
