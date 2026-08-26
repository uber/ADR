"""C3 -- the ledger every stage writes to.

Every stage can fail to see something, so every stage records it. The
ledger is passed down the pipeline and collected once at the end, which is
the only arrangement in which a stage cannot forget to report.

Records are appended where the reason is still known -- inside the module
that hit the boundary, not inferred afterwards from a short result.
"""

from __future__ import annotations

from ..contracts.snapshot import (
    BoundaryHit,
    Coverage,
    Denied,
    ProbeRun,
    RootSwept,
    Truncated,
    Unavailable,
)


class Ledger:
    """Mutable during a scan, frozen into a Coverage at the end.

    This is the one piece of shared mutable state in the pipeline, and it is
    deliberate: the alternative is every stage returning a coverage fragment
    that the caller must remember to merge, which is a thing a caller can
    forget to do.
    """

    __slots__ = ("_roots", "_boundaries", "_denied", "_unavailable", "_truncated",
                 "_probes", "_seen_unavailable")

    def __init__(self) -> None:
        self._roots: list[RootSwept] = []
        self._boundaries: list[BoundaryHit] = []
        self._denied: list[Denied] = []
        self._unavailable: list[Unavailable] = []
        self._truncated: list[Truncated] = []
        self._probes: list[ProbeRun] = []
        self._seen_unavailable: set[tuple[str, str]] = set()

    def swept(self, path: str, depth_reached: int, entries: int) -> None:
        self._roots.append(RootSwept(path, depth_reached, entries))

    def boundary(self, path: str, boundary: str, detail: str = "") -> None:
        self._boundaries.append(BoundaryHit(path, boundary, detail))

    def deny(self, path: str, reason: str) -> None:
        self._denied.append(Denied(path, reason))

    def unavailable(self, provider: str, reason: str) -> None:
        """A registry or service that could not be queried.

        This is the record that keeps 'no packages' distinct from 'no package
        manager', which are opposite facts about a machine.
        """
        # One fact, however many callers ask. Recording it per call turns
        # the ledger into a log and buries the surfaces that matter.
        key = (provider, reason)
        if key in self._seen_unavailable:
            return
        self._seen_unavailable.add(key)
        self._unavailable.append(Unavailable(provider, reason))

    def truncate(self, path: str, kept: int, true_count: int) -> None:
        self._truncated.append(Truncated(path, kept, true_count))

    def probe(self, name: str, status: str, detail: str = "") -> None:
        self._probes.append(ProbeRun(name, status, detail))

    def freeze(self) -> Coverage:
        return Coverage(
            roots_swept=tuple(self._roots),
            boundaries_hit=tuple(self._boundaries),
            denied=tuple(self._denied),
            unavailable=tuple(self._unavailable),
            truncated=tuple(self._truncated),
            probes=tuple(self._probes),
        )
