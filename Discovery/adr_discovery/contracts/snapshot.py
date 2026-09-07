"""The output shape: a snapshot, and the coverage that travels with it.

Coverage is a field of the answer rather than a log beside it, because the
rule it exists to enforce is a rule about the answer: every asset that
exists and is not in the snapshot must be explained by a record here.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .records import Asset, Finding, ReviewItem

SCHEMA_VERSION = "1.0"

#: Categories discovery deliberately does not collect. Named rather than
#: omitted, so a reader can tell a clean machine from an unasked question.
OUT_OF_SCOPE: tuple[str, ...] = (
    "instruction_files",
    "agent_hooks",
    "scheduling_mechanisms",
)


class Boundary(str):
    """Why a walk or a read stopped."""

    DEPTH = "depth"
    ENTRY_CAP = "entry_cap"
    BUDGET = "budget_exhausted"
    TIME = "time_exhausted"


@dataclass(frozen=True, slots=True)
class RootSwept:
    path: str
    depth_reached: int
    entries: int


@dataclass(frozen=True, slots=True)
class BoundaryHit:
    path: str
    boundary: str
    detail: str = ""


@dataclass(frozen=True, slots=True)
class Denied:
    path: str
    reason: str


@dataclass(frozen=True, slots=True)
class Unavailable:
    provider: str
    reason: str


@dataclass(frozen=True, slots=True)
class Truncated:
    path: str
    kept: int
    true_count: int


@dataclass(frozen=True, slots=True)
class ProbeRun:
    name: str
    status: str  # ran | degraded | failed
    detail: str = ""


@dataclass(frozen=True, slots=True)
class Coverage:
    """What this scan did not see. An empty snapshot with empty coverage is
    a claim that the machine is clean; an empty snapshot with records here
    is a claim that we could not tell."""

    roots_swept: tuple[RootSwept, ...] = ()
    boundaries_hit: tuple[BoundaryHit, ...] = ()
    denied: tuple[Denied, ...] = ()
    unavailable: tuple[Unavailable, ...] = ()
    truncated: tuple[Truncated, ...] = ()
    probes: tuple[ProbeRun, ...] = ()
    out_of_scope: tuple[str, ...] = OUT_OF_SCOPE

    @property
    def is_complete(self) -> bool:
        """No surface went unread. Note this is never a claim that the
        inventory is complete -- only that nothing is known to be missing."""
        return not (self.boundaries_hit or self.denied or self.unavailable or self.truncated)


@dataclass(frozen=True, slots=True)
class Snapshot:
    hostname: str
    username: str
    platform: str
    timestamp: str
    assets: tuple[Asset, ...] = ()
    findings: tuple[Finding, ...] = ()
    review_queue: tuple[ReviewItem, ...] = ()
    coverage: Coverage = field(default_factory=Coverage)
    catalog_version: str = "unknown"
    schema_version: str = SCHEMA_VERSION
