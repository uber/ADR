"""Reading a run off disk, and reducing it to the part worth scoring.

Scoring works on the delta rather than the raw second scan. A golden image is
never perfectly empty, and residual baseline noise present in both scans would
otherwise be charged to the manifest as invention. What survives here is the
set of assets that installation actually caused to appear.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple

from adr_discovery.contracts.records import Asset
from adr_discovery.contracts.snapshot import Snapshot
from adr_discovery.reporter.delta import diff
from adr_discovery.reporter.snapshot import from_dict

BEFORE = "before.json"
AFTER = "after.json"
ACTUAL = "manifest.actual.json"
CANARIES = "canaries.json"

#: The two delta kinds that mean "this asset was not here before".
#: ``reinstalled`` counts because the asset carries a new id: to an operator
#: reading an inventory it is a new row, and scoring reads what they read.
APPEARED = ("appeared", "reinstalled")

#: The three statuses the runner may record. Only one of them is scoreable.
STATUSES = ("installed", "unavailable", "failed")


class RunError(ValueError):
    """A run directory that cannot be scored, said plainly rather than crashed."""


@dataclass(frozen=True)
class Outcome:
    """What the runner recorded actually happened for one manifest id.

    Scoring compares against this, never against the manifest: the manifest is
    intent, and an entry that did not install is not a blind spot.
    """

    id: str
    status: str
    catalog_id: Optional[str] = None
    version: Optional[str] = None
    path: Optional[str] = None
    method: Optional[str] = None
    reason: Optional[str] = None

    @property
    def is_scoreable(self) -> bool:
        """``unavailable`` and ``failed`` both leave the denominator.

        The distinction is kept for the report rather than the arithmetic:
        one is the vendor's choice, the other is a broken harness, and a
        denominator that shrinks quietly flatters every recall number after it.
        """
        return self.status == "installed"


@dataclass(frozen=True)
class Run:
    """One scored run: two scans, what the runner did, and the planted canaries."""

    os: str
    image: str
    before: Snapshot
    after: Snapshot
    outcomes: Tuple[Outcome, ...] = ()
    canaries: Dict[str, str] = field(default_factory=dict)
    collector: str = "unknown"
    run_id: str = "unnamed"

    def outcome(self, entry_id: str) -> Optional[Outcome]:
        for recorded in self.outcomes:
            if recorded.id == entry_id:
                return recorded
        return None

    @property
    def installed(self) -> Tuple[Outcome, ...]:
        return tuple(o for o in self.outcomes if o.is_scoreable)

    @property
    def counts(self) -> Dict[str, int]:
        tally = {status: 0 for status in STATUSES}
        for recorded in self.outcomes:
            tally[recorded.status] = tally.get(recorded.status, 0) + 1
        tally["applicable"] = len(self.outcomes)
        return tally


def added(run: "Run") -> Tuple[Asset, ...]:
    """The assets the second scan reports that the first one did not.

    Derived through the shipped delta rather than a set difference here, so
    the harness scores the same notion of "new" that the product reports.
    """
    delta = diff(run.before, run.after)
    fresh = {c.asset_id for c in delta.changes if c.kind in APPEARED}
    return tuple(a for a in run.after.assets if a.asset_id in fresh)


def baseline_is_clean(before: Snapshot) -> bool:
    """A baseline with assets in it has nothing to blame them on.

    Asserted separately and before installation, because anything the golden
    image reports is a false positive whose manifest row does not exist.
    """
    return not before.assets


def load(directory: str) -> Run:
    """Read a run directory. Missing files are an error, not an empty run."""
    before = _snapshot(directory, BEFORE)
    after = _snapshot(directory, AFTER)
    actual = _json(os.path.join(directory, ACTUAL))
    canaries = _optional_json(os.path.join(directory, CANARIES)) or {}

    if not isinstance(actual.get("entries"), list):
        raise RunError(f"{ACTUAL} has no entries list; nothing to score against")

    outcomes = tuple(_outcome(row) for row in actual["entries"])
    return Run(
        os=actual.get("os", "unknown"),
        image=actual.get("image", "unknown"),
        before=before,
        after=after,
        outcomes=outcomes,
        canaries={str(k): str(v) for k, v in canaries.items()},
        collector=actual.get("collector", "unknown"),
        run_id=actual.get("run_id", os.path.basename(directory.rstrip("/")) or "unnamed"),
    )


def _outcome(row: Dict[str, Any]) -> Outcome:
    entry_id = row.get("id")
    if not entry_id:
        raise RunError("an outcome with no id cannot be joined to the manifest")
    status = row.get("status")
    if status not in STATUSES:
        raise RunError(f"{entry_id}: status {status!r} is not one of {STATUSES}")
    return Outcome(
        id=entry_id,
        status=status,
        catalog_id=row.get("catalog_id"),
        version=row.get("version"),
        path=row.get("path"),
        method=row.get("method"),
        reason=row.get("reason"),
    )


def _snapshot(directory: str, name: str) -> Snapshot:
    return from_dict(_json(os.path.join(directory, name)))


def _json(path: str) -> Dict[str, Any]:
    if not os.path.isfile(path):
        raise RunError(f"{path} is missing; a run is scored from its files, not from a VM")
    with open(path, encoding="utf-8") as handle:
        try:
            return json.load(handle)
        except json.JSONDecodeError as broken:
            raise RunError(f"{path} is not valid JSON: {broken}") from broken


def _optional_json(path: str) -> Optional[Dict[str, Any]]:
    return _json(path) if os.path.isfile(path) else None


def serialized(snapshot: Snapshot) -> str:
    """The snapshot as the collector would emit it.

    The canary check searches this rather than walking the object graph: a
    credential that leaks into a field nobody thought to inspect is exactly
    the leak worth catching.
    """
    from adr_discovery.reporter.snapshot import to_json

    return to_json(snapshot, indent=None)


__all__ = [
    "ACTUAL", "AFTER", "BEFORE", "CANARIES", "Outcome", "Run", "RunError",
    "added", "baseline_is_clean", "load", "serialized",
]
