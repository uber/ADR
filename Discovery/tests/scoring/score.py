"""TP, FP, FN, DUP - and the reasons they are four numbers and not two.

Recall and precision are computed per category and per OS and never pooled,
because the denominators differ by OS: an entry that does not apply to Linux
is not a Linux miss, and averaging the three hides which platform regressed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from adr_discovery.contracts.records import Asset

from ..manifest import Entry, Manifest
from . import canary as canary_module
from .match import Matching, match
from .snapshot import Run, added, baseline_is_clean, serialized

TP, FP, FN, DUP = "tp", "fp", "fn", "dup"


@dataclass(frozen=True)
class Verdict:
    """One entry's outcome, keyed by manifest id.

    Keyed by id so a regression reads ``M-SITE-08 went from TP to FN`` rather
    than "MCP recall dropped", which nobody can act on.
    """

    entry_id: str
    category: str
    outcome: str
    assets: Tuple[str, ...] = ()
    detail: str = ""


@dataclass(frozen=True)
class Counts:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    dup: int = 0

    @property
    def recall(self) -> Optional[float]:
        found = self.tp + self.fn
        return round(self.tp / found, 4) if found else None

    @property
    def precision(self) -> Optional[float]:
        claimed = self.tp + self.fp
        return round(self.tp / claimed, 4) if claimed else None

    def as_dict(self) -> Dict[str, Any]:
        return {"tp": self.tp, "fp": self.fp, "fn": self.fn, "dup": self.dup,
                "recall": self.recall, "precision": self.precision}


@dataclass(frozen=True)
class Score:
    run_id: str
    os: str
    image: str
    collector: str
    baseline_clean: bool
    baseline_assets: int
    manifest_counts: Dict[str, int] = field(default_factory=dict)
    totals: Counts = field(default_factory=Counts)
    by_category: Dict[str, Counts] = field(default_factory=dict)
    fields: Dict[str, Optional[float]] = field(default_factory=dict)
    verdicts: Tuple[Verdict, ...] = ()
    canaries: canary_module.CanaryReport = field(default_factory=canary_module.CanaryReport)
    errors: Dict[str, int] = field(default_factory=dict)
    review_queue_ok: Optional[bool] = None

    @property
    def misses(self) -> Tuple[Verdict, ...]:
        return tuple(v for v in self.verdicts if v.outcome == FN)

    @property
    def inventions(self) -> Tuple[Verdict, ...]:
        return tuple(v for v in self.verdicts if v.outcome == FP)

    @property
    def duplicates(self) -> Tuple[Verdict, ...]:
        return tuple(v for v in self.verdicts if v.outcome == DUP)


def score(run: Run, manifest: Manifest, *, platform: Optional[str] = None,
          home: str = "/root") -> Score:
    """The whole measurement, as one pure call over already-loaded files."""
    platform = platform or run.os
    assets = added(run)
    scoreable = _scoreable_entries(run, manifest)

    outcomes = {o.id: o for o in run.installed}
    matching = match(scoreable, assets, outcomes=outcomes, platform=platform, home=home)
    verdicts = _verdicts(scoreable, matching, assets, manifest, platform=platform)

    totals = _tally(verdicts)
    by_category = {
        category: _tally([v for v in verdicts if v.category == category])
        for category in sorted({v.category for v in verdicts})
    }

    return Score(
        run_id=run.run_id,
        os=run.os,
        image=run.image,
        collector=run.collector,
        baseline_clean=baseline_is_clean(run.before),
        baseline_assets=len(run.before.assets),
        manifest_counts=run.counts,
        totals=totals,
        by_category=by_category,
        fields=_field_accuracy(scoreable, matching, assets, run),
        verdicts=verdicts,
        canaries=canary_module.check(
            run.canaries,
            {"after.json": serialized(run.after)},
            declared=manifest.canary_names(),
        ),
        errors=_errors(run, manifest),
        review_queue_ok=_review_queue(run, manifest),
    )


def _scoreable_entries(run: Run, manifest: Manifest) -> List[Entry]:
    """Only entries the runner actually installed are scored.

    An entry the vendor does not ship here, or one that failed outright, is
    excluded from both numerator and denominator - being counted as a miss
    would blame the collector for the harness.
    """
    scoreable: List[Entry] = []
    for recorded in run.installed:
        try:
            entry = manifest.by_id(recorded.id)
        except KeyError:
            continue
        if not entry.must_not_appear:
            scoreable.append(entry)
    return scoreable


def _verdicts(entries: Sequence[Entry], matching: Matching, assets: Sequence[Asset],
              manifest: Manifest, *, platform: str) -> Tuple[Verdict, ...]:
    verdicts: List[Verdict] = []

    for entry in entries:
        if entry.variant_of:
            verdicts.append(_variant_verdict(entry, matching))
            continue
        found = matching.for_entry(entry.id)
        count = len(found.assets) if found else 0
        if count == 1:
            outcome, detail = TP, ""
        elif count == 0:
            where = f"{found.how} {found.key}".strip() if found else "entry"
            outcome, detail = FN, f"no asset matched {where}"
        else:
            outcome, detail = DUP, f"{count} assets matched one entry"
        verdicts.append(Verdict(entry.id, entry.category, outcome,
                                tuple(found.assets) if found else (), detail))

    by_id = {a.asset_id: a for a in assets}
    for asset_id in matching.unmatched_assets:
        asset = by_id.get(asset_id)
        verdicts.append(Verdict(
            entry_id=asset_id,
            category=asset.kind.value if asset else "unknown",
            outcome=FP,
            assets=(asset_id,),
            detail=f"{asset.name} at {asset.install_path}" if asset else "",
        ))
    return tuple(verdicts)


def _variant_verdict(entry: Entry, matching: Matching) -> Verdict:
    """A channel variant is scored on what its base tool reported.

    Two installs of one tool must yield one asset. That is the whole point of
    the eight T-CHAN rows: they provoke the duplicate that inflates a fleet
    inventory, and they pass only when the collector refuses to be provoked.
    """
    base = matching.for_entry(entry.variant_of)
    count = len(base.assets) if base else 0
    if count == 1:
        return Verdict(entry.id, entry.category, TP, tuple(base.assets), f"deduplicated with {entry.variant_of}")
    if count == 0:
        return Verdict(entry.id, entry.category, FN, (), f"base {entry.variant_of} reported no asset")
    return Verdict(entry.id, entry.category, DUP, tuple(base.assets),
                   f"{count} assets for {entry.variant_of} installed twice")


def _tally(verdicts: Iterable[Verdict]) -> Counts:
    counts = {TP: 0, FP: 0, FN: 0, DUP: 0}
    for verdict in verdicts:
        counts[verdict.outcome] = counts.get(verdict.outcome, 0) + 1
    return Counts(tp=counts[TP], fp=counts[FP], fn=counts[FN], dup=counts[DUP])


def _field_accuracy(entries: Sequence[Entry], matching: Matching, assets: Sequence[Asset],
                    run: Run) -> Dict[str, Optional[float]]:
    """Per field, over true positives only.

    Reported per field rather than blended: a collector that always gets
    version right and always gets config_scope wrong has a specific bug, and
    an average hides exactly that.
    """
    by_id = {a.asset_id: a for a in assets}
    right: Dict[str, int] = {}
    total: Dict[str, int] = {}

    for entry in entries:
        found = matching.for_entry(entry.id)
        if not found or len(found.assets) != 1:
            continue
        asset = by_id.get(found.assets[0])
        if asset is None:
            continue
        recorded = run.outcome(entry.id)
        for name, expected in _expectations(entry).items():
            actual = _observed(asset, name, recorded)
            if actual is None:
                continue
            total[name] = total.get(name, 0) + 1
            if _same(expected, actual):
                right[name] = right.get(name, 0) + 1

    return {name: round(right.get(name, 0) / count, 4) if count else None
            for name, count in sorted(total.items())}


def _expectations(entry: Entry) -> Dict[str, Any]:
    """Everything this row asserts about the asset it produces.

    A pinned version counts even when ``expect`` does not repeat it: pinning
    exists precisely so that version stops being a guess and becomes a check,
    and a pin nobody verifies is a comment.
    """
    declared = dict(entry.expect)
    pinned = entry.install.get("version")
    if pinned and "version" not in declared:
        declared["version"] = pinned
    return declared


def _observed(asset: Asset, name: str, recorded) -> Optional[Any]:
    """Where a declared field is actually found on a reported asset."""
    if name == "kind":
        return asset.kind.value
    if name == "liveness":
        return asset.liveness.value
    if name == "version":
        return asset.version
    if name == "install_method":
        return asset.install_method
    value = getattr(asset, name, None)
    if value is None:
        # Anything the collector records as a flag rather than a column:
        # transport, config_scope, pinned, has_identity, risk_factor.
        value = _from_evidence(asset, name)
    return value


def _from_evidence(asset: Asset, name: str) -> Optional[Any]:
    """Fields the collector records as evidence rather than as columns."""
    for flag in asset.flags:
        if flag.startswith(f"{name}="):
            return flag.split("=", 1)[1]
    return None


_TRUE = {"true", "1", "yes"}
_FALSE = {"false", "0", "no"}


def _norm(value: Any) -> str:
    return str(value).strip().lower()


def _same(expected: Any, actual: Any) -> bool:
    """Compare a declared expectation with what the collector reported.

    Booleans are compared by meaning rather than by truthiness. A collector
    reports flags as text, and ``bool("false")`` is True - which silently
    scored every ``pinned = false`` expectation as wrong.
    """
    if isinstance(expected, (list, tuple, set)):
        return {_norm(v) for v in expected} <= {_norm(v) for v in (actual or ())}

    left, right = _norm(expected), _norm(actual)
    if left in _TRUE or left in _FALSE or right in _TRUE or right in _FALSE:
        return (left in _TRUE) == (right in _TRUE)
    return left == right


def _errors(run: Run, manifest: Manifest) -> Dict[str, int]:
    """Errors must be zero, or explained by something the manifest created.

    N-09 plants a dangling symlink precisely so that one error is expected;
    an unexplained error means the collector hit something nobody predicted.
    """
    coverage = run.after.coverage
    denied = len(getattr(coverage, "denied", ()) or ())
    unavailable = len(getattr(coverage, "unavailable", ()) or ())
    count = denied + unavailable
    explained = sum(1 for entry in manifest if entry.explains_error)
    return {"count": count, "explained": min(count, explained),
            "unexplained": max(0, count - explained)}


def _review_queue(run: Run, manifest: Manifest) -> Optional[bool]:
    """N-10 must be triaged, not asserted.

    Being confidently wrong and being silent are different failures, so the
    in-house wrapper is scored on its own: it belongs in the review queue and
    must not appear as an asset.
    """
    wanted = [e for e in manifest if e.must_be_reviewed]
    if not wanted:
        return None
    queued = " ".join(item.path for item in run.after.review_queue).lower()
    names = " ".join(a.name.lower() for a in run.after.assets)
    for entry in wanted:
        token = (entry.name or entry.id).lower()
        if token not in queued or token in names:
            return False
    return True


__all__ = ["Counts", "DUP", "FN", "FP", "Score", "TP", "Verdict", "score"]
