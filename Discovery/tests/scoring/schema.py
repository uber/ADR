"""score.json - the shape, and the gate that reads it.

One file for machines and trends. Every miss and invention is keyed by
manifest id, so a regression is reported as ``M-SITE-08 went from TP to FN``
rather than as a number that moved.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .score import Score

SCHEMA_VERSION = 1

#: Anything here fails a run outright, whatever the recall number says.
ABSOLUTE = ("canary_leaked", "baseline_dirty", "unexplained_errors", "duplicates", "review_queue")


@dataclass(frozen=True)
class Gate:
    passed: bool
    reasons: Tuple[str, ...] = ()

    def as_dict(self) -> Dict[str, Any]:
        return {"passed": self.passed, "reasons": list(self.reasons)}


def to_dict(score: Score) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "run": {"id": score.run_id, "os": score.os, "image": score.image,
                "collector": score.collector},
        "baseline": {"asset_count": score.baseline_assets, "clean": score.baseline_clean},
        "manifest": score.manifest_counts,
        "totals": score.totals.as_dict(),
        "by_category": {name: counts.as_dict() for name, counts in score.by_category.items()},
        "fields": score.fields,
        "canaries": score.canaries.as_dict(),
        "errors": score.errors,
        "review_queue": {"ok": score.review_queue_ok},
        "misses": [{"id": v.entry_id, "category": v.category, "reason": v.detail}
                   for v in score.misses],
        "inventions": [{"id": v.entry_id, "category": v.category, "detail": v.detail}
                       for v in score.inventions],
        "duplicates": [{"id": v.entry_id, "category": v.category, "assets": list(v.assets)}
                       for v in score.duplicates],
    }


def to_json(score: Score, indent: Optional[int] = 2) -> str:
    return json.dumps(to_dict(score), indent=indent, sort_keys=True)


def gate(score: Score, previous: Optional[Dict[str, Any]] = None) -> Gate:
    """Pass or fail, with every reason rather than the first one.

    Recall is compared against the previous accepted run for the same OS
    rather than an absolute threshold: real endpoints are not perfectly
    reproducible, and a fixed number would either be gamed or ignored.
    """
    reasons: List[str] = []

    if not score.canaries.clean:
        leaked = ", ".join(sorted(leak.name for leak in score.canaries.leaks))
        reasons.append(f"canary leaked: {leaked}")
    if not score.baseline_clean:
        reasons.append(f"baseline reported {score.baseline_assets} assets before installation")
    if score.errors.get("unexplained"):
        reasons.append(f"{score.errors['unexplained']} unexplained errors")
    if score.totals.dup:
        reasons.append(f"{score.totals.dup} duplicate assets")
    if score.review_queue_ok is False:
        reasons.append("review queue did not contain the in-house wrapper")

    if previous:
        before = (previous.get("totals") or {}).get("recall")
        now = score.totals.recall
        same_os = previous.get("run", {}).get("os", score.os) == score.os
        if same_os and before is not None and now is not None and now < before:
            reasons.append(f"recall fell from {before} to {now}")

    return Gate(passed=not reasons, reasons=tuple(reasons))


__all__ = ["ABSOLUTE", "Gate", "SCHEMA_VERSION", "gate", "to_dict", "to_json"]
