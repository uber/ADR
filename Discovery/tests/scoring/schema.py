"""The shape of ``score.json``.

Every miss and every invention is keyed by manifest id, so a regression reads
as ``M-SITE-08 went from TP to FN`` rather than as "MCP recall dropped". The
aggregate is for trends; the ids are what somebody fixes.
"""

from typing import Any, Dict, List

#: Bumped when a consumer of score.json would have to change. Trend tracking
#: compares runs across months, and a silently reshaped file makes the history
#: wrong rather than absent.
SCORE_VERSION = 1

OUTCOMES = ("tp", "fp", "fn", "dup")

#: Fields compared over true positives only. Reported per field rather than
#: blended: a collector that always gets `version` right and always gets
#: `config_scope` wrong has a specific bug, and an average hides it.
SCORED_FIELDS = ("version", "install_path", "install_method", "config_scope",
                 "transport", "pinned", "liveness")

#: Why a run failed, in the order a reader should care. Canary leaks come first
#: because they invalidate everything below them.
GATE_REASONS = ("canary_leaked", "baseline_dirty", "unexplained_errors",
                "duplicates", "recall_regressed", "review_queue_miss")


def empty_totals() -> Dict[str, Any]:
    return {"tp": 0, "fp": 0, "fn": 0, "dup": 0, "recall": None, "precision": None}


def ratios(totals: Dict[str, Any]) -> Dict[str, Any]:
    """Recall and precision, or ``None`` where the denominator is empty.

    ``None`` rather than 1.0: a category with nothing installed has no recall,
    and recording a perfect score for it would flatter every pooled average
    somebody later computes from this file.
    """
    tp, fp, fn = totals["tp"], totals["fp"], totals["fn"]
    totals["recall"] = round(tp / (tp + fn), 4) if (tp + fn) else None
    totals["precision"] = round(tp / (tp + fp), 4) if (tp + fp) else None
    return totals


def blank_score(run: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "score_version": SCORE_VERSION,
        "run": run,
        "baseline": {},
        "manifest": {},
        "totals": empty_totals(),
        "by_category": {},
        "fields": {},
        "canaries": {},
        "errors": {},
        "review_queue": {},
        "misses": [],
        "inventions": [],
        "duplicates": [],
        "excluded": [],
        "gate": {"passed": True, "reasons": []},
    }


def sort_findings(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Stable order by manifest id, so two runs diff cleanly."""
    return sorted(rows, key=lambda row: str(row.get("id") or row.get("name") or ""))
