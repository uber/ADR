"""The scorer: three JSON files in, one verdict out.

``score()`` is pure - no VM, no network, no clock - which is what makes it
testable in milliseconds against runs recorded months apart, and what lets a
scoring fix be replayed over every historical run to show exactly which
verdicts moved.
"""

import json
import os
from typing import Any, Dict, List, Optional, Tuple

from ..manifest import Entry, Manifest
from . import schema
from .match import Match, expand, load_snapshot, match_all, norm_path
from .snapshot import Asset, Snapshot, added_assets, duplicate_ids


def score_run(run_dir: str, manifest: Manifest) -> Dict[str, Any]:
    """Score a run directory: the two snapshots plus what actually installed.

    A run directory is the unit of replay. Everything the scorer needs is in it,
    which is why a failed run can be re-scored without being re-run.
    """
    before = load_snapshot(os.path.join(run_dir, "before.json"))
    after = load_snapshot(os.path.join(run_dir, "after.json"))
    with open(os.path.join(run_dir, "manifest.actual.json"), encoding="utf-8") as handle:
        actual = json.load(handle)
    return score(before, after, actual, manifest)


def score(before: Snapshot, after: Snapshot, actual: Dict[str, Any],
          manifest: Manifest) -> Dict[str, Any]:
    """Compare what the collector reported against what was actually installed."""
    platform = actual.get("os", "linux")
    for name, snapshot in (("before", before), ("after", after)):
        repeated = duplicate_ids(snapshot)
        if repeated:
            # A repeated id would silently halve the delta. Refusing is the only
            # honest response: any score computed from it would be wrong in a
            # direction that flatters the collector.
            raise ValueError("%s snapshot repeats asset_id %s" % (name, repeated))
    arrived = added_assets(before, after)
    matches, unclaimed = match_all(manifest, actual, arrived)

    result = schema.blank_score({
        "id": actual.get("run_id", ""),
        "os": platform,
        "image": actual.get("image", ""),
        "collector": actual.get("collector", ""),
        "catalog_version": after.stats.get("catalog_version"),
        "scan_ms": after.stats.get("wall_ms"),
    })
    result["baseline"] = _baseline(before)
    result["manifest"] = _denominator(actual, manifest, platform)

    totals, by_category, misses, duplicates, excluded = _tally(matches, platform)
    inventions = _inventions(matches, unclaimed, totals, by_category)

    result["totals"] = schema.ratios(totals)
    result["by_category"] = {name: schema.ratios(values) for name, values in sorted(by_category.items())}
    result["misses"] = schema.sort_findings(misses)
    result["inventions"] = schema.sort_findings(inventions)
    result["duplicates"] = schema.sort_findings(duplicates)
    result["excluded"] = schema.sort_findings(excluded)
    result["fields"] = _field_accuracy(matches, actual, platform)
    result["errors"] = _errors(after, manifest, platform, actual.get("home"))
    result["review_queue"] = _review_queue(after, manifest, platform, actual.get("home"))
    return result


# -- the parts ---------------------------------------------------------


def _baseline(before: Snapshot) -> Dict[str, Any]:
    """The noise floor. Anything here is a false positive with nothing to blame.

    Not a formality: a baseline that is not near-empty invalidates the whole
    run, because a reported asset can no longer be attributed to the manifest.
    """
    return {"asset_count": len(before.assets), "clean": not before.assets,
            "review_queue_count": len(before.review_queue),
            "assets": [{"name": asset.name, "kind": asset.kind, "install_path": asset.install_path}
                       for asset in before.assets]}


def _denominator(actual: Dict[str, Any], manifest: Manifest, platform: str) -> Dict[str, Any]:
    """How many entries were in play, and why the rest were not.

    A silently shrinking denominator flatters every recall number computed from
    it, so ``failed`` and ``unimplemented`` are counted separately from
    ``unavailable`` and surfaced in their own right.
    """
    statuses: Dict[str, int] = {}
    for record in _records(actual):
        statuses[record.get("status", "unknown")] = statuses.get(record.get("status", "unknown"), 0) + 1
    return {"applicable": len(manifest.for_platform(platform)),
            "installed": statuses.get("installed", 0),
            "unavailable": statuses.get("unavailable", 0),
            "failed": statuses.get("failed", 0),
            "unimplemented": statuses.get("unimplemented", 0),
            "by_status": statuses}


def _records(actual: Dict[str, Any]) -> List[Dict[str, Any]]:
    entries = actual.get("entries", [])
    return list(entries.values()) if isinstance(entries, dict) else list(entries)


def _tally(matches: List[Match], platform: str) -> Tuple[Dict[str, Any], Dict[str, Any],
                                                         List[Dict[str, Any]], List[Dict[str, Any]],
                                                         List[Dict[str, Any]]]:
    """TP, FN and DUP per entry, and per category.

    A duplicate is not a partial success and is never also counted as a TP: it
    inflates a fleet inventory, and folding it into the good column is what let
    it recur.
    """
    totals = schema.empty_totals()
    by_category: Dict[str, Dict[str, Any]] = {}
    misses, duplicates, excluded = [], [], []

    for match in matches:
        entry = match.entry
        bucket = by_category.setdefault(entry.category, schema.empty_totals())
        if match.outcome == "excluded":
            excluded.append({"id": entry.id, "name": entry.name, "category": entry.category,
                             "reason": match.detail})
            continue
        if entry.is_negative:
            continue  # counted as inventions, where their assets belong
        if len(match.assets) == 1:
            totals["tp"] += 1
            bucket["tp"] += 1
        elif not match.assets:
            totals["fn"] += 1
            bucket["fn"] += 1
            misses.append({"id": entry.id, "name": entry.name, "category": entry.category,
                           "shape": entry.shape, "expected": _expected_of(entry, platform)})
        else:
            totals["dup"] += 1
            bucket["dup"] += 1
            duplicates.append({"id": entry.id, "name": entry.name, "category": entry.category,
                               "count": len(match.assets),
                               "assets": [{"asset_id": asset.asset_id, "name": asset.name,
                                           "install_path": asset.install_path,
                                           "install_method": asset.install_method}
                                          for asset in match.assets]})
    return totals, by_category, misses, duplicates, excluded


def _expected_of(entry: Entry, platform: str) -> Dict[str, Any]:
    """What the miss should have looked like, for the person diagnosing it."""
    expected = {"catalog_id": entry.catalog_id, "path": entry.path_for(platform)}
    if entry.declare:
        expected["launches"] = " ".join([str(entry.declare.get("command") or entry.declare.get("url") or "")]
                                        + [str(arg) for arg in entry.declare.get("args", [])])
    return {key: value for key, value in expected.items() if value}


def _inventions(matches: List[Match], unclaimed: List[Asset],
                totals: Dict[str, Any], by_category: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Assets nothing installed, attributed to a control where one explains them.

    Both kinds cost an operator the same time, so both are FPs. Only the
    attribution differs, and the attributed ones are the actionable ones: a
    negative control that fired names the exact lookalike that fooled the
    collector.
    """
    inventions = []
    for match in matches:
        if not match.entry.is_negative or not match.assets:
            continue
        bucket = by_category.setdefault("negative_control", schema.empty_totals())
        for asset in match.assets:
            totals["fp"] += 1
            bucket["fp"] += 1
            inventions.append({"id": match.entry.id, "name": asset.name, "kind": asset.kind,
                               "attributed_to": match.entry.id, "why_wrong": match.entry.reason,
                               "install_path": asset.install_path,
                               "evidence": [item.to_dict() for item in asset.evidence]})
    for asset in unclaimed:
        totals["fp"] += 1
        bucket = by_category.setdefault(_category_of(asset), schema.empty_totals())
        bucket["fp"] += 1
        inventions.append({"id": None, "name": asset.name, "kind": asset.kind,
                           "attributed_to": None,
                           "why_wrong": "reported, but nothing in the manifest installed it",
                           "install_path": asset.install_path,
                           "evidence": [item.to_dict() for item in asset.evidence]})
    return inventions


#: Asset kinds mapped onto the report's categories, so an unattributed invention
#: lands in the table a reader would look for it in.
_KIND_TO_CATEGORY = {
    "cli_agent": "cli_agent", "app": "app", "ai_browser": "app", "extension": "extension",
    "model_runtime": "model_runtime", "ai_frontend": "model_runtime", "agent_platform": "model_runtime",
    "mcp_server": "mcp_server", "mcp_bundle": "mcp_server",
    "skill": "artifact", "plugin": "artifact", "hook": "artifact", "instructions": "artifact",
    "rules": "artifact", "agent": "agent", "scheduled_agent": "agent", "cloud_agent": "agent",
    "ci_agent": "agent", "model_weights": "model_runtime",
}


def _category_of(asset: Asset) -> str:
    return _KIND_TO_CATEGORY.get(asset.kind, "artifact")


def _field_accuracy(matches: List[Match], actual: Dict[str, Any], platform: str) -> Dict[str, Any]:
    """Per-field accuracy over true positives only.

    A tool found with the wrong facts is only partly found. Version and path are
    compared against what the runner *recorded installing*, not against the
    manifest: the manifest states intent, and intent is not what is on the disk.
    """
    records = {record["id"]: record for record in _records(actual)}
    tallies: Dict[str, Dict[str, Any]] = {}

    for match in matches:
        if match.entry.is_negative or len(match.assets) != 1:
            continue
        asset = match.assets[0]
        record = records.get(match.entry.id, {})
        for field, expected in _expectations(match.entry, record, platform).items():
            observed = _observed(asset, field, platform)
            tally = tallies.setdefault(field, {"checked": 0, "correct": 0, "wrong": []})
            tally["checked"] += 1
            if _equal(field, expected, observed, platform):
                tally["correct"] += 1
            else:
                tally["wrong"].append({"id": match.entry.id, "expected": expected, "observed": observed})

    return {field: dict(tally, accuracy=round(tally["correct"] / tally["checked"], 4))
            for field, tally in sorted(tallies.items()) if tally["checked"]}


def _expectations(entry: Entry, record: Dict[str, Any], platform: str) -> Dict[str, Any]:
    """What this entry claims about the asset, from the manifest and from reality."""
    expected: Dict[str, Any] = {}
    for field in schema.SCORED_FIELDS:
        if field in entry.expect:
            expected[field] = entry.expect[field]
    if record.get("version"):
        expected["version"] = record["version"]
    if record.get("path"):
        expected["install_path"] = record["path"]
    return expected


def _observed(asset: Asset, field: str, platform: str) -> Any:
    if field == "pinned":
        return (asset.risk or {}).get("pinned")
    return getattr(asset, field, None)


def _equal(field: str, expected: Any, observed: Any, platform: str) -> bool:
    if field == "install_path":
        return norm_path(str(observed), platform) == norm_path(str(expected), platform)
    if field == "pinned":
        return bool(expected) == bool(observed)
    return str(expected) == str(observed)


def _errors(after: Snapshot, manifest: Manifest, platform: str,
            home: Optional[str] = None) -> Dict[str, Any]:
    """Errors must be zero, or attributable to something the manifest created.

    N-09's dangling symlink is a deliberate error and is expected to produce
    one. Anything else is the collector tripping over the real world, and a run
    that shrugs at unexplained errors is a run that stops noticing them.
    """
    explained_paths = {expand(path, home, platform)
                       for entry in manifest.for_platform(platform) if entry.explains_error
                       for path in ([entry.path_for(platform)] + list((entry.detect or {}).get("paths", [])))
                       if path}
    unexplained = []
    for error in after.errors:
        if norm_path(error.get("path"), platform) not in explained_paths:
            unexplained.append(error)
    return {"count": len(after.errors), "unexplained": len(unexplained), "detail": unexplained}


def _review_queue(after: Snapshot, manifest: Manifest, platform: str,
                  home: Optional[str] = None) -> Dict[str, Any]:
    """The open-world check, scored as its own pass/fail.

    Being confidently wrong and being silent are different failures. An
    uncatalogued AI wrapper must appear in ``review_queue`` and must not appear
    in ``assets``, and neither half implies the other.
    """
    wanted = [entry for entry in manifest.for_platform(platform) if entry.must_be_reviewed]
    queued_paths = {norm_path(item.get("path"), platform) for item in after.review_queue}
    queued_names = {str(item.get("name", "")).lower() for item in after.review_queue}
    rows = []
    for entry in wanted:
        names = {str(name).lower() for name in (entry.detect or {}).get("names", [])}
        paths = {expand(path, home, platform) for path in (entry.detect or {}).get("paths", [])}
        found = bool(names & queued_names) or bool(paths & queued_paths)
        rows.append({"id": entry.id, "name": entry.name, "queued": found})
    return {"expected": len(wanted), "queued": sum(1 for row in rows if row["queued"]),
            "size": len(after.review_queue), "entries": rows,
            "passed": all(row["queued"] for row in rows)}
