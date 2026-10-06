"""Pure, bounded presentation of coverage, including older saved snapshots.

Grouping is lexical display organisation, not proof of app ownership and
not a security boundary. No paths are probed or resolved here. The original
coverage remains the lossless diagnostic record.
"""

from __future__ import annotations

import errno
from dataclasses import asdict

from ..contracts.snapshot import Coverage
from .reasons import classify_denial


def location_root(path: str) -> str:
    """Group by app data directory, home subtree, app bundle or system root."""
    value = path.replace("\\", "/")
    parts = [part for part in value.split("/") if part]
    if not parts:
        return value or "(unknown location)"
    prefix = "//" if value.startswith("//") else "/" if value.startswith("/") else ""
    # A temporary tree can contain many copied .app bundles. Those are not
    # separate installed applications or separate permissions to request.
    for temporary_root in (["var", "folders"], ["private", "var", "folders"]):
        if parts[:len(temporary_root)] == temporary_root:
            return prefix + "/".join(temporary_root)
    home_end = 0
    if parts[0] in ("Users", "home") and len(parts) >= 2:
        home_end = 2
    elif parts[0] == "root":
        home_end = 1
    elif parts[:2] == ["var", "root"]:
        home_end = 2
    elif len(parts) >= 3 and parts[0].endswith(":") and parts[1].casefold() == "users":
        home_end = 3

    # A bundle, app container or app-specific settings subtree is a more
    # useful label than hundreds of children, without inventing an owner.
    for index, part in enumerate(parts):
        if part.endswith(".app"):
            return prefix + "/".join(parts[:index + 1])
    end = min(len(parts), home_end + 1) if home_end else min(len(parts), 2)
    tail = parts[home_end:]
    if tail and tail[0] == "Library":
        end = min(len(parts), home_end + 2)
        if len(tail) >= 3 and tail[1] in ("Application Support", "Containers", "Group Containers"):
            end = home_end + 3
    elif len(tail) >= 2 and tail[0] == ".config":
        end = home_end + 2
    elif len(tail) >= 3 and tail[0] == "AppData" and tail[1] in ("Local", "LocalLow", "Roaming"):
        end = home_end + 3
    return prefix + "/".join(parts[:end])


def _diagnostic(
    path: str, reason: str, category: str, error_number: int | None,
    operations: tuple[str, ...], occurrences: int, detail: str = "",
) -> dict:
    return {
        "path": path,
        "reason": reason,
        "category": category,
        "detail": detail,
        "errno": error_number,
        "errno_name": errno.errorcode.get(error_number) if error_number is not None else None,
        "operations": list(operations),
        "occurrences": occurrences,
    }


def _group(records: list[dict], group_limit: int, detail_limit: int) -> dict:
    # De-duplicate old snapshots too. Do not merge different failures at the
    # same path: the reason and numeric error remain independently visible.
    merged: dict[tuple, dict] = {}
    for record in records:
        key = (record["path"], record["category"], record["reason"], record["errno"], record["detail"])
        if key in merged:
            merged[key]["occurrences"] += record["occurrences"]
            merged[key]["operations"] = sorted(set(merged[key]["operations"] + record["operations"]))
        else:
            merged[key] = {**record, "operations": sorted(set(record["operations"]))}
    grouped: dict[str, list[dict]] = {}
    for record in merged.values():
        grouped.setdefault(location_root(record["path"]), []).append(record)
    groups = []
    for root, details in sorted(grouped.items()):
        details.sort(key=lambda item: (item["path"], item["category"], item["reason"], str(item["errno"])))
        categories = sorted({item["category"] for item in details})
        groups.append({
            "root": root,
            "path_count": len({item["path"] for item in details}),
            "diagnostic_count": len(details),
            "occurrences": sum(item["occurrences"] for item in details),
            "categories": categories,
            "details": details[:detail_limit],
            "omitted_details": max(0, len(details) - detail_limit),
        })
    categories = sorted({item["category"] for item in merged.values()})
    category_counts = {}
    for category in categories:
        items = [item for item in merged.values() if item["category"] == category]
        category_counts[category] = {
            "path_count": len({item["path"] for item in items}),
            "diagnostic_count": len(items),
            "occurrences": sum(item["occurrences"] for item in items),
        }
    return {
        "path_count": len({item["path"] for item in merged.values()}),
        "diagnostic_count": len(merged),
        "occurrences": sum(item["occurrences"] for item in merged.values()),
        "group_count": len(groups),
        "categories": categories,
        # Safe to inspect without exposing paths. Category path counts can
        # overlap when one path produced more than one kind of failure.
        "category_counts": category_counts,
        "groups": groups[:group_limit],
        "omitted_groups": max(0, len(groups) - group_limit),
    }


def _bounded(records, limit: int) -> dict:
    # These dataclasses contain scalar fields. Preserve exact details while
    # suppressing duplicates from overlapping source checks.
    unique = list(dict.fromkeys(records))
    return {
        "count": len(unique),
        "items": [asdict(item) for item in unique[:limit]],
        "omitted": max(0, len(unique) - limit),
    }


def _records(coverage: Coverage):
    access: list[dict] = []
    skipped: list[dict] = []
    for item in coverage.denied:
        section, category = classify_denial(item.reason, item.errno)
        target = access if section == "access" else skipped
        target.append(_diagnostic(
            item.path, item.reason, category, item.errno, item.operations, item.occurrences,
        ))
    for item in coverage.skipped:
        section, category = classify_denial(item.reason)
        # Explicit skips cannot turn into permission issues because a new
        # skip reason is unfamiliar to an older renderer.
        if section == "access":
            category = "other_skip"
        skipped.append(_diagnostic(
            item.path, item.reason, category, item.errno, item.operations, item.occurrences, item.detail,
        ))
    limits = []
    for item in coverage.boundaries_hit:
        if item.boundary == "scope_excluded":
            skipped.append(_diagnostic(
                item.path, item.boundary, "scanner_scope", None, ("walk",), 1, item.detail,
            ))
        else:
            limits.append(item)
    return access, skipped, limits


def coverage_page(
    coverage: Coverage, *, section: str = "access", root: str | None = None,
    offset: int = 0, limit: int = 20,
) -> dict:
    """Paginate every recorded group/detail, without probing any supplied path."""
    if section not in ("access", "skipped") or type(offset) is not int or not 0 <= offset <= 100000:
        raise ValueError("Invalid coverage page")
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("Invalid coverage page size")
    access, skipped, _ = _records(coverage)
    records = access if section == "access" else skipped
    if root is None:
        items = _group(records, max(1, len(records)), 20)["groups"]
    else:
        selected = [record for record in records if location_root(record["path"]) == root]
        grouped = _group(selected, 1, max(1, len(selected)))["groups"]
        items = grouped[0]["details"] if grouped else []
    end = offset + limit
    return {
        "items": items[offset:end], "offset": offset, "total": len(items),
        "next_offset": end if end < len(items) else None,
    }


def summarize_coverage(
    coverage: Coverage, *, group_limit: int = 20, details_per_group: int = 20,
    item_limit: int = 40,
) -> dict:
    """Return bounded examples with exact total counts and explicit omissions.

    Access path/group counts are NOT numbers of permission grants required.
    Callers should retain the raw coverage for on-demand local diagnostics,
    and must not interpret no observed failures as universal disk access.
    """
    if any(
        type(value) is not int or not 1 <= value <= ceiling
        for value, ceiling in ((group_limit, 100), (details_per_group, 100), (item_limit, 200))
    ):
        raise ValueError("coverage display limits must be positive and bounded")
    access, skipped, limits = _records(coverage)
    return {
        "access": _group(access, group_limit, details_per_group),
        "skipped": _group(skipped, group_limit, details_per_group),
        "limits": _bounded(limits, item_limit),
        "unavailable": _bounded(coverage.unavailable, item_limit),
        "truncated": _bounded(coverage.truncated, item_limit),
        "failed_probes": _bounded(
            (item for item in coverage.probes if item.status in ("failed", "degraded")), item_limit,
        ),
        # "Swept" only means enumeration started, not that the root was
        # fully checked. Limits and errors must remain next to this count.
        "roots_swept": _bounded(coverage.roots_swept, item_limit),
        "out_of_scope": list(coverage.out_of_scope),
    }
