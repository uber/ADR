"""Inventory-only access guidance, derived from an existing saved snapshot.

This module does not read the filesystem, TCC databases, conversations or
credentials. A successful settings-navigation request is not a permission
grant, and an error-free partial scan is not proof of Full Disk Access.
"""

from __future__ import annotations

from adr_discovery.coverage.report import summarize_coverage
from adr_discovery.reporter.snapshot import from_dict


def inventory_access_status(
    snapshot: dict | None, *, phase: str = "idle", platform_name: str = "unknown",
    native_available: bool = False,
) -> dict:
    """Bounded diagnostics for the owner UI; never triggers a scan or prompt.

    Return at most 20 access groups and 20 other-location groups, each with
    20 diagnostic examples, plus 40 items per other coverage section. Exact
    counts and explicit omission counts accompany these examples. Retain
    the original snapshot for on-demand inspection of every recorded path.
    """
    report = None
    state = "not_scanned" if snapshot is None else "coverage_unavailable"
    observed_at = None
    if isinstance(snapshot, dict):
        observed_at = snapshot.get("timestamp") if isinstance(snapshot.get("timestamp"), str) else None
        coverage = snapshot.get("coverage")
        if isinstance(coverage, dict):
            try:
                # Do not deserialize assets, findings, or any unrelated
                # saved settings just to show access diagnostics.
                parsed = from_dict({"coverage": coverage}).coverage
                report = summarize_coverage(parsed)
                if report["access"]["path_count"]:
                    state = "access_issues_observed"
                else:
                    state = "no_access_issues_observed"
            except (KeyError, TypeError, ValueError, AttributeError):
                # An unrecognised snapshot is not evidence of access.
                state = "coverage_unavailable"

    is_macos = platform_name.casefold() in ("darwin", "macos")
    categories = report["access"]["categories"] if report else []
    guidance = []
    if "filesystem_permissions" in categories:
        guidance.append({
            "category": "filesystem_permissions",
            "title": "File ownership or ACL permissions",
            "explanation": (
                "The OS reported permission denied (EACCES). Check the location's owner and access rules "
                "only if you want it included. Full Disk Access does not change UNIX ownership or ACLs. "
                "Other users' locations do not need to be made readable."
            ),
        })
    if "os_privacy_or_policy" in categories:
        guidance.append({
            "category": "os_privacy_or_policy",
            "title": "macOS privacy or security policy" if is_macos else "Operating-system security policy",
            "explanation": (
                "The OS reported operation not permitted (EPERM). On macOS this can involve privacy "
                "controls, "
                "App Sandbox, other protected data, or security software; the error alone does not prove "
                "Full Disk Access is missing."
                if is_macos else
                "The OS reported operation not permitted (EPERM). Review the specific operation and "
                "the system's security policy; do not assume changing file modes will fix it."
            ),
        })
    if "unclassified_access" in categories:
        guidance.append({
            "category": "unclassified_access",
            "title": "Access failure needs diagnosis",
            "explanation": (
                "This record has no recognised error code. Keep its path and reason visible; "
                "it does not identify which permission, if any, would help."
            ),
        })

    return {
        "state": state,
        "phase": phase,
        "observed_at": observed_at,
        "basis": "saved_inventory_coverage",
        "full_disk_access": "not_determined",
        "can_continue": True,
        "can_rescan": phase != "scanning",
        "coverage": report,
        "guidance": guidance,
        "setup": {
            "title": "Choose what inventory can check",
            "explanation": (
                "Inventory can use the locations already readable. Additional access is optional. "
                "Privacy exclusions, symlink safety rules, and scan limits still apply."
            ),
            "settings_available": is_macos and native_available,
            "settings_targets": ["files_and_folders", "full_disk_access"] if is_macos else [],
            "manual_steps": (
                "System Settings > Privacy & Security > Files & Folders for applicable locations, "
                "or Full Disk Access if you choose broader access. Review the entry for the app "
                "that actually runs inventory."
                if is_macos else
                "Review the reported location and operating-system error before changing access."
            ),
            "after_change": (
                "If you change access, fully quit and reopen ADR, then explicitly scan again. "
                "Opening Settings does not grant access, and some restrictions may remain."
            ),
        },
    }
