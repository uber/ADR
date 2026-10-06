"""Classify evidence, not guessed permission grants.

An EPERM is not proof that macOS Full Disk Access is disabled. App Sandbox,
other mandatory access controls and security software can produce it too.
Keep unknown legacy denial strings visible rather than assuming success.
"""

from __future__ import annotations

import errno


def classify_denial(reason: str, error_number: int | None = None) -> tuple[str, str]:
    """Return (section, category) for current or pre-errno coverage records.

    Legacy snapshots stored intentional exclusions and every OSError in
    ``denied``. Recognise only known reasons; unfamiliar records remain
    access issues that need diagnosis, never silently become a skip.
    """
    if error_number == errno.EACCES:
        return "access", "filesystem_permissions"
    if error_number == errno.EPERM:
        return "access", "os_privacy_or_policy"
    if error_number == errno.ENOENT:
        return "skipped", "missing"
    if error_number == errno.ENOTDIR:
        return "skipped", "not_directory"
    if error_number == errno.ELOOP:
        return "skipped", "symlink_safety"
    if error_number is not None:
        return "skipped", "io_error"

    normal = reason.strip().casefold()
    if normal in ("permission denied", "eacces"):
        return "access", "filesystem_permissions"
    if normal in ("operation not permitted", "eperm"):
        return "access", "os_privacy_or_policy"
    if normal in ("personal_path", "privacy_policy"):
        return "skipped", "privacy_policy"
    if normal in ("outside_root", "safety_boundary"):
        return "skipped", "safety_boundary"
    if normal in ("target swapped after validation", "swapped", "target_changed", "changed_path"):
        return "skipped", "changed_path"
    if normal in ("no such file or directory", "absent", "missing"):
        return "skipped", "missing"
    if normal in ("not a directory", "not_directory"):
        return "skipped", "not_directory"
    if normal in ("too many levels of symbolic links", "symlink_not_followed", "symlink_safety"):
        return "skipped", "symlink_safety"
    if normal in ("scope_excluded", "platform_root", "scanner_scope"):
        return "skipped", "scanner_scope"
    if normal in ("input/output error", "too many open files", "io_error"):
        return "skipped", "io_error"
    if normal in ("invalid_path", "unresolvable", "unsupported_operation"):
        return "skipped", "invalid_path"
    return "access", "unclassified_access"
