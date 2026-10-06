"""Opt-in credential-path defaults. Never read credential contents or install hooks."""

import platform
from pathlib import Path

from .policy import _comparison, _same_file, _within, resolve_path, validate_rule

STARTER_ID = "sensitive-paths-v1"

# Standard locations only, not a claim to discover every credential on a device.
# Public vendor references and limitations are in docs/DEFAULT_PROTECTION.md.
COMMON_PATHS = (
    ("ssh", ".ssh", "directory", "SSH keys", "Private keys and SSH configuration."),
    ("gpg", ".gnupg", "directory", "GPG keys", "Private keys and the GnuPG key store."),
    ("aws", ".aws", "directory", "AWS credentials", "Shared credentials, role credentials, and SSO caches."),
    ("gcloud", ".config/gcloud", "directory", "Google Cloud credentials", "CLI and application credentials."),
    ("azure", ".azure", "directory", "Azure credentials", "CLI account and authentication caches."),
    (
        "kubernetes",
        ".kube/config",
        "file",
        "Kubernetes access",
        "Cluster credentials and client-key references.",
    ),
    ("docker", ".docker/config.json", "file", "Docker credentials", "Registry authentication configuration."),
    ("git", ".git-credentials", "file", "Git credentials", "Credentials saved by Git's plaintext store."),
    (
        "git-xdg",
        ".config/git/credentials",
        "file",
        "Git credentials (XDG)",
        "Git's alternative plaintext credential store.",
    ),
    ("npm", ".npmrc", "file", "npm tokens", "User-level registry tokens and authentication settings."),
    ("pypi", ".pypirc", "file", "Python package tokens", "Package-upload credentials and API tokens."),
    (
        "netrc",
        ".netrc",
        "file",
        "Network credentials",
        "Host login credentials used by command-line clients.",
    ),
)


def starter_catalog() -> list[dict]:
    """Return standard paths, including not-yet-created files; do not inspect contents."""
    system = platform.system()
    if system not in ("Darwin", "Linux"):
        return []
    home = Path.home()
    definitions = COMMON_PATHS
    if system == "Darwin":
        definitions = (
            (
                "keychains",
                "Library/Keychains",
                "directory",
                "macOS Keychain files",
                "User Keychain databases. This rule does not control Keychain API access.",
            ),
            *definitions,
        )
    return [
        {
            "key": key,
            "path": str(home / relative),
            "kind": kind,
            "action": "block",
            "label": label,
            "description": description,
        }
        for key, relative, kind, label, description in definitions
    ]


def starter_preview(snapshot: dict) -> dict:
    """Keep existing choices, including Ask rules inside a proposed Block folder."""
    home = Path.home().resolve()
    rules = list(snapshot["rules"]) + [
        {"path": path, "kind": kind, "action": "block"} for path, kind in snapshot.get("control_paths", [])
    ]
    resolved_rules = []
    review_required = 0
    for rule in rules:
        try:
            resolved_rules.append((rule, resolve_path(rule["path"], str(home))))
        except (OSError, RuntimeError, ValueError):
            review_required += 1
    items = []
    for candidate in starter_catalog():
        item = {**candidate, "state": "available", "note": "Block direct file-tool access"}
        if review_required:
            item.update(state="unavailable", note="An existing rule has an unreadable path; review it first.")
            items.append(item)
            continue
        try:
            validated = validate_rule(
                candidate["path"], candidate["action"], candidate["kind"], candidate["label"]
            )
            target = resolve_path(validated["path"], str(home))
            # Never turn a credential-directory symlink into a broad home/root rule.
            if _within(home, target):
                raise ValueError(
                    "This location resolves to your home folder or a parent; choose it manually."
                )
            if target.exists():
                expected_type = target.is_dir() if candidate["kind"] == "directory" else target.is_file()
                if not expected_type:
                    raise ValueError("This location has an unexpected file type; review it manually.")
            item.update(validated)
        except (OSError, RuntimeError, ValueError):
            item.update(
                state="unavailable", note="This path could not be safely prepared; review it manually."
            )
            items.append(item)
            continue

        covering = []
        overlapping = False
        for rule, existing in resolved_rules:
            same = _comparison(target) == _comparison(existing) or _same_file(target, existing)
            if (
                rule["kind"] == "directory"
                and _within(target, existing)
                or same
                and rule["kind"] == candidate["kind"]
            ):
                covering.append(rule)
            if same or candidate["kind"] == "directory" and _within(existing, target):
                overlapping = True
        if covering:
            action = "block" if any(rule["action"] == "block" for rule in covering) else "ask"
            item.update(
                state="covered",
                existing_action=action,
                note="Existing Block rule kept" if action == "block" else "Existing Ask first rule kept",
            )
        elif overlapping:
            # A new parent Block would override a user's more specific Ask rule.
            # Skip the folder rather than silently changing that user's decision.
            item.update(state="custom", note="Overlaps a custom rule; left unchanged")
        items.append(item)
    return {
        "id": STARTER_ID,
        "supported": bool(items),
        "enabled": snapshot.get("enabled", True),
        "review_required": review_required,
        "items": items,
        "available": sum(item["state"] == "available" for item in items),
        "covered": sum(item["state"] == "covered" for item in items),
        "custom": sum(item["state"] == "custom" for item in items),
        "unavailable": sum(item["state"] == "unavailable" for item in items),
    }
