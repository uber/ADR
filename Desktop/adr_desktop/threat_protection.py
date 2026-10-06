"""Owner-managed artifact intelligence, bounded local checks, and denial receipts."""

import copy
import hashlib
import json
import os
import threading
from collections import Counter, OrderedDict
from pathlib import Path

from .artifact_identity import (
    IdentityBudget,
    configured_mcp_definitions,
    inspect_file,
    inspect_mcp_definition,
    skill_roots,
)
from .config import canonical, utcnow
from .policy import printable
from .threat_feed import (
    BUNDLED_FEED_ID,
    compile_generation,
    compose_generation,
    generation_summary,
    load_bundled_feed,
    parse_feed_json,
    validate_generation,
)

HARNESS_NAMES = ("claude", "codex", "opencode", "copilot")
MAX_SCAN_ITEMS = 512
MAX_SCAN_FINDINGS = 100
MAX_SCAN_PROJECTS = 24
MAX_SCAN_ROOTS = 128
MAX_POLICY_BYTES = 1024 * 1024
SCAN_STATES = frozenset({"not_run", "complete", "partial", "error"})


class ThreatStateConflict(ValueError):
    """The owner must refresh rather than overwriting another policy edit."""


def initialize_threats(previous):
    """Refresh the bundled baseline while retaining validated owner additions."""
    enabled, imported_at, old_generation = True, None, None
    if previous is not None:
        if (
            not isinstance(previous, dict)
            or set(previous) != {"enabled", "generation", "imported_at"}
            or type(previous["enabled"]) is not bool
            or (previous["imported_at"] is not None and not isinstance(previous["imported_at"], str))
        ):
            raise ValueError("The saved artifact blocking settings are invalid; they were not replaced")
        old_generation = validate_generation(previous["generation"])
        enabled, imported_at = previous["enabled"], previous["imported_at"]
    custom = old_generation["feeds"][1] if old_generation and len(old_generation["feeds"]) == 2 else None
    try:
        baseline = load_bundled_feed()
        generation = compose_generation(baseline, custom)
    except (OSError, ValueError):
        if old_generation is None:
            raise ValueError(
                "The bundled threat list could not be validated; no policy was replaced"
            ) from None
        return {
            "enabled": enabled, "generation": old_generation, "imported_at": imported_at,
        }, "The updated bundled list could not be applied. The last accepted list is still in use."
    return {
        "enabled": enabled, "generation": generation, "imported_at": imported_at,
    }, None


def _empty_scan():
    return {
        "state": "not_run", "checked_at": None, "generation": None, "stale": False,
        "checked_items": 0, "skipped_items": 0, "findings": [], "issues": [],
    }


def _display(value, maximum=8192):
    return printable(str(value))[:maximum]


class ThreatProtection:
    def __init__(self, runtime):
        self.runtime = runtime
        self.store = runtime.store
        self.check_lock = threading.Lock()
        self.generations_lock = threading.Lock()
        self.generations = OrderedDict()
        self.remember_generation(runtime.policy["threats"]["generation"])

    def remember_generation(self, generation, *, compiled=None):
        compiled = compiled or compile_generation(generation)
        with self.generations_lock:
            self.generations[compiled.digest] = compiled
            self.generations.move_to_end(compiled.digest)
            while len(self.generations) > 8:
                self.generations.popitem(last=False)

    def _snapshot(self):
        with self.runtime.policy_lock:
            return self.runtime.policy["revision"], copy.deepcopy(self.runtime.policy["threats"])

    def _check_revision(self, expected):
        if expected != self.runtime.policy["revision"]:
            raise ThreatStateConflict("Protection settings changed. Refresh and review the change again.")

    def _publish(self, config):
        updated = copy.deepcopy(self.runtime.policy)
        updated["threats"] = config
        # Leave room for the revision replaced by _publish_policy. Never publish
        # an authority that the bounded offline hook cannot subsequently read.
        if len(canonical(updated).encode()) > MAX_POLICY_BYTES - 128:
            raise ValueError("The combined protection policy is too large")
        self.runtime._publish_policy(updated)

    def change_settings(self, *, enabled, expected_revision):
        if type(enabled) is not bool:
            raise ValueError("Choose whether artifact blocking is enabled")
        with self.runtime.policy_lock:
            self._check_revision(expected_revision)
            updated = copy.deepcopy(self.runtime.policy["threats"])
            updated["enabled"] = enabled
            self._publish(updated)
        self.store.audit(
            "threat_protection_changed",
            "Known-malicious artifact blocking enabled" if enabled
            else "Known-malicious artifact blocking disabled",
        )
        return self.status()

    def _import_candidate(self, document, expected_revision):
        custom = parse_feed_json(document)
        with self.runtime.policy_lock:
            self._check_revision(expected_revision)
            current = copy.deepcopy(self.runtime.policy["threats"])
        generation = compose_generation(current["generation"]["feeds"][0], custom)
        return custom, generation, current

    def preview_import(self, document, *, expected_revision):
        custom, generation, current = self._import_candidate(document, expected_revision)
        summary = generation_summary(generation)
        metadata = next(item for item in summary["feeds"] if item["feed_id"] == custom["feed_id"])
        return {
            "feed_id": custom["feed_id"], "revision": custom["revision"],
            "active_indicators": metadata["active"], "revoked_indicators": metadata["revoked"],
            "all_versions_count": sum(
                item["status"] == "active" and item["target"].get("all_versions") is True
                for item in custom["indicators"]
            ),
            "counts": {key: summary[key] for key in (
                "file_sha256", "skill_sha256", "npm", "pypi", "mcp_endpoint", "package_versions", "total",
            )},
            "replaces_custom": len(current["generation"]["feeds"]) == 2,
            "expected_revision": expected_revision,
        }

    def import_feed(self, document, *, expected_revision, confirm=False):
        if confirm is not True:
            raise ValueError("Review and confirm the local threat-list import")
        custom, generation, _ = self._import_candidate(document, expected_revision)
        with self.runtime.policy_lock:
            self._check_revision(expected_revision)
            updated = copy.deepcopy(self.runtime.policy["threats"])
            updated.update(generation=generation, imported_at=utcnow())
            self._publish(updated)
        self.store.audit(
            "threat_list_imported", "Imported an owner-selected local threat list",
            {"feed_id": custom["feed_id"], "revision": custom["revision"]},
        )
        return self.status()

    def _scan(self):
        row = self.store.one("SELECT payload FROM artifact_scan WHERE id=1")
        if not row:
            return _empty_scan()
        value = json.loads(row["payload"])
        if value.get("state") not in SCAN_STATES:
            return _empty_scan()
        return value

    def summary(self):
        revision, config = self._snapshot()
        scan = self._scan()
        return {
            "revision": revision, "enabled": config["enabled"],
            "generation": config["generation"]["digest"],
            "latest_block_id": (
                self.store.one("SELECT id FROM artifact_blocks ORDER BY id DESC LIMIT 1") or {"id": 0}
            )["id"],
            "scan_revision": scan.get("checked_at"),
        }

    def status(self):
        revision, config = self._snapshot()
        summary = generation_summary(config["generation"])
        warning = getattr(self.runtime, "threat_feed_warning", None)
        scan = self._scan()
        scan["stale"] = bool(scan["generation"] and scan["generation"] != summary["digest"])
        return {
            "enabled": config["enabled"], "revision": revision,
            "feed": {
                "state": "degraded" if warning else "ready" if summary["total"] else "empty",
                "generation": summary["digest"],
                "counts": {key: summary[key] for key in (
                    "file_sha256", "skill_sha256", "npm", "pypi", "mcp_endpoint", "package_versions", "total",
                )},
                "feeds": [{
                    "feed_id": item["feed_id"], "revision": item["revision"],
                    "published_at": item["published_at"],
                    "active_indicators": item["active"], "revoked_indicators": item["revoked"],
                } for item in summary["feeds"]],
                "imported_at": config["imported_at"],
                "has_custom": any(item["feed_id"] != BUNDLED_FEED_ID for item in summary["feeds"]),
                "error": warning,
            },
            "scan": scan,
            "blocks": self.store.rows("SELECT * FROM artifact_blocks ORDER BY id DESC LIMIT 25"),
        }

    def record_block(self, decision, *, harness, source):
        """Accept only actual denials with metadata from a recently accepted feed."""
        if isinstance(decision, dict):
            denied, artifact = decision.get("decision") == "deny", decision.get("artifact")
            session, tool = decision.get("session_id", ""), decision.get("tool", "")
        else:
            denied, artifact = decision.decision == "deny", decision.artifact
            session, tool = decision.session_id, decision.tool
        if not denied or not isinstance(artifact, dict) or source not in {"hook", "approval", "vault"}:
            return False
        # A newly published offline policy can be read immediately by a hook.
        # Wait for the publication transaction to finish registering its index.
        with self.runtime.policy_lock, self.generations_lock:
            compiled = self.generations.get(artifact.get("generation"))
        record = compiled.catalog().get(artifact.get("indicator_id")) if compiled else None
        if not record or any(
            artifact.get(key) != record[key] for key in ("source_id", "kind", "target_display")
        ):
            return False
        # Store the verified feed label, not a hook-supplied command/config value.
        self.store.execute(
            """INSERT INTO artifact_blocks(
               timestamp,harness,session_id,tool,indicator_id,source_id,kind,generation,target_display,source
               ) VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (utcnow(), _display(harness, 40), _display(session, 512), _display(tool, 200),
             record["indicator_id"], record["source_id"], record["kind"], compiled.digest,
             record["target_display"], source),
        )
        return True

    def _persist_scan(self, result):
        self.store.execute(
            "INSERT INTO artifact_scan(id,payload) VALUES (1,?) "
            "ON CONFLICT(id) DO UPDATE SET payload=excluded.payload",
            (canonical(result),),
        )

    def check_installed(self):
        """Inspect known local roots and inventory candidates, without starting them."""
        if not self.check_lock.acquire(blocking=False):
            raise ThreatStateConflict("An installed-item check is already running")
        try:
            _, config = self._snapshot()
            compiled = compile_generation(config["generation"])
            result = _empty_scan()
            result.update(state="complete", generation=compiled.digest, checked_at=utcnow())
            issues, checked, findings, associations = Counter(), set(), {}, {}
            budget = IdentityBudget(seconds=4, max_files=512, max_total_bytes=32 * 1024 * 1024)
            inventory = self.store.settings().get("inventory_snapshot", {})
            assets = inventory.get("assets", []) if isinstance(inventory, dict) else []
            assets = assets if isinstance(assets, list) else []
            if len(assets) > 2000:
                issues["inventory_limit"] += 1
            assets = [item for item in assets[:2000] if isinstance(item, dict)]

            def consume(evidence, *, label=None, inventory_asset_id=None):
                issues.update(evidence.unresolved)
                for candidate in evidence.candidates:
                    display_label = _display(label or candidate.label, 200)
                    checked.add((candidate.location, display_label))
                    for match in compiled.match(candidate.subject):
                        key = canonical([match["indicator_id"], candidate.location, display_label])
                        if len(findings) >= MAX_SCAN_FINDINGS and key not in findings:
                            issues["finding_limit"] += 1
                            continue
                        links = associations.setdefault(key, set())
                        if inventory_asset_id:
                            links.add(inventory_asset_id)
                        findings[key] = {
                            "id": hashlib.sha256(key.encode()).hexdigest()[:32],
                            **{field: match[field] for field in (
                                "indicator_id", "source_id", "kind", "target_display",
                                "summary", "references",
                            )},
                            "location": _display(candidate.location), "label": display_label,
                            "inventory_asset_id": next(iter(links)) if len(links) == 1 else None,
                        }

            projects = [str(Path.home())]
            projects.extend(row["project"] for row in self.store.rows(
                "SELECT DISTINCT project FROM sessions WHERE project<>'' ORDER BY project LIMIT ?",
                (MAX_SCAN_PROJECTS + 1,),
            ) if Path(row["project"]).is_absolute())
            projects = list(dict.fromkeys(projects))
            if len(projects) > MAX_SCAN_PROJECTS:
                issues["project_limit"] += 1
            projects = projects[:MAX_SCAN_PROJECTS]

            seen_configs = set()
            for project in projects:
                for harness in HARNESS_NAMES:
                    try:
                        budget.check()
                    except ValueError:
                        issues["check_limit"] += 1
                        break
                    diagnostics = []
                    definitions = configured_mcp_definitions(
                        harness, project, self.runtime.state_dir, budget=budget, diagnostics=diagnostics,
                    )
                    issues.update(diagnostics)
                    for alias, definition, path in definitions:
                        # Disabled entries are findings about configuration, not live use.
                        key = (str(path), alias, canonical(definition), project)
                        if key in seen_configs:
                            continue
                        seen_configs.add(key)
                        consume(
                            inspect_mcp_definition(definition, path, project, budget=budget),
                            label=f"{alias} · {harness}",
                        )

            roots = []
            for project in projects:
                for harness in HARNESS_NAMES:
                    roots.extend(skill_roots(harness, project))
            files = {}

            def add_manifest(manifest, asset_id=None):
                try:
                    canonical_path = Path(manifest).resolve(strict=False)
                except (OSError, RuntimeError, ValueError):
                    issues["file_unresolved"] += 1
                    return
                # Coalesce aliases such as macOS /var and /private/var before
                # associating findings with a unique inventory record.
                identifiers = files.setdefault(canonical_path, set())
                if isinstance(asset_id, str) and asset_id:
                    identifiers.add(asset_id)

            for asset in assets:
                path = asset.get("install_path") or asset.get("path")
                if not isinstance(path, str) or not Path(path).is_absolute():
                    continue
                if asset.get("kind") == "skill":
                    manifest = Path(path) if Path(path).name == "SKILL.md" else Path(path) / "SKILL.md"
                    add_manifest(manifest, asset.get("asset_id"))
                elif asset.get("kind") == "plugin":
                    roots.append(Path(path) / "skills")
            roots = list(dict.fromkeys(roots))
            if len(roots) > MAX_SCAN_ROOTS:
                issues["root_limit"] += 1
            # Explicit roots, at most one hidden grouping directory; never a
            # recursive device walk or a scan of arbitrary package dependencies.
            for root in roots[:MAX_SCAN_ROOTS]:
                if len(files) >= MAX_SCAN_ITEMS:
                    issues["item_limit"] += 1
                    break
                try:
                    budget.check()
                    with os.scandir(root) as entries:
                        for index, entry in enumerate(entries):
                            if index >= MAX_SCAN_ITEMS or len(files) >= MAX_SCAN_ITEMS:
                                issues["item_limit"] += 1
                                break
                            budget.check()
                            if entry.is_dir(follow_symlinks=False):
                                manifest = Path(entry.path) / "SKILL.md"
                                if manifest.is_file():
                                    add_manifest(manifest)
                                elif entry.name.startswith("."):
                                    with os.scandir(entry.path) as hidden:
                                        for child_index, child in enumerate(hidden):
                                            if child_index >= MAX_SCAN_ITEMS or len(files) >= MAX_SCAN_ITEMS:
                                                issues["item_limit"] += 1
                                                break
                                            budget.check()
                                            if child.is_dir(follow_symlinks=False):
                                                nested = Path(child.path) / "SKILL.md"
                                                if nested.is_file():
                                                    add_manifest(nested)
                            elif entry.is_symlink():
                                issues["skill_symlink_not_enumerated"] += 1
                except FileNotFoundError:
                    continue
                except (OSError, ValueError):
                    issues["skill_root_unreadable"] += 1
            if len(files) > MAX_SCAN_ITEMS:
                issues["item_limit"] += len(files) - MAX_SCAN_ITEMS
            for manifest, identifiers in list(files.items())[:MAX_SCAN_ITEMS]:
                try:
                    budget.check()
                except ValueError:
                    issues["check_limit"] += 1
                    break
                unique = set(value for value in identifiers if isinstance(value, str) and value)
                consume(
                    inspect_file(manifest, skill=True, budget=budget),
                    label=manifest.parent.name,
                    inventory_asset_id=next(iter(unique)) if len(unique) == 1 else None,
                )
            result.update(
                state="partial" if issues else "complete",
                checked_items=len(checked), skipped_items=sum(issues.values()),
                findings=list(findings.values()),
                issues=[{"reason": reason, "count": count} for reason, count in sorted(issues.items())],
            )
            self._persist_scan(result)
            return self.status()
        finally:
            self.check_lock.release()
