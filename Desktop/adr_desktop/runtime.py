"""Local app composition: collection, policy cache, owner sessions, and scoped agents."""

import json
import secrets
import sys
import threading
import time
from pathlib import Path

from . import __version__
from .approval_queue import ApprovalQueue
from .broker import Broker
from .collector import SOURCE_LABELS, Collector
from .config import (
    CAPTURE_INTERVAL_SECONDS,
    atomic_json,
    canonical,
    command_prefix,
    read_private_json,
    token,
    token_hash,
    utcnow,
)
from .environment_vault import EnvironmentVault
from .guard import GUARD_VERSION, publish_target, upgrade_guard
from .hooks import HARNESS_LABELS, configuration_path, installed
from .native import NativeBridge
from .policy import project_path, validate_rule
from .presets import STARTER_ID, starter_preview
from .security_reviews import SecurityReviews
from .store import Store, new_id
from .threat_feed import compile_generation
from .threat_protection import MAX_POLICY_BYTES, ThreatProtection, initialize_threats


class Runtime:
    def __init__(self, state_dir: Path, native=None, *, start_collectors=True):
        self.state_dir = state_dir
        self.store = Store(state_dir)
        self.native = native or NativeBridge()
        self.owner_token = token()
        self.hook_token = token()
        self.port = 0
        self.instance = new_id()
        self.policy_lock = threading.RLock()
        self.auth_lock = threading.Lock()
        self.hook_approvals = ApprovalQueue()
        self.integration_lock = threading.RLock()
        self.enrollment_lock = threading.Lock()
        self.vault_migration_lock = threading.Lock()
        self.last_enrollment = 0.0
        self.tickets: dict[str, float] = {}
        self.sessions: dict[str, tuple[str, float]] = {}
        self.policy_error = None
        self.policy = self._load_policy()
        self.threats = ThreatProtection(self)
        if __import__("os").name != "nt":
            publish_target(state_dir)
            upgrade_guard(state_dir)
        self.broker = Broker(self.store, self.native)
        self.environment_vault = EnvironmentVault(self)
        self.collector = Collector(self.store, state_dir)
        atomic_json(state_dir / "hook-access.json", {"token": self.hook_token})
        if start_collectors:
            self.collector.start()
        self.reviews = SecurityReviews(self, start_worker=start_collectors)

    def _load_policy(self):
        path = self.state_dir / "policy.json"
        if path.exists():
            snapshot = read_private_json(path, maximum=1024 * 1024)
            if snapshot.get("version") != 1 or not isinstance(snapshot.get("rules"), list):
                raise ValueError("The saved policy is invalid; it was not replaced")
        else:
            snapshot = {
                "version": 1,
                "revision": new_id(),
                "enabled": True,
                "opaque_tools": "ask",
                "strict_execution": False,
                "rules": [],
            }
        if "strict_execution" not in snapshot:
            # Older previews asked for every unknown tool implicitly. Make that
            # behavior opt-in, while preserving an explicitly configured Block.
            snapshot["strict_execution"] = snapshot.get("opaque_tools") == "block"
            snapshot["revision"] = new_id()
        if not isinstance(snapshot["strict_execution"], bool):
            raise ValueError("The saved strict execution setting is invalid")
        previous_threats = snapshot.get("threats")
        snapshot["threats"], self.threat_feed_warning = initialize_threats(previous_threats)
        if snapshot["threats"] != previous_threats:
            snapshot["revision"] = new_id()
        snapshot["control_paths"] = [
            [str(self.state_dir), "directory"],
            [str(configuration_path("claude")), "file"],
            [str(Path.home() / ".claude.json"), "file"],
            [str(Path.home() / ".copilot" / "hooks"), "directory"],
            [str(Path.home() / ".copilot" / "config.json"), "file"],
            [str(Path.home() / ".copilot" / "mcp-config.json"), "file"],
            [str(configuration_path("codex")), "file"],
            [str(configuration_path("codex").parent / "config.toml"), "file"],
            [str(configuration_path("opencode")), "file"],
            [str(configuration_path("opencode").parent.parent / "opencode.json"), "file"],
            [str(configuration_path("opencode").parent.parent / "opencode.jsonc"), "file"],
        ]
        if getattr(sys, "frozen", False):
            bundle = next(
                (parent for parent in Path(sys.executable).parents if parent.suffix == ".app"), None
            )
            if bundle is not None:
                snapshot["control_paths"].append([str(bundle), "directory"])
        if len(canonical(snapshot).encode()) > MAX_POLICY_BYTES - 128:
            if previous_threats is not None:
                # A larger valid baseline can fit the feed cap yet exceed the
                # whole policy cap beside existing long file rules.
                snapshot["threats"] = previous_threats
                self.threat_feed_warning = (
                    "The updated list exceeds this profile's policy limit. "
                    "The last accepted list is still in use."
                )
            if len(canonical(snapshot).encode()) > MAX_POLICY_BYTES - 128:
                raise ValueError("The combined protection policy is too large; no policy was replaced")
        atomic_json(path, snapshot)
        return snapshot

    def change_policy(self, *, add=None, delete=None, enabled=None, opaque_tools=None, strict_execution=None):
        with self.policy_lock:
            updated = json.loads(json.dumps(self.policy))
            if add:
                rule = validate_rule(add["path"], add["action"], add["kind"], add.get("label", ""))
                if len(updated["rules"]) >= 100:
                    raise ValueError("This preview supports at most 100 file rules")
                updated["rules"].append({"id": new_id(), "created_at": utcnow(), **rule})
            if delete:
                if not any(rule["id"] == delete for rule in updated["rules"]):
                    raise ValueError("Rule not found")
                updated["rules"] = [rule for rule in updated["rules"] if rule["id"] != delete]
            if enabled is not None:
                updated["enabled"] = bool(enabled)
            if opaque_tools is not None:
                if opaque_tools not in ("ask", "block"):
                    raise ValueError("Unclassified execution tools must ask or block")
                updated["opaque_tools"] = opaque_tools
                # An explicit API choice of Ask/Block opts into execution review.
                updated["strict_execution"] = True
            if strict_execution is not None:
                if not isinstance(strict_execution, bool):
                    raise ValueError("Strict execution review must be enabled or disabled")
                updated["strict_execution"] = strict_execution
            self._publish_policy(updated)
        self.store.audit("file_policy_changed", "File protection rules updated")
        return updated

    def _publish_policy(self, updated):
        # Caller holds policy_lock. Publish the offline authority before acknowledging.
        compiled = compile_generation(updated["threats"]["generation"])
        updated["revision"] = new_id()
        if len(canonical(updated).encode()) > MAX_POLICY_BYTES:
            raise ValueError("The combined protection policy is too large; no policy was replaced")
        atomic_json(self.state_dir / "policy.json", updated)
        self.policy = updated
        self.threats.remember_generation(updated["threats"]["generation"], compiled=compiled)

    def starter_protection(self):
        with self.policy_lock:
            return {
                **starter_preview(self.policy),
                "connected": any(installed(harness, state_dir=self.state_dir) for harness in HARNESS_LABELS),
                "applied": self.policy.get("starter_applied", False)
                or any(rule.get("preset") == STARTER_ID for rule in self.policy["rules"]),
            }

    def add_starter_protection(self):
        with self.policy_lock:
            if not any(installed(harness, state_dir=self.state_dir) for harness in HARNESS_LABELS):
                raise ValueError("Connect an agent's protection hook before adding starter protections")
            preview = self.starter_protection()
            if not preview["supported"]:
                raise ValueError("Starter paths are available for macOS and Linux in this preview")
            if preview["review_required"]:
                raise ValueError("An existing rule has an unreadable path; review it before adding defaults")
            additions = [item for item in preview["items"] if item["state"] == "available"]
            if len(self.policy["rules"]) + len(additions) > 100:
                raise ValueError(
                    "Adding this starter set would exceed the 100-rule limit; no rules were added"
                )
            if not additions and preview["applied"]:
                return {"added": 0, **preview}
            updated = json.loads(json.dumps(self.policy))
            updated["starter_applied"] = True
            for item in additions:
                updated["rules"].append(
                    {
                        "id": new_id(),
                        "created_at": utcnow(),
                        "preset": STARTER_ID,
                        "preset_key": item["key"],
                        **{key: item[key] for key in ("path", "kind", "action", "label")},
                    }
                )
            self._publish_policy(updated)
            result = {"added": len(additions), **self.starter_protection()}
        self.store.audit(
            "file_policy_changed",
            f"Added {len(additions)} starter file protections",
            {"preset": STARTER_ID, "added": len(additions)},
        )
        return result

    def new_ticket(self) -> str:
        now = time.monotonic()
        with self.auth_lock:
            self.tickets = {key: expiry for key, expiry in self.tickets.items() if expiry > now}
            value = token()
            self.tickets[token_hash(value)] = now + 60
            return value

    def consume_ticket(self, value: str, current_session: str | None = None):
        now = time.monotonic()
        with self.auth_lock:
            expiry = self.tickets.pop(token_hash(value), 0)
            if expiry <= now:
                raise PermissionError("Open ADR from its menu-bar icon to reconnect")
            self.sessions = {key: entry for key, entry in self.sessions.items() if entry[1] > now}
            existing = self.sessions.get(token_hash(current_session)) if current_session else None
            if existing:
                # Cookies are shared across tabs. Replacing a valid session here
                # would strand older tabs with the previous session's CSRF token.
                session, csrf = current_session, existing[0]
            else:
                session, csrf = token(), token()
            self.sessions[token_hash(session)] = (csrf, now + 8 * 60 * 60)
        return session, csrf

    def session(self, value: str | None):
        if not value:
            return None
        with self.auth_lock:
            result = self.sessions.get(token_hash(value))
        if result and result[1] > time.monotonic():
            return result[0]
        return None

    def is_owner(self, value: str) -> bool:
        return bool(value) and secrets.compare_digest(value, self.owner_token)

    def is_hook(self, value: str) -> bool:
        return bool(value) and secrets.compare_digest(value, self.hook_token)

    def grant(self, value: str):
        if not value:
            return None
        return self.store.one("SELECT * FROM grants WHERE token_hash=? AND revoked=0", (token_hash(value),))

    def create_grant(
        self,
        name: str,
        project: str = "",
        credentials: list[str] | None = None,
        *,
        kind="legacy",
        approval_mode="ask",
        confirm_device_history=False,
        confirm_automatic=False,
        confirm_execution=False,
        confirm_all_environment=False,
        confirm_agent=False,
    ):
        credentials = list(dict.fromkeys(credentials or []))
        if (
            kind not in ("legacy", "history", "context", "vault", "execution", "agent")
            or approval_mode not in ("ask", "automatic")
        ):
            raise ValueError("Choose history search or credential access")
        if kind == "agent":
            if not confirm_agent or project or credentials:
                raise ValueError("Confirm the ADR integration before enabling automatic credential use")
            credentials, history_scope, approval_mode = ["*"], "device", "automatic"
        elif kind in ("history", "context"):
            if not confirm_device_history or project or credentials or approval_mode != "ask":
                raise ValueError(
                    "Confirm read-only access to all captured history; no credentials are included"
                )
            history_scope = "device"
        elif kind == "execution":
            if not project or not credentials or not confirm_execution:
                raise ValueError("Choose a project and credentials, and confirm command-execution access")
            if approval_mode == "automatic" and not confirm_automatic:
                raise ValueError("Confirm automatic execution with the selected environment credentials")
            if credentials == ["*"] and not confirm_all_environment:
                raise ValueError("Confirm access to all current and future environment credentials")
            project = project_path(project)
            if not Path(project).is_dir():
                raise ValueError("Choose an existing project folder")
            history_scope = "none"
        elif kind == "vault":
            if project or not credentials:
                raise ValueError("Choose at least one credential; vault access does not include history")
            if approval_mode == "automatic" and not confirm_automatic:
                raise ValueError("Confirm automatic use within the selected credentials' allowed GET paths")
            history_scope = "none"
        else:
            if not project or approval_mode != "ask":
                raise ValueError("Existing-style connections require a project and per-request approval")
            project = project_path(project)
            history_scope = "project"
        available = (
            self.environment_vault.entries() if kind in ("execution", "agent") else self.broker.credentials()
        )
        active = {item["id"] for item in available if item["state"] == "active"}
        if not (kind in ("execution", "agent") and credentials == ["*"]) and not set(credentials) <= active:
            raise ValueError("One of the selected credentials is unavailable")
        identifier, capability = new_id(), token()
        self.store.execute(
            """INSERT INTO grants(
               id,name,token_hash,project,credentials,created_at,revoked,kind,history_scope,approval_mode
               ) VALUES (?,?,?,?,?,?,0,?,?,?)""",
            (
                identifier,
                name,
                token_hash(capability),
                project,
                json.dumps(credentials),
                utcnow(),
                kind,
                history_scope,
                approval_mode,
            ),
        )
        access_file = self.state_dir / "agents" / f"{identifier}.json"
        try:
            atomic_json(
                access_file,
                {"id": identifier, "token": capability, "state_dir": str(self.state_dir), "kind": kind},
            )
        except Exception:
            self.store.execute("DELETE FROM grants WHERE id=?", (identifier,))
            raise
        self.store.audit(
            "agent_connected",
            f"Created {kind} access: {name}",
            {"project": project, "history_scope": history_scope, "approval_mode": approval_mode},
        )
        return {
            "id": identifier,
            "name": name,
            "project": project,
            "kind": kind,
            "history_scope": history_scope,
            "approval_mode": approval_mode,
            "configuration": self.grant_configuration(identifier),
        }

    def grant_configuration(self, identifier: str):
        grant = self.store.one("SELECT * FROM grants WHERE id=? AND revoked=0", (identifier,))
        if not grant:
            raise ValueError("This connection is no longer available")
        access_file = self.state_dir / "agents" / f"{identifier}.json"
        if not access_file.is_file():
            raise ValueError("The connection's access file is missing; create a new connection")
        prefix = command_prefix()
        name = {"history": "adr_history", "context": "adr_context", "vault": "adr_vault",
                "execution": "adr_vault_env", "agent": "adr"}.get(
            grant["kind"], "adr"
        )
        return {
            "mcpServers": {
                name: {
                    "command": prefix[0],
                    "args": [*prefix[1:], "mcp", "--access-file", str(access_file)],
                }
            }
        }

    def revoke_grant(self, identifier: str):
        self.store.execute("UPDATE grants SET revoked=1 WHERE id=?", (identifier,))
        self.store.execute(
            "UPDATE broker_requests SET state='revoked',result=NULL WHERE grant_id=?", (identifier,)
        )
        self.store.audit("agent_revoked", "Agent access revoked", {"id": identifier})

    def status(self):
        from .agent_plugins import NativePluginDriver, configured, read_receipt

        self.broker.expire()
        settings = self.store.settings()
        settings.pop("inventory_snapshot", None)
        try:
            bridge_ready = (
                read_private_json(self.state_dir / "guard-version.json").get("version") == GUARD_VERSION
            )
        except (OSError, ValueError):
            bridge_ready = False
        context_connected = {}
        vault_connected = {}
        agent_available = {}
        driver = getattr(self, "integration_driver", None) or NativePluginDriver()
        for harness in HARNESS_LABELS:
            try:
                driver.executable(harness)
                agent_available[harness] = True
            except (OSError, ValueError):
                agent_available[harness] = False
            try:
                receipt = read_receipt(self.state_dir, harness)
                principal = self.store.one(
                    "SELECT kind FROM grants WHERE id=? AND revoked=0",
                    (receipt["grant_id"],),
                ) if receipt else None
                context_connected[harness] = bool(
                    receipt
                    and configured(self.state_dir, harness)
                    and principal
                )
                vault_connected[harness] = bool(context_connected[harness] and principal["kind"] == "agent")
            except (OSError, ValueError, KeyError):
                context_connected[harness] = False
                vault_connected[harness] = False
        return {
            "version": __version__,
            "running": True,
            "state_dir": str(self.state_dir),
            "collector": self.collector.status(),
            "settings": {
                **settings,
                "protection_enabled": self.policy["enabled"],
                "opaque_tools": self.policy["opaque_tools"],
                "strict_execution": self.policy["strict_execution"],
            },
            "protection": {
                "enabled": self.policy["enabled"],
                "rules": len(self.policy["rules"]),
                "latest_intervention_id": (
                    self.store.one(
                        """SELECT id FROM hook_events WHERE decision IN ('deny','ask')
                           OR approval_requested=1 ORDER BY id DESC LIMIT 1"""
                    ) or {"id": 0}
                )["id"],
            },
            "threats": self.threats.summary(),
            "reviews": self.reviews.summary(),
            "hooks": [
                {
                    "harness": harness,
                    "name": name,
                    "available": agent_available[harness],
                    "installed": installed(harness, state_dir=self.state_dir),
                    "output_check": installed(harness, phase="post", state_dir=self.state_dir),
                    "prompt_check": installed(harness, phase="prompt", state_dir=self.state_dir),
                    "context_connected": context_connected[harness],
                    "vault_connected": vault_connected[harness],
                    "needs_update": not vault_connected[harness]
                    or not bridge_ready
                    or (harness in ("claude", "codex")
                        and not installed(harness, phase="prompt", state_dir=self.state_dir))
                    or (
                        harness != "copilot"
                        and not installed(harness, phase="post", state_dir=self.state_dir)
                    ),
                    "last_event": self.store.one(
                        "SELECT timestamp,decision FROM hook_events WHERE harness=? ORDER BY id DESC LIMIT 1",
                        (harness,),
                    ),
                }
                for harness, name in HARNESS_LABELS.items()
            ],
            "vault_available": self.native.connected,
            "prompt_blocks": self.store.one("SELECT count(*) AS n FROM prompt_blocks")["n"],
            "pending": self.store.one("SELECT count(*) AS n FROM broker_requests WHERE state='pending'")["n"],
            "storage_bytes": self.store.bytes_used(),
            "sources": SOURCE_LABELS,
            "capture_intervals_seconds": CAPTURE_INTERVAL_SECONDS,
        }

    def close(self):
        self.hook_approvals.close()
        self.reviews.close()
        self.collector.close()
        self.store.close()
