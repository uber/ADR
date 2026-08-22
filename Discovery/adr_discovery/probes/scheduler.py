"""Agents that run without a person watching.

Scheduled, delegated and background agents are the hardest to see and the least
supervised: a launchd job at 3am, a CI workflow holding repository credentials,
a task dispatched to a vendor's cloud runner. Each is an agent with access, and
none of them shows up in a process table sampled during the working day.
"""

import plistlib
import posixpath
import re
from typing import Any, Dict, List, Optional

from ..base_probe import BaseProbe, Observation
from ..env import DiscoveryEnv
from ..redact import redact_argv

PROJECT_ROOTS = ("~/dev", "~/src", "~/workspace", "~/code")

LAUNCH_AGENT_DIRS = ("~/Library/LaunchAgents", "/Library/LaunchAgents", "/Library/LaunchDaemons")

SYSTEMD_DIRS = ("~/.config/systemd/user", "/etc/systemd/system")

#: Where a host application records work it handed to a cloud runner.
CLOUD_SESSION_FILES = {
    "claude-code": "~/.claude/cloud-sessions.json",
    "codex": "~/.codex/cloud-tasks.json",
}

#: Claude Desktop keeps delegated background runs beside interactive ones.
DISPATCH_ROOTS = {
    "darwin": "~/Library/Application Support/Claude/local-agent-mode-sessions",
    "windows": "%APPDATA%/Claude/local-agent-mode-sessions",
    "linux": "~/.config/claude-desktop/local-agent-mode-sessions",
}

CRON_LINE = re.compile(r"^\s*([\d*/,\-]+(?:\s+[\d*/,\-]+){4})\s+(.*)$")


class SchedulerProbe(BaseProbe):
    name = "scheduler"

    def collect(self, env: DiscoveryEnv) -> List[Observation]:
        out: List[Observation] = []
        out.extend(self._launchd(env))
        out.extend(self._cron(env))
        out.extend(self._systemd(env))
        out.extend(self._windows_tasks(env))
        out.extend(self._ci_workflows(env))
        out.extend(self._dispatch_sessions(env))
        out.extend(self._cloud_sessions(env))
        return out

    # -- local schedulers -------------------------------------------------

    def _launchd(self, env: DiscoveryEnv) -> List[Observation]:
        out: List[Observation] = []
        for directory in LAUNCH_AGENT_DIRS:
            base = env.expand(directory)
            for name in env.listdir(base):
                if not name.endswith(".plist"):
                    continue
                logical = posixpath.join(base, name)
                result = env.read(logical)
                if not result:
                    continue
                try:
                    data = plistlib.loads(result.data)
                except Exception as exc:
                    self.error(env, logical, "malformed plist: %s" % exc)
                    continue
                argv = [str(item) for item in (data.get("ProgramArguments") or [])]
                if not argv and data.get("Program"):
                    argv = [str(data["Program"])]
                entry = self._match(argv)
                if not entry:
                    continue
                schedule = self._launchd_schedule(data)
                flags = ["runs_at_login"] if data.get("RunAtLoad") else []
                out.append(self._scheduled(env, logical, entry, argv, schedule, "launchd", flags))
        return out

    def _launchd_schedule(self, data: Dict[str, Any]) -> str:
        if data.get("StartInterval"):
            return "every %ss" % data["StartInterval"]
        calendar = data.get("StartCalendarInterval")
        if isinstance(calendar, dict):
            return "at %02d:%02d" % (int(calendar.get("Hour", 0)), int(calendar.get("Minute", 0)))
        if data.get("RunAtLoad"):
            return "at login"
        return "unknown"

    def _cron(self, env: DiscoveryEnv) -> List[Observation]:
        text = env.run(["crontab", "-l"], timeout=2.0)
        if not text:
            return []
        out: List[Observation] = []
        for line in text.splitlines():
            if line.strip().startswith("#"):
                continue
            match = CRON_LINE.match(line)
            if not match:
                continue
            argv = match.group(2).split()
            entry = self._match(argv)
            if entry:
                out.append(self._scheduled(env, "crontab", entry, argv, match.group(1), "cron", []))
        return out

    def _systemd(self, env: DiscoveryEnv) -> List[Observation]:
        out: List[Observation] = []
        for directory in SYSTEMD_DIRS:
            base = env.expand(directory)
            units = {name for name in env.listdir(base) if name.endswith(".timer")}
            for timer in sorted(units):
                service = timer[:-6] + ".service"
                result = env.read(posixpath.join(base, service))
                if not result:
                    continue
                argv = []
                schedule = "unknown"
                for line in result.text.splitlines():
                    if line.startswith("ExecStart="):
                        argv = line.split("=", 1)[1].split()
                timer_body = env.read(posixpath.join(base, timer))
                if timer_body:
                    for line in timer_body.text.splitlines():
                        if line.startswith(("OnCalendar=", "OnUnitActiveSec=")):
                            schedule = line.split("=", 1)[1].strip()
                entry = self._match(argv)
                if entry:
                    out.append(self._scheduled(env, posixpath.join(base, service), entry,
                                               argv, schedule, "systemd", []))
        return out

    def _windows_tasks(self, env: DiscoveryEnv) -> List[Observation]:
        out: List[Observation] = []
        for task in env.scheduled_tasks:
            argv = task.get("argv") or str(task.get("action", "")).split()
            entry = self._match(argv)
            if not entry:
                continue
            out.append(self._scheduled(env, "task:%s" % task.get("name", "unnamed"), entry, argv,
                                       str(task.get("schedule", "unknown")), "scheduled_task", []))
        return out

    # -- delegated execution ----------------------------------------------

    def _ci_workflows(self, env: DiscoveryEnv) -> List[Observation]:
        """An agent in CI runs with repository credentials and no human present."""
        out: List[Observation] = []
        for root in PROJECT_ROOTS:
            for logical, _ in env.walk(env.expand(root), max_depth=4):
                if "/.github/workflows/" not in logical or not logical.endswith((".yml", ".yaml")):
                    continue
                result = env.read(logical)
                if not result:
                    continue
                entry = self._match(result.text.split())
                if not entry:
                    continue
                secrets = sorted(set(re.findall(r"secrets\.([A-Z0-9_]+)", result.text)))
                trigger = "schedule" if "schedule:" in result.text else "event"
                repository = logical.split("/.github/")[0]
                out.append(Observation(
                    probe=self.name, channel="config", kind="ci_agent", name=entry["name"],
                    path=logical, matched_on="ci_workflow", catalog_id=entry["id"],
                    vendor=entry.get("vendor"), install_method="ci", owner=env.user,
                    identity_hint="sched:%s:%s" % (entry["id"], logical),
                    extra={"trigger": trigger, "repository": repository,
                           "risk_factors": ["unattended_run"], "secrets": secrets,
                           "scope": "project"},
                    confidence=0.55,
                ))
        return out

    def _dispatch_sessions(self, env: DiscoveryEnv) -> List[Observation]:
        base = env.expand(DISPATCH_ROOTS.get(env.platform, ""))
        if not base or not env.is_dir(base):
            return []
        out: List[Observation] = []
        seen = set()
        for logical, _ in env.walk(base, max_depth=6):
            if not logical.endswith("audit.jsonl"):
                continue
            session = posixpath.basename(posixpath.dirname(logical))
            dispatch = "/agent/" in logical or session.startswith("local_ditto_")
            key = (dispatch, session)
            if key in seen:
                continue
            seen.add(key)
            out.append(Observation(
                probe=self.name, channel="filesystem", kind="agent",
                name="Claude Desktop agent session", path=logical,
                matched_on="dispatch" if dispatch else "interactive",
                catalog_id="claude-desktop", install_method="agent_session", owner=env.user,
                identity_hint="sched:session:%s" % session,
                extra={"flags": ["dispatch"] if dispatch else [], "session": session,
                       "risk_factors": ["unattended_run"] if dispatch else []},
                confidence=0.6,
            ))
        return out

    def _cloud_sessions(self, env: DiscoveryEnv) -> List[Observation]:
        """Work dispatched to a vendor runner. The delegation is what we know."""
        out: List[Observation] = []
        for catalog_id, template in CLOUD_SESSION_FILES.items():
            logical = env.expand(template)
            if not env.exists(logical):
                continue
            data = self.read_json(env, logical)
            if not isinstance(data, (list, dict)):
                continue
            records = data if isinstance(data, list) else data.get("sessions", [])
            entry = self.catalog.get(catalog_id) or {"name": catalog_id}
            out.append(Observation(
                probe=self.name, channel="config", kind="cloud_agent",
                name=entry.get("name", catalog_id), path=logical, matched_on="cloud_sessions",
                catalog_id=catalog_id, vendor=entry.get("vendor"), install_method="cloud",
                owner=env.user, identity_hint="sched:cloud:%s" % catalog_id,
                extra={"session_count": len(records), "location": "remote",
                       "risk_factors": ["unattended_run"], "scope": "cloud"},
                confidence=0.6,
            ))
        return out

    # -- helpers ----------------------------------------------------------

    def _match(self, argv: List[str]) -> Optional[Dict[str, Any]]:
        for token in argv:
            name = posixpath.basename(str(token).replace("\\", "/"))
            if name.lower().endswith(".exe"):
                name = name[:-4]
            entry = self.catalog.match("binaries", name)
            if entry:
                return entry
            entry = self.catalog.match("npm_packages", str(token))
            if entry:
                return entry
        return None

    def _scheduled(self, env, path, entry, argv, schedule, mechanism, flags) -> Observation:
        return Observation(
            probe=self.name, channel="config", kind="scheduled_agent", name=entry["name"],
            path=path, matched_on=mechanism, catalog_id=entry["id"], vendor=entry.get("vendor"),
            install_method=mechanism, owner=env.user,
            identity_hint="sched:%s:%s" % (entry["id"], path),
            extra={"schedule": schedule, "argv": redact_argv(argv), "flags": flags,
                   "risk_factors": ["unattended_run"], "host_app": entry["id"]},
            confidence=0.6,
        )
