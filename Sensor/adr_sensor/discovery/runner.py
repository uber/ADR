"""Stage orchestration: enumerate, fingerprint, infer, resolve, rank, report."""

import platform as platform_mod
import socket as socket_mod
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from .catalog import Catalog
from .env import DiscoveryEnv
from .probes import ALL_PROBES
from .probes.openworld import OpenWorldProbe
from .redact import redact_secretish, sanitize
from .resolver import resolve
from .schema import DiscoveredAsset, DiscoverySnapshot


def discover(env: DiscoveryEnv, catalog: Optional[Catalog] = None,
             hostname: Optional[str] = None, timestamp: Optional[str] = None) -> DiscoverySnapshot:
    """Run every supported probe against ``env`` and resolve one snapshot.

    A snapshot is emitted even when nothing is found: to fleet coverage, a host
    that reported an empty inventory and a host that never reported are very
    different facts.
    """
    catalog = catalog or Catalog.load()
    started = time.time()
    observations = []
    per_probe: Dict[str, Any] = {}

    for probe_class in ALL_PROBES:
        probe = probe_class(catalog)
        if not probe.supports(env):
            continue
        probe_started = time.time()
        found = probe.run(env)
        per_probe[probe.name] = {"count": len(found),
                                 "ms": round((time.time() - probe_started) * 1000, 1)}
        observations.extend(found)

    review_queue = OpenWorldProbe(catalog).score_candidates(env, observations)
    assets = resolve(observations, telemetry=env.telemetry)
    mark_effective_scope(assets)
    findings = derive_findings(assets)

    snapshot = DiscoverySnapshot(
        hostname=hostname or socket_mod.gethostname(),
        username=env.user,
        platform=env.platform,
        timestamp=timestamp or datetime.utcnow().isoformat(timespec="seconds") + "Z",
        assets=assets,
        review_queue=review_queue,
        findings=findings,
        errors=list(env.errors),
        stats={"probes": per_probe, "catalog_version": catalog.version,
               "wall_ms": round((time.time() - started) * 1000, 1),
               "asset_count": len(assets), "review_queue_count": len(review_queue),
               "error_count": len(env.errors)},
    )
    return scrub(snapshot)


def live_env(**overrides) -> DiscoveryEnv:
    """A :class:`DiscoveryEnv` bound to the real machine.

    Deliberately the only place in the package that touches the live host, so
    everything downstream of it stays testable.
    """
    import os
    from pathlib import Path

    system = platform_mod.system()
    kind = {"Darwin": "darwin", "Windows": "windows"}.get(system, "linux")
    defaults = {
        "root": Path("/"),
        "platform": kind,
        "home": str(Path.home()),
        "user": os.environ.get("USER") or os.environ.get("USERNAME") or "unknown",
        "env_vars": dict(os.environ),
        "case_insensitive": kind == "darwin",
        "runner": _subprocess_runner,
        "http": _localhost_probe,
        "processes": _live_processes(),
        "sockets": (),
    }
    defaults.update(overrides)
    return DiscoveryEnv(**defaults)


def _subprocess_runner(argv, timeout):
    """Run a command under a hard timeout, killing the child if it overruns.

    The kill matters: a binary that never returns from ``--version`` would
    otherwise leak a process for every scan.
    """
    import subprocess

    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               stdin=subprocess.DEVNULL)
    try:
        out, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        raise TimeoutError("timed out after %ss" % timeout)
    return process.returncode, (out or b"").decode("utf-8", "replace")


def _localhost_probe(port, path):
    """GET a loopback endpoint with a short timeout. Loopback only, by design."""
    import json as json_mod
    import urllib.request

    request = urllib.request.Request("http://127.0.0.1:%d%s" % (port, path))
    with urllib.request.urlopen(request, timeout=1.0) as response:
        return json_mod.loads(response.read(2_000_000).decode("utf-8", "replace"))


def _live_processes():
    """Own-UID process table via ``ps``.

    Own-UID is sufficient for endpoint discovery - the agents run as the user -
    and it keeps the collector unprivileged.
    """
    import subprocess

    from .env import ProcessInfo

    try:
        raw = subprocess.run(["ps", "-axo", "pid=,ppid=,user=,comm=,args="],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             timeout=5).stdout.decode("utf-8", "replace")
    except Exception:
        return ()
    processes = []
    for line in raw.splitlines():
        fields = line.split(None, 4)
        if len(fields) < 5 or not fields[0].isdigit():
            continue
        pid, ppid, user, comm, args = fields
        processes.append(ProcessInfo(int(pid), int(ppid), comm, args.split(), user=user))
    return tuple(processes)


#: Which declaration wins when one name exists at several scopes. Enterprise
#: policy cannot be overridden by a user; a project skill overrides a personal
#: one, because it travels with the repository the agent is working in.
SCOPE_PRECEDENCE = {
    "mcp_server": ("enterprise_managed", "project", "user", "plugin"),
    "skill": ("project", "personal", "plugin"),
    "command": ("project", "personal", "plugin"),
    "agent_definition": ("project", "personal", "plugin"),
}


def mark_effective_scope(assets: List[DiscoveredAsset]) -> None:
    """Say which of several same-named declarations is the one that runs."""
    groups: Dict[tuple, List[DiscoveredAsset]] = {}
    for asset in assets:
        if asset.kind in SCOPE_PRECEDENCE:
            groups.setdefault((asset.kind, asset.name, asset.owner), []).append(asset)
    for (kind, _, _), members in groups.items():
        order = SCOPE_PRECEDENCE[kind]
        winner = min(members, key=lambda a: order.index(a.config_scope)
                     if a.config_scope in order else 99)
        for asset in members:
            asset.risk["effective"] = asset is winner


def derive_findings(assets: List[DiscoveredAsset]) -> List[Dict[str, Any]]:
    """Conclusions no single probe can reach, because they compare channels."""
    findings: List[Dict[str, Any]] = []
    for asset in assets:
        if asset.kind != "mcp_server":
            continue
        channels = asset.channels
        if "runtime" in channels and "config" not in channels:
            findings.append({
                "finding": "undeclared_mcp_server", "asset_id": asset.asset_id,
                "name": asset.name, "severity": "high", "install_path": asset.install_path,
                "detail": "server process observed with no declaring config on this host",
            })
        if not asset.risk.get("pinned", True):
            findings.append({
                "finding": "unpinned_mcp_server", "asset_id": asset.asset_id,
                "name": asset.name, "severity": "medium",
                "detail": "launch resolves a package version at run time",
            })
    return findings


def scrub(snapshot: DiscoverySnapshot) -> DiscoverySnapshot:
    """Last-line defense: sanitize and mask anything key-shaped in the output.

    Probes already redact at the point of collection. This pass exists because
    one probe forgetting to is a data-leak incident, not a bug report.
    """

    def walk(value):
        if isinstance(value, str):
            return redact_secretish(value)
        if isinstance(value, list):
            return [walk(item) for item in value]
        if isinstance(value, dict):
            return {sanitize(str(key)): walk(item) for key, item in value.items()}
        return value

    for asset in snapshot.assets:
        asset.name = walk(asset.name)
        asset.risk = walk(asset.risk)
        asset.network = walk(asset.network)
        asset.install_path = walk(asset.install_path)
        for item in asset.evidence:
            item.path = walk(item.path)
            item.matched_on = walk(item.matched_on)
    snapshot.review_queue = walk(snapshot.review_queue)
    snapshot.findings = walk(snapshot.findings)
    snapshot.errors = walk(snapshot.errors)
    return snapshot
