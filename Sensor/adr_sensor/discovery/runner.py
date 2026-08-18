"""Stage orchestration: enumerate, fingerprint, infer, resolve, rank, report."""

import os
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
    for duplicate in catalog.duplicates:
        env.errors.append({"probe": "catalog", "path": "catalog.json",
                           "message": "ambiguous fingerprint %s=%s claimed by %s"
                                      % (duplicate["field"], duplicate["value"],
                                         duplicate["entries"])})
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

    observations.extend(correlate_declared_servers(env, observations, catalog))
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
               "error_count": len(env.errors), "coverage": dict(env.coverage)},
    )
    return scrub(snapshot)


def live_env(**overrides) -> DiscoveryEnv:
    """A :class:`DiscoveryEnv` bound to the real machine.

    Deliberately the only place in the package that touches the live host, so
    everything downstream of it stays testable.
    """
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
        "sockets": _live_sockets(),
    }
    defaults.update(overrides)
    return DiscoveryEnv(**defaults)


#: Ceiling on what one child process may hand back. A timeout bounds how long a
#: command runs; without this a command that returns promptly and prints forever
#: is still unbounded.
MAX_SUBPROCESS_BYTES = 1_000_000


def _subprocess_runner(argv, timeout):
    """Run a command under a hard timeout and a hard output ceiling.

    The kill matters twice over: a binary that never returns from ``--version``
    would otherwise leak a process for every scan, and one that floods stdout
    would otherwise be read into memory in full.
    """
    import subprocess
    import threading

    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               stdin=subprocess.DEVNULL)
    collected = bytearray()
    truncated = [False]

    def drain():
        while True:
            block = process.stdout.read(65536)
            if not block:
                return
            if len(collected) < MAX_SUBPROCESS_BYTES:
                collected.extend(block[:MAX_SUBPROCESS_BYTES - len(collected)])
            else:
                truncated[0] = True
                process.kill()
                return

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    reader.join(timeout)
    if reader.is_alive():
        process.kill()
        reader.join(1.0)
        raise TimeoutError("timed out after %ss" % timeout)
    process.wait(timeout=1.0)
    text = bytes(collected).decode("utf-8", "replace")
    if truncated[0]:
        text += "\n[output truncated at %d bytes]" % MAX_SUBPROCESS_BYTES
    return process.returncode, text


def _localhost_probe(port, path):
    """GET a loopback endpoint with a short timeout. Loopback only, by design."""
    import json as json_mod
    import socket as socket_lib
    import urllib.request

    # A port that is listening but not speaking HTTP must cost a fraction of a
    # second, not a full timeout: most listeners on a developer machine are not
    # inference servers.
    with socket_lib.create_connection(("127.0.0.1", port), timeout=0.3):
        pass
    request = urllib.request.Request("http://127.0.0.1:%d%s" % (port, path))
    with urllib.request.urlopen(request, timeout=0.5) as response:
        return json_mod.loads(response.read(2_000_000).decode("utf-8", "replace"))


def _live_processes():
    """Own-UID process table via ``ps``.

    Own-UID is sufficient for endpoint discovery - the agents run as the user -
    and it keeps the collector unprivileged. The filter is applied twice: ``ps``
    is asked for one user, and rows are checked again after parsing, because
    collecting another person's command lines is both a privacy problem and an
    attribution error.
    """
    import getpass
    import subprocess

    from .env import ProcessInfo

    try:
        user = getpass.getuser()
    except Exception:
        user = os.environ.get("USER") or os.environ.get("USERNAME") or ""
    fields = "pid=,ppid=,user=,comm=,args="
    for argv in (["ps", "-u", user, "-o", fields], ["ps", "-xo", fields]):
        try:
            raw = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 timeout=5).stdout.decode("utf-8", "replace")
        except Exception:
            continue
        processes = []
        for line in raw.splitlines():
            parts = line.split(None, 4)
            if len(parts) < 5 or not parts[0].isdigit():
                continue
            pid, ppid, owner, comm, args = parts
            if user and owner != user:
                continue
            processes.append(ProcessInfo(int(pid), int(ppid), comm, args.split(), user=owner))
        if processes:
            return tuple(processes)
    return ()


def _live_sockets():
    """Listening TCP sockets owned by this user.

    Without this the runtime probe is fully tested and entirely inert in
    production: every port-based detection passes on fixtures and finds nothing
    on a real endpoint.
    """
    import getpass
    import re as re_mod
    import subprocess

    from .env import SocketInfo

    if platform_mod.system() == "Windows":
        argv = ["netstat", "-ano", "-p", "TCP"]
    else:
        try:
            user = getpass.getuser()
        except Exception:
            user = ""
        argv = ["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"] + (["-u", user] if user else [])
    try:
        raw = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             timeout=5).stdout.decode("utf-8", "replace")
    except Exception:
        return ()
    sockets = {}
    for line in raw.splitlines():
        if platform_mod.system() == "Windows":
            match = re_mod.match(r"\s*TCP\s+\S+:(\d+)\s+\S+\s+LISTENING\s+(\d+)", line)
            if match:
                sockets[int(match.group(1))] = SocketInfo(int(match.group(2)),
                                                          int(match.group(1)))
            continue
        parts = line.split()
        if len(parts) < 9 or not parts[1].isdigit():
            continue
        match = re_mod.search(r":(\d+)$", parts[8])
        if match:
            sockets[int(match.group(1))] = SocketInfo(int(parts[1]), int(match.group(1)))
    return tuple(sockets.values())


def correlate_declared_servers(env, observations, catalog):
    """Match running child processes against servers a config already declares.

    Runtime identification alone has to be strict, or ordinary development
    becomes a stream of findings. Correlation is where the strictness is paid
    back: a server that names itself nothing recognizable is still recognized
    the moment a config on this host declares the very command that is running.
    """
    import posixpath

    from .base_probe import Observation
    from .probes.mcp import server_identity
    from .redact import redact_argv

    declared = {}
    for observation in observations:
        if observation.kind == "mcp_server" and observation.channel == "config":
            declared[observation.identity_hint] = observation
    seen_runtime = {o.identity_hint for o in observations
                    if o.kind == "mcp_server" and o.channel == "runtime"}
    if not declared:
        return []

    by_pid = {process.pid: process for process in env.processes}
    recovered = []
    for process in env.processes:
        parent = by_pid.get(process.ppid)
        if parent is None:
            continue
        parent_entry = catalog.match("binaries", posixpath.basename(parent.exe))
        if not parent_entry:
            continue
        argv = redact_argv(process.argv)
        identity = server_identity("stdio", posixpath.basename(process.exe), argv[1:], "")
        if identity not in declared or identity in seen_runtime:
            continue
        seen_runtime.add(identity)
        source = declared[identity]
        recovered.append(Observation(
            probe="correlation", channel="runtime", kind="mcp_server", name=source.name,
            path=process.exe, matched_on="declared_and_running",
            install_method=source.install_method, identity_hint=identity,
            owner=process.user or env.user,
            extra={"pid": process.pid, "ppid": parent.pid, "argv": argv,
                   "parent_agent": parent_entry["id"], "transport": "stdio", "running": True},
            confidence=0.6,
        ))
    return recovered


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
