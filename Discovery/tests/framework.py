"""Fixture-world builder and case runner for the discovery fidelity suite.

A case declares a world and a list of expectations. The runner builds the world
on disk, runs one scan, and reports per-expectation agreement, so the output is
a scorecard rather than a pass count.
"""

import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from adr_discovery import DiscoveryEnv, ProcessInfo, SocketInfo, discover


class World:
    """Builds one fixture endpoint: files, links, processes, sockets, services."""

    def __init__(self, platform: str = "darwin", home: Optional[str] = None,
                 user: str = "alice", case_insensitive: bool = False, **extra):
        self.root = Path(tempfile.mkdtemp(prefix="adr-fidelity-")).resolve()
        self.platform = platform
        self.user = user
        default_home = {"windows": "/Users/%s" % user, "linux": "/home/%s" % user}.get(
            platform, "/Users/%s" % user)
        self.home = home or default_home
        self.case_insensitive = case_insensitive
        self.env_vars: Dict[str, str] = {"PATH": ""}
        if platform == "windows":
            self.env_vars["APPDATA"] = self.home + "/AppData/Roaming"
            self.env_vars["LOCALAPPDATA"] = self.home + "/AppData/Local"
        self.processes: List[ProcessInfo] = []
        self.sockets: List[SocketInfo] = []
        self.registry: List[Dict[str, str]] = []
        self.telemetry: Dict[str, str] = {}
        self.extra_users: List[str] = []
        self._http: Dict[tuple, Any] = {}
        self._runs: List[tuple] = []
        self.extra = extra

    # -- filesystem -------------------------------------------------------

    def _real(self, logical: str) -> Path:
        text = logical
        if text.startswith("~"):
            text = self.home + text[1:]
        for name, value in self.env_vars.items():
            text = text.replace("%%%s%%" % name, value)
        return self.root / text.lstrip("/").replace("\\", "/")

    def dir(self, logical: str) -> "World":
        self._real(logical).mkdir(parents=True, exist_ok=True)
        return self

    def file(self, logical: str, content: str = "x") -> "World":
        target = self._real(logical)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        return self

    def bytes(self, logical: str, payload: bytes) -> "World":
        target = self._real(logical)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
        return self

    def json(self, logical: str, obj: Any) -> "World":
        return self.file(logical, json.dumps(obj, indent=2))

    def plist(self, logical: str, obj: Dict[str, Any], binary: bool = True) -> "World":
        import plistlib

        target = self._real(logical)
        target.parent.mkdir(parents=True, exist_ok=True)
        fmt = plistlib.FMT_BINARY if binary else plistlib.FMT_XML
        with open(target, "wb") as handle:
            plistlib.dump(obj, handle, fmt=fmt)
        return self

    def link(self, logical: str, target_logical: str) -> "World":
        source = self._real(logical)
        source.parent.mkdir(parents=True, exist_ok=True)
        if source.exists() or source.is_symlink():
            source.unlink()
        os.symlink(str(self._real(target_logical)), str(source))
        return self

    def raw_link(self, logical: str, raw_target: str) -> "World":
        """A symlink to a literal target, used for dangling and loop cases."""
        source = self._real(logical)
        source.parent.mkdir(parents=True, exist_ok=True)
        if source.exists() or source.is_symlink():
            source.unlink()
        os.symlink(raw_target, str(source))
        return self

    def path(self, *directories: str) -> "World":
        entries = [d for d in self.env_vars["PATH"].split(":") if d]
        entries.extend(directories)
        self.env_vars["PATH"] = ":".join(dict.fromkeys(entries))
        for directory in directories:
            self.dir(directory)
        return self

    def var(self, name: str, value: str) -> "World":
        self.env_vars[name] = value
        return self

    # -- injected services ------------------------------------------------

    def proc(self, pid: int, exe: str, argv: Optional[List[str]] = None, ppid: int = 1,
             user: Optional[str] = None, cwd: str = "") -> "World":
        self.processes.append(ProcessInfo(pid, ppid, exe, argv or [os.path.basename(exe)],
                                          cwd=cwd, user=user or self.user))
        return self

    def sock(self, port: int, pid: int = 0) -> "World":
        self.sockets.append(SocketInfo(pid, port))
        return self

    def http(self, port: int, endpoint: str, payload: Any) -> "World":
        self._http[(port, endpoint)] = payload
        return self

    def reg(self, **fields: str) -> "World":
        self.registry.append(dict(fields))
        return self

    def used(self, catalog_id: str, stamp: str) -> "World":
        self.telemetry[catalog_id] = stamp
        return self

    def users(self, *names: str) -> "World":
        self.extra_users.extend(names)
        return self

    def run(self, contains: str, out: str, code: int = 0) -> "World":
        """Register a runner response for any argv containing ``contains``."""
        self._runs.append((contains, code, out))
        return self

    # -- materialize ------------------------------------------------------

    def _runner(self, argv, timeout):
        joined = " ".join(argv)
        for contains, code, out in self._runs:
            if contains == "!timeout" and "--version" in joined:
                raise TimeoutError("timed out")
            if contains and contains in joined:
                return code, out
        return 1, ""

    def _http_get(self, port, endpoint):
        return self._http.get((port, endpoint))

    def env(self) -> DiscoveryEnv:
        return DiscoveryEnv(
            root=self.root, platform=self.platform, home=self.home, user=self.user,
            env_vars=dict(self.env_vars), processes=self.processes, sockets=self.sockets,
            registry=self.registry, http=self._http_get, runner=self._runner,
            case_insensitive=self.case_insensitive, telemetry=self.telemetry,
            extra_users=self.extra_users, **self.extra)

    def scan(self):
        return discover(self.env(), hostname="fixture", timestamp="2026-08-18T00:00:00Z")

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)


# -- expectation helpers --------------------------------------------------

class Expect:
    """One named condition over a snapshot."""

    def __init__(self, label: str, check: Callable[[Any], Any]):
        self.label = label
        self.check = check

    def evaluate(self, snapshot):
        try:
            outcome = self.check(snapshot)
        except Exception as exc:
            return False, "%s: %s" % (exc.__class__.__name__, exc)
        if outcome is True or outcome is None:
            return True, ""
        if outcome is False:
            return False, "condition false"
        return False, str(outcome)


def assets(snapshot, **filters):
    """Select assets by field equality; catalog_id and kind are the usual keys."""
    found = []
    for asset in snapshot.assets:
        if all(getattr(asset, key, None) == value for key, value in filters.items()):
            found.append(asset)
    return found


def one(snapshot, **filters):
    matches = assets(snapshot, **filters)
    if len(matches) != 1:
        raise AssertionError("expected 1 %s, got %d: %s"
                             % (filters, len(matches), [a.name for a in matches]))
    return matches[0]


def queued(snapshot, name):
    return [item for item in snapshot.review_queue if item["name"] == name]


def findings(snapshot, kind):
    return [f for f in snapshot.findings if f["finding"] == kind]


def has(label, fn):
    return Expect(label, fn)


def run_cases(cases: Dict[str, Callable[[], Any]], only: Optional[str] = None):
    """Run every case, returning (results, failures)."""
    results = []
    for case_id in sorted(cases, key=_sort_key):
        if only and not case_id.startswith(only):
            continue
        world = None
        try:
            world, expectations = cases[case_id]()
            snapshot = world.scan()
            for expectation in expectations:
                ok, detail = expectation.evaluate(snapshot)
                results.append((case_id, expectation.label, ok, detail))
        except Exception as exc:
            results.append((case_id, "case setup", False,
                            "%s: %s" % (exc.__class__.__name__, exc)))
        finally:
            if world is not None:
                world.cleanup()
    failures = [r for r in results if not r[2]]
    return results, failures


def _sort_key(case_id: str):
    group, _, number = case_id.partition("-")
    return (group, int(number)) if number.isdigit() else (group, 0)
