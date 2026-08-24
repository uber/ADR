"""macOS providers.

`ps -o comm=` returns a full executable path here rather than a truncated
name, so the exe requirement is met without /proc.
"""

from __future__ import annotations

import plistlib
import pwd

from .base import Application, LanguagePackages, NullProviders, Package, Process, Socket


class DarwinProviders(NullProviders):
    reason = "not readable on this host"

    #: `/home` is autofs here and blocks indefinitely when automountd is
    #: unresponsive. Homes live under /Users; there is nothing to gain by
    #: asking, and a hang to lose.
    HOME_ROOTS = ("/Users",)

    def _homes(self, gate) -> tuple[str, ...]:
        out: list[str] = []
        for base in self.home_roots():
            listing = gate.list_dir(base)
            if listing.ok:
                out.extend(e.path for e in listing.value if e.is_dir)
        return tuple(out)

    def owner_of(self, uid: int) -> str:
        try:
            return pwd.getpwuid(uid).pw_name
        except KeyError:
            return str(uid)

    def processes(self, gate):
        from ..gate import Ok

        ran = gate.run(("ps", "-axo", "pid=,ppid=,user=,comm="))
        if not ran.ok or ran.value.code != 0:
            return self._unavailable(gate, "processes")
        procs: list[Process] = []
        for line in ran.value.stdout.splitlines():
            parts = line.strip().split(None, 3)
            if len(parts) < 4:
                continue
            pid, ppid, user, exe = parts
            if not pid.isdigit():
                continue
            procs.append(Process(pid=int(pid), exe=exe, ppid=int(ppid) if ppid.isdigit() else 0, user=user))
        return Ok(tuple(procs))

    def sockets(self, gate):
        from ..gate import Ok

        ran = gate.run(("lsof", "-nP", "-iTCP"))
        if not ran.ok or ran.value.code != 0:
            return self._unavailable(gate, "sockets")
        out: list[Socket] = []
        for line in ran.value.stdout.splitlines()[1:]:
            cols = line.split()
            if len(cols) < 9 or not cols[1].isdigit():
                continue
            endpoint = cols[8]
            raw_state = cols[9].strip("()") if len(cols) > 9 else ""
            state = "LISTEN" if raw_state == "LISTEN" else "ESTABLISHED" if "->" in endpoint else ""
            if not state:
                continue
            local, _, remote = endpoint.partition("->")
            _, lport = _split_colon_hostport(local)
            rhost, rport = _split_colon_hostport(remote) if remote else ("", 0)
            out.append(Socket("tcp", state, lport, rhost, rport, int(cols[1])))
        return Ok(tuple(out))

    def applications(self, gate):
        from ..gate import Ok

        apps: list[Application] = []
        for root in ("/Applications", "/System/Applications"):
            listing = gate.list_dir(root)
            if not listing.ok:
                continue
            for entry in listing.value:
                if not entry.path.endswith(".app"):
                    continue
                raw = gate.read_bytes(entry.path + "/Contents/Info.plist", limit=1 << 20)
                if not raw.ok:
                    continue
                try:
                    info = plistlib.loads(raw.value)
                except Exception:
                    gate.ledger.probe("Info.plist", "degraded", entry.path)
                    continue
                apps.append(
                    Application(
                        ident=str(info.get("CFBundleIdentifier", "")),
                        name=str(info.get("CFBundleName", entry.path.rsplit("/", 1)[-1])),
                        version=_str_or_none(info.get("CFBundleShortVersionString")),
                        path=entry.path,
                    )
                )
        if not apps:
            return self._unavailable(gate, "applications")
        return Ok(tuple(apps))

    def dns_cache(self, gate):
        # The macOS resolver cache has not been externally enumerable since
        # the mDNSResponder rework. Say so; do not return an empty list.
        gate.ledger.unavailable("dns_cache", "mDNSResponder cache is not enumerable")
        from ..gate import Refused

        return Refused("unavailable", "mDNSResponder cache is not enumerable")

    def packages(self, gate):
        from ..gate import Ok

        found: list[Package] = []
        found.extend(LanguagePackages().collect(gate, self._homes(gate)))
        for cellar in ("/opt/homebrew/Cellar", "/usr/local/Cellar"):
            listing = gate.list_dir(cellar)
            if not listing.ok:
                continue
            for entry in listing.value:
                if not entry.is_dir:
                    continue
                name = entry.path.rsplit("/", 1)[-1]
                versions = gate.list_dir(entry.path)
                version = (
                    versions.value[-1].path.rsplit("/", 1)[-1] if versions.ok and versions.value else None
                )
                found.append(Package("brew", name, version, entry.path))
        if not found:
            return self._unavailable(gate, "packages")
        return Ok(tuple(found))


def _str_or_none(v):
    return str(v) if v is not None else None


def _port(hostport: str) -> int:
    tail = hostport.rsplit(".", 1)[-1]
    return int(tail) if tail.isdigit() else 0


def _split_hostport(hostport: str) -> tuple[str, int]:
    host, _, port = hostport.rpartition(".")
    return host, int(port) if port.isdigit() else 0


def _split_colon_hostport(value: str) -> tuple[str, int]:
    host, sep, port = value.rpartition(":")
    return (host, int(port)) if sep and port.isdigit() else (value, 0)
