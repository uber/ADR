"""Linux providers. Processes come from /proc, never from a name."""

from __future__ import annotations

import os
import pwd

from .base import Application, LanguagePackages, NullProviders, Package, Process, Socket


class LinuxProviders(NullProviders):
    reason = "not readable on this host"

    HOME_ROOTS = ("/home", "/root")

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

        procs: list[Process] = []
        listing = gate.list_dir("/proc")
        if not listing.ok:
            return self._unavailable(gate, "processes")
        for entry in listing.value:
            name = entry.path.rsplit("/", 1)[-1]
            if not name.isdigit():
                continue
            pid = int(name)
            # The link target, not the name: one syscall, and it is the
            # difference between /opt/agents/claude and /usr/bin/claude.
            try:
                exe = os.readlink(gate.host_path(f"/proc/{pid}/exe"))
            except OSError:
                continue
            cmdline = gate.read_bytes(f"/proc/{pid}/cmdline", limit=8192)
            argv = tuple(cmdline.value.decode("utf-8", "replace").split("\0")[:-1]) if cmdline.ok else ()
            try:
                cwd = os.readlink(gate.host_path(f"/proc/{pid}/cwd"))
            except OSError:
                cwd = None
            status = gate.read_text(f"/proc/{pid}/status", limit=4096)
            ppid, uid = 0, 0
            if status.ok:
                for line in status.value.splitlines():
                    if line.startswith("PPid:"):
                        ppid = int(line.split()[1])
                    elif line.startswith("Uid:"):
                        uid = int(line.split()[1])
            environ = gate.read_bytes(f"/proc/{pid}/environ", limit=32768)
            env_names = ()
            if environ.ok:
                env_names = tuple(
                    sorted(
                        {
                            part.split("=", 1)[0]
                            for part in environ.value.decode("utf-8", "replace").split("\0")
                            if "=" in part
                        }
                    )
                )
            procs.append(
                Process(pid=pid, exe=exe, argv=argv, ppid=ppid, cwd=cwd,
                        user=self.owner_of(uid), env_names=env_names)
            )
        return Ok(tuple(procs))

    def sockets(self, gate):
        from ..gate import Ok

        out: list[Socket] = []
        inode_pids = _socket_pids(gate)
        for proto, path in (("tcp", "/proc/net/tcp"), ("tcp6", "/proc/net/tcp6")):
            raw = gate.read_text(path, limit=1 << 20)
            if not raw.ok:
                continue
            for line in raw.value.splitlines()[1:]:
                cols = line.split()
                if len(cols) < 4:
                    continue
                try:
                    lport = int(cols[1].split(":")[1], 16)
                    rhex, rport_hex = cols[2].split(":")
                    rport = int(rport_hex, 16)
                    inode = cols[9]
                except (ValueError, IndexError):
                    continue
                state = {"0A": "LISTEN", "01": "ESTABLISHED"}.get(cols[3], cols[3])
                if state not in ("LISTEN", "ESTABLISHED"):
                    continue
                out.append(
                    Socket(proto=proto, state=state, local_port=lport,
                           remote_host=_hex_ip(rhex), remote_port=rport,
                           pid=inode_pids.get(inode))
                )
        if not out:
            return self._unavailable(gate, "sockets")
        return Ok(tuple(out))

    def packages(self, gate):
        from ..gate import Ok

        found: list[Package] = []
        found.extend(LanguagePackages().collect(gate, self._homes(gate)))
        status = gate.read_text("/var/lib/dpkg/status", limit=8 << 20)
        if status.ok:
            name = version = None
            for line in status.value.splitlines():
                if line.startswith("Package: "):
                    name = line[9:].strip()
                elif line.startswith("Version: "):
                    version = line[9:].strip()
                elif not line.strip() and name:
                    found.append(Package("dpkg", name, version))
                    name = version = None
        else:
            gate.ledger.unavailable("dpkg", "status file not readable")

        apk = gate.read_text("/lib/apk/db/installed", limit=8 << 20)
        if apk.ok:
            name = version = None
            for line in apk.value.splitlines() + [""]:
                if line.startswith("P:"):
                    name = line[2:]
                elif line.startswith("V:"):
                    version = line[2:]
                elif not line and name:
                    found.append(Package("apk", name, version))
                    name = version = None

        for root, manager in (("/var/lib/snapd/snaps", "snap"), ("/var/lib/flatpak/app", "flatpak")):
            listing = gate.list_dir(root)
            if not listing.ok:
                continue
            for entry in listing.value:
                name = entry.path.rsplit("/", 1)[-1]
                if manager == "snap" and name.endswith(".snap"):
                    stem = name[:-5]
                    pkg, _, version = stem.rpartition("_")
                    found.append(Package(manager, pkg or stem, version or None, entry.path))
                elif manager == "flatpak" and entry.is_dir:
                    found.append(Package(manager, name, None, entry.path))

        rpm = gate.run_helper(("/usr/bin/rpm", "-qa", "--qf", "%{NAME}\\t%{VERSION}-%{RELEASE}\\n"))
        if rpm.ok and rpm.value.code == 0:
            for line in rpm.value.stdout.splitlines():
                name, sep, version = line.partition("\t")
                if sep:
                    found.append(Package("rpm", name, version))
        if not found:
            return self._unavailable(gate, "packages")
        return Ok(tuple(found))

    def applications(self, gate):
        from ..gate import Ok

        apps: list[Application] = []
        for root in ("/usr/share/applications", "/var/lib/flatpak/exports/share/applications"):
            listing = gate.list_dir(root)
            if not listing.ok:
                continue
            for entry in listing.value:
                if not entry.path.endswith(".desktop"):
                    continue
                raw = gate.read_text(entry.path, limit=65536)
                if not raw.ok:
                    continue
                fields = dict(
                    line.split("=", 1) for line in raw.value.splitlines() if "=" in line and not line.startswith("#")
                )
                apps.append(
                    Application(
                        ident=entry.path.rsplit("/", 1)[-1].removesuffix(".desktop"),
                        name=fields.get("Name", ""),
                        version=fields.get("Version"),
                        path=fields.get("Exec"),
                    )
                )
        if not apps:
            return self._unavailable(gate, "applications")
        return Ok(tuple(apps))

    def dns_cache(self, gate):
        ran = gate.run_helper(("/usr/bin/resolvectl", "statistics"))
        if not ran.ok:
            return self._unavailable(gate, "dns_cache")
        # resolvectl exposes counters, not entries, on most builds. Report
        # the surface as unavailable rather than inventing an empty answer.
        gate.ledger.unavailable("dns_cache", "resolvectl exposes counters, not cache entries")
        from ..gate import Refused

        return Refused("unavailable", "no enumerable resolver cache")

    def package_owner(self, gate, path):
        from ..gate import Ok, Refused

        ran = gate.run_helper(("/usr/bin/dpkg", "-S", path))
        if not ran.ok:
            return ran
        if ran.value.code != 0 or ":" not in ran.value.stdout:
            return Refused("not_owned", path)
        pkg = ran.value.stdout.split(":", 1)[0].strip()
        return Ok(Package("dpkg", pkg, None, path))


def _hex_ip(hex_addr: str) -> str:
    if len(hex_addr) == 8:
        octets = [int(hex_addr[i : i + 2], 16) for i in (6, 4, 2, 0)]
        return ".".join(str(o) for o in octets)
    return hex_addr


def _socket_pids(gate) -> dict[str, int]:
    """Join /proc/net socket inodes back to their owning processes."""
    owners: dict[str, int] = {}
    procs = gate.list_dir("/proc")
    if not procs.ok:
        return owners
    for proc in procs.value:
        name = proc.path.rsplit("/", 1)[-1]
        if not name.isdigit() or not proc.is_dir:
            continue
        fds = gate.list_dir(proc.path + "/fd")
        if not fds.ok:
            continue
        for fd in fds.value:
            try:
                target = os.readlink(gate.host_path(fd.path))
            except OSError:
                continue
            if target.startswith("socket:[") and target.endswith("]"):
                owners[target[8:-1]] = int(name)
    return owners
