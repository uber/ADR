"""Provider shapes, and the two providers that need no OS at all.

The only place an OS difference may exist is under this package. Everything
above it sees these dataclasses and nothing else, which is what makes a
fixture world and a live machine interchangeable.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..gate import Gate, Result


@dataclass(frozen=True, slots=True)
class Process:
    pid: int
    exe: str
    """The link target of /proc/<pid>/exe, or its platform equivalent.

    Never a name. `ps comm=` truncates at fifteen characters on Linux, and
    resolving that name against PATH attributes /opt/agents/claude to
    /usr/bin/claude -- a different binary.
    """
    argv: tuple[str, ...] = ()
    ppid: int = 0
    cwd: str | None = None
    user: str = "system"
    env_names: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Socket:
    proto: str
    state: str  # LISTEN | ESTABLISHED
    local_port: int = 0
    remote_host: str = ""
    remote_port: int = 0
    pid: int | None = None


@dataclass(frozen=True, slots=True)
class Package:
    manager: str
    name: str
    version: str | None = None
    path: str | None = None


@dataclass(frozen=True, slots=True)
class Application:
    ident: str
    name: str
    version: str | None = None
    vendor: str | None = None
    path: str | None = None


@dataclass(frozen=True, slots=True)
class DnsEntry:
    hostname: str


@dataclass(frozen=True, slots=True)
class ExecEvent:
    """What ran between scans. Absent unless a privileged collector supplies
    it -- and its absence is a coverage fact, never an empty set."""

    exe: str
    argv: tuple[str, ...] = ()
    ppid: int = 0
    parent_exe: str | None = None
    started: str = ""


class Providers(Protocol):
    def home_roots(self) -> tuple[str, ...]: ...
    def owner_of(self, uid: int) -> str: ...
    def processes(self, gate: "Gate") -> "Result": ...
    def sockets(self, gate: "Gate") -> "Result": ...
    def packages(self, gate: "Gate") -> "Result": ...
    def applications(self, gate: "Gate") -> "Result": ...
    def dns_cache(self, gate: "Gate") -> "Result": ...
    def exec_journal(self, gate: "Gate") -> "Result": ...
    def package_owner(self, gate: "Gate", path: str) -> "Result": ...


class NullProviders:
    """Every query is unavailable, with a reason.

    This is the correct provider for a platform nobody has implemented yet:
    it makes the gap appear in coverage instead of making the machine look
    clean, which is the difference the whole design turns on.
    """

    reason = "no provider for this platform"

    #: Where user homes live. A platform question, and therefore not one
    #: M2 may answer: on macOS `/home` is an autofs mount that blocks a
    #: lister for as long as automountd feels like it, and a scan that
    #: hangs there is indistinguishable from a scan that found nothing.
    HOME_ROOTS: tuple[str, ...] = ("/Users", "/home")

    def home_roots(self) -> tuple[str, ...]:
        return self.HOME_ROOTS

    def owner_of(self, uid: int) -> str:
        return "system"

    def _unavailable(self, gate: "Gate", name: str):
        from ..gate import Refused

        gate.ledger.unavailable(name, self.reason)
        return Refused("unavailable", self.reason)

    def processes(self, gate):
        return self._unavailable(gate, "processes")

    def sockets(self, gate):
        return self._unavailable(gate, "sockets")

    def packages(self, gate):
        return self._unavailable(gate, "packages")

    def applications(self, gate):
        return self._unavailable(gate, "applications")

    def dns_cache(self, gate):
        return self._unavailable(gate, "dns_cache")

    def exec_journal(self, gate):
        return self._unavailable(gate, "exec_journal")

    def package_owner(self, gate, path):
        return self._unavailable(gate, "package_owner")


class LanguagePackages:
    """Package databases that are the same on every platform.

    npm, pipx, uv, cargo and go keep their manifests on disk in the same
    shape everywhere, so reading them is not an OS difference and does not
    belong in a per-platform provider. Every read goes through the gate,
    so a fixture tree answers these exactly as a real machine does.
    """

    NODE_ROOTS = (
        "/usr/local/lib/node_modules", "/opt/homebrew/lib/node_modules",
        "/usr/lib/node_modules", "~/.npm-global/lib/node_modules",
        "~/.nvm/versions/node", "~/node_modules",
    )
    PIPX_ROOTS = ("~/.local/pipx/venvs", "~/.local/share/pipx/venvs")
    UV_ROOTS = ("~/.local/share/uv/tools",)
    BIN_ROOTS = ("~/.cargo/bin", "~/go/bin", "~/.local/bin")

    def collect(self, gate, homes: tuple[str, ...]) -> list[Package]:
        found: list[Package] = []
        found.extend(self._npm(gate, homes))
        found.extend(self._venvs(gate, homes, self.PIPX_ROOTS, "pipx"))
        found.extend(self._venvs(gate, homes, self.UV_ROOTS, "uv"))
        found.extend(self._cargo(gate, homes))
        found.extend(self._go(gate, homes))
        return found

    def _cargo(self, gate, homes) -> list[Package]:
        out: list[Package] = []
        for home in homes:
            raw = gate.read_text(home + "/.cargo/.crates2.json", limit=4 << 20)
            if not raw.ok:
                continue
            try:
                document = json.loads(raw.value)
            except ValueError:
                gate.ledger.probe("cargo", "degraded", home + "/.cargo/.crates2.json")
                continue
            for key in (document.get("installs") or {}):
                # Current Cargo uses "name version (source)" as the key.
                parts = key.split()
                if parts:
                    name = parts[0]
                    version = parts[1] if len(parts) > 1 else None
                    out.append(Package("cargo", name, version, home + "/.cargo/bin"))
        return out

    def _go(self, gate, homes) -> list[Package]:
        out: list[Package] = []
        for home in homes:
            listing = gate.list_dir(home + "/go/bin")
            if not listing.ok:
                continue
            for entry in listing.value:
                if entry.is_dir or not entry.is_exec:
                    continue
                ran = gate.run(("go", "version", "-m", entry.path))
                if not ran.ok or ran.value.code != 0:
                    continue
                for line in ran.value.stdout.splitlines():
                    fields = line.strip().split()
                    if len(fields) >= 3 and fields[0] == "mod":
                        out.append(Package("go", fields[1], fields[2], entry.path))
                        break
        return out

    def _expand(self, template: str, homes: tuple[str, ...]) -> list[str]:
        if not template.startswith("~"):
            return [template]
        return [home + template[1:] for home in homes]

    def _npm(self, gate, homes) -> list[Package]:
        import json as _json

        out: list[Package] = []
        for template in self.NODE_ROOTS:
            for root in self._expand(template, homes):
                listing = gate.list_dir(root)
                if not listing.ok:
                    continue
                for entry in listing.value:
                    if not entry.is_dir:
                        continue
                    name = entry.path.rsplit("/", 1)[-1]
                    # Scoped packages hold their real entries one level down.
                    targets = [entry.path]
                    if name.startswith("@"):
                        scoped = gate.list_dir(entry.path)
                        targets = [e.path for e in scoped.value] if scoped.ok else []
                    for target in targets:
                        raw = gate.read_text(target + "/package.json", limit=1 << 20)
                        if not raw.ok:
                            continue
                        try:
                            manifest = _json.loads(raw.value)
                        except ValueError:
                            gate.ledger.probe("npm", "degraded", target)
                            continue
                        out.append(
                            Package("npm", str(manifest.get("name") or ""),
                                    _opt_str(manifest.get("version")), target)
                        )
        return out

    def _venvs(self, gate, homes, roots, manager) -> list[Package]:
        out: list[Package] = []
        for template in roots:
            for root in self._expand(template, homes):
                listing = gate.list_dir(root)
                if not listing.ok:
                    continue
                for entry in listing.value:
                    if entry.is_dir:
                        out.append(Package(manager, entry.path.rsplit("/", 1)[-1], None, entry.path))
        return out


def _opt_str(value):
    return str(value) if value is not None else None


class FixtureProviders(NullProviders):
    """Reads the non-filesystem surfaces from JSON beside the fixture tree.

    A surface with no file is *unavailable*, not empty -- so a case that
    forgets to supply processes.json fails loudly rather than quietly
    asserting that nothing was running.
    """

    reason = "not supplied by this fixture"

    FILES = {
        "processes": ("processes.json", Process),
        "sockets": ("sockets.json", Socket),
        "packages": ("packages.json", Package),
        "applications": ("applications.json", Application),
        "dns_cache": ("dns.json", DnsEntry),
        "exec_journal": ("execjournal.json", ExecEvent),
    }

    def __init__(self, data: dict[str, object] | None = None) -> None:
        self._data = data or {}

    def _load(self, gate: "Gate", surface: str):
        from ..gate import Ok

        if surface in self._data:
            rows = self._data[surface]
        else:
            filename, _ = self.FILES[surface]
            raw = gate.read_text("/" + filename)
            if not raw.ok:
                return self._unavailable(gate, surface)
            try:
                rows = json.loads(raw.value)
            except json.JSONDecodeError as exc:
                gate.ledger.unavailable(surface, f"malformed fixture: {exc}")
                from ..gate import Refused

                return Refused("malformed", str(exc))
        _, cls = self.FILES[surface]
        out = []
        for row in rows:
            row = dict(row)
            for key in ("argv", "env_names"):
                if key in row and isinstance(row[key], list):
                    row[key] = tuple(row[key])
            out.append(cls(**row))
        return Ok(tuple(out))

    def processes(self, gate):
        return self._load(gate, "processes")

    def sockets(self, gate):
        return self._load(gate, "sockets")

    def packages(self, gate):
        return self._load(gate, "packages")

    def applications(self, gate):
        return self._load(gate, "applications")

    def dns_cache(self, gate):
        return self._load(gate, "dns_cache")

    def exec_journal(self, gate):
        return self._load(gate, "exec_journal")

    def package_owner(self, gate, path):
        from ..gate import Ok, Refused

        pkgs = self._load(gate, "packages")
        if not pkgs.ok:
            return pkgs
        for pkg in pkgs.value:
            if pkg.path and pkg.path == path:
                return Ok(pkg)
        return Refused("not_owned", path)
