"""The injected view of the world a probe is allowed to see.

A probe that calls ``Path.home()`` or shells out to ``ps`` cannot be pointed at
a known world, and is therefore unevaluable. Every probe takes a
:class:`DiscoveryEnv` instead: a filesystem root, an environment block, a
process table, a socket table, a Windows registry view, an HTTP prober and a
subprocess runner. In production these are backed by the live machine; in the
test corpus they are backed by a fixture directory.
"""

import errno
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from .redact import is_denied

#: ``${NAME}``, ``$NAME`` and ``%NAME%``, matched as whole tokens.
_VARIABLE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}"
                       r"|\$([A-Za-z_][A-Za-z0-9_]*)"
                       r"|%([A-Za-z_][A-Za-z0-9_]*)%")

#: Ceiling on any single file read, so a hostile or merely enormous config
#: cannot exhaust memory on an employee laptop.
MAX_READ_BYTES = 1_000_000

#: Hard cap on directory descent, independent of what a caller asks for.
MAX_DEPTH = 8

#: Cap on entries visited in one walk, so a pathological tree cannot stall a scan.
MAX_WALK_ENTRIES = 20_000


@dataclass(frozen=True)
class ProcessInfo:
    """One row of the process table."""

    pid: int
    ppid: int
    exe: str
    argv: List[str] = field(default_factory=list)
    cwd: str = ""
    user: str = ""
    start: str = ""


@dataclass(frozen=True)
class SocketInfo:
    """One listening socket, attributed to a pid."""

    pid: int
    port: int
    state: str = "LISTEN"
    remote: str = ""


class ReadResult:
    """Outcome of a bounded read.

    Carries raw bytes, because some of the things a probe reads are binary -
    a macOS ``Info.plist`` is usually a binary plist, and decoding it to text
    first destroys it.
    """

    __slots__ = ("data", "truncated", "error")

    def __init__(self, data: bytes = b"", truncated: bool = False, error: Optional[str] = None):
        self.data = data
        self.truncated = truncated
        self.error = error

    @property
    def text(self) -> str:
        return self.data.decode("utf-8", "replace")

    def __bool__(self) -> bool:
        return self.error is None


class DiscoveryEnv:
    """The world a probe may observe.

    Paths passed to and returned from this class are *logical* - they look like
    absolute paths on the target machine (``/Applications/Claude.app``). They
    are resolved beneath ``root``, which is ``/`` in production.
    """

    def __init__(
        self,
        root: Path,
        platform: str = "darwin",
        home: str = "/Users/alice",
        user: str = "alice",
        env_vars: Optional[Dict[str, str]] = None,
        processes: Sequence[ProcessInfo] = (),
        sockets: Sequence[SocketInfo] = (),
        registry: Sequence[Dict[str, str]] = (),
        http: Optional[Callable[[int, str], Optional[Any]]] = None,
        runner: Optional[Callable[[List[str], float], Tuple[int, str]]] = None,
        case_insensitive: bool = False,
        telemetry: Optional[Dict[str, str]] = None,
        extra_users: Sequence[str] = (),
        locations: Sequence[Dict[str, str]] = (),
        scheduled_tasks: Sequence[Dict[str, Any]] = (),
        preferences: Optional[Dict[str, Any]] = None,
        policy: Optional[Dict[str, Any]] = None,
    ):
        self.root = Path(root)
        self.platform = platform
        self.home = home
        self.user = user
        self.env_vars = dict(env_vars or {})
        self.processes = list(processes)
        self.sockets = list(sockets)
        self.registry = list(registry)
        self.case_insensitive = case_insensitive
        #: catalog id -> ISO timestamp of the most recent session, from Sensor.
        self.telemetry = dict(telemetry or {})
        self.extra_users = list(extra_users)
        #: Filesystem roots that are on this machine but not of this OS - WSL
        #: distributions, mounted container images. Each is
        #: ``{"kind": "wsl", "name": "Ubuntu", "root": "/wsl/Ubuntu", "home": "/home/alice"}``.
        #: A tool installed in one of these is present on the endpoint even
        #: though no host path contains it.
        self.locations = [dict(item) for item in locations]
        #: Windows Task Scheduler entries, as the platform reports them.
        self.scheduled_tasks = [dict(item) for item in scheduled_tasks]
        #: macOS managed-preference domains, as delivered by MDM. A file-only
        #: probe reports an MDM-managed fleet as having no policy at all.
        self.preferences = dict(preferences or {})
        #: Tenant configuration: corporate domains, sensitive repositories.
        #: Never hardcoded - one tenant's internal host is another's third party.
        self.policy = dict(policy or {})
        self._http = http
        self._runner = runner
        #: Probes append error records here rather than raising.
        self.errors: List[Dict[str, str]] = []
        #: Subprocess calls that had to be killed, for robustness assertions.
        self.killed: List[List[str]] = []
        #: What the scan could not see, so a partial inventory is legible as one.
        self.coverage: Dict[str, Any] = {}

    # -- path plumbing ----------------------------------------------------

    def real(self, logical: str) -> Path:
        """Map a logical absolute path to its location beneath ``root``."""
        text = self.expand(logical)
        return self.root / text.lstrip("/\\").replace("\\", "/")

    def resolve_target(self, logical: str) -> Tuple[Optional[Path], Optional[str]]:
        """Canonicalize a path and decide whether we are allowed to touch it.

        Two checks, and both have to run against the *resolved* target rather
        than the path we were handed. A permitted path can be a symlink into a
        denied one, and a relative segment inside a config can climb out of the
        tree we were pointed at - in both cases the name we started from looks
        entirely innocent.
        """
        candidate = self.real(logical)
        try:
            resolved = Path(os.path.realpath(str(candidate)))
        except (OSError, ValueError):
            return None, "unresolvable path"
        if not self._within_root(resolved):
            return None, "outside discovery root"
        requested = self.expand(logical)
        if is_denied(requested):
            # Asked for outright. Refused quietly: enumerating a home directory
            # meets these constantly and each one is expected, not an event.
            return None, "denied path"
        if is_denied(self.logical(resolved)):
            # Permitted on the way in, denied on the way out. That is the shape
            # of a deliberate bypass, and it is worth saying out loud.
            self.errors.append({"probe": "env", "path": requested,
                                "message": "refused: resolves into a denied path"})
            self.coverage.setdefault("denied", []).append(requested)
            return None, "denied path"
        return candidate, None

    def _within_root(self, resolved: Path) -> bool:
        """True when a canonical path is still inside the tree we may read."""
        root = Path(os.path.realpath(str(self.root)))
        if str(root) == os.sep:
            return True
        try:
            resolved.relative_to(root)
            return True
        except ValueError:
            return False

    def logical(self, real: Path) -> str:
        """Map a path beneath ``root`` back to its logical form.

        Tolerant of symlinked prefixes - on macOS ``/var`` is a link to
        ``/private/var``, so the same directory has two spellings and a naive
        prefix strip leaks the fixture root into every install path.
        """
        for base in (self.root, Path(os.path.realpath(str(self.root)))):
            for candidate in (Path(real), Path(os.path.realpath(str(real)))):
                try:
                    return "/" + str(candidate.relative_to(base))
                except ValueError:
                    continue
        return str(real)

    def expand(self, logical: str) -> str:
        """Expand ``~``, ``$VAR``, ``${VAR}`` and ``%VAR%`` in a single pass.

        Substituting one variable at a time by substring rewrites the *names* of
        other variables: with PATH and PATH_EXTRA both set, ``$PATH_EXTRA``
        becomes ``/bin_EXTRA``. Whole tokens are matched instead, so the longest
        name always wins because it is the token that was written.
        """
        text = logical
        if text.startswith("~"):
            text = self.home + text[1:]

        def substitute(match):
            name = match.group(1) or match.group(2) or match.group(3)
            return self.env_vars.get(name, match.group(0))

        return _VARIABLE.sub(substitute, text)

    def exists(self, logical: str) -> bool:
        target, refusal = self.resolve_target(logical)
        if refusal:
            return False
        try:
            return target.exists()
        except OSError:
            return False

    def is_dir(self, logical: str) -> bool:
        target, refusal = self.resolve_target(logical)
        if refusal:
            return False
        try:
            return target.is_dir()
        except OSError:
            return False

    def listdir(self, logical: str) -> List[str]:
        """List a directory, tolerating anything that goes wrong."""
        target, refusal = self.resolve_target(logical)
        if refusal:
            return []
        try:
            return sorted(entry.name for entry in target.iterdir())
        except OSError:
            return []

    def realpath(self, logical: str) -> str:
        """Deref symlinks with loop protection, staying in logical space.

        Real-path resolution is the primary merge key, so a symlink chain that
        never terminates has to fail closed rather than hang the scan.
        """
        current = self.real(logical)
        for _ in range(MAX_DEPTH * 5):
            try:
                if not current.is_symlink():
                    break
                target = os.readlink(str(current))
            except OSError:
                break
            if os.path.isabs(target):
                # An absolute link target is a real path when it already lives
                # under the root, and a logical one otherwise. In production the
                # root is "/" and the two are the same thing.
                candidate = Path(target)
                inside = str(candidate).startswith(str(self.root))
                following = candidate if inside else self.real(target)
            else:
                # Resolve a relative target against the *canonicalized* parent.
                # On a usrmerge system /bin is a symlink to usr/bin, so joining
                # "../lib/node_modules/x" onto the literal parent yields
                # /lib/node_modules/x while the same binary reached via
                # /usr/bin yields /usr/lib/node_modules/x. Two spellings of one
                # file produce two merge keys and the tool is counted twice.
                parent = Path(os.path.realpath(str(current.parent)))
                following = parent / target
            try:
                following = Path(os.path.normpath(str(following)))
            except (OSError, ValueError):
                break
            if following == current:
                break
            current = following
        canonical = Path(os.path.realpath(str(current)))
        if not self._within_root(canonical):
            # A link out of the tree resolves to nothing we may describe, so the
            # path we were given is the most we can honestly report.
            resolved = self.expand(logical)
        elif is_denied(self.logical(canonical)):
            # Reporting where a denied link points discloses the very path the
            # deny-list exists to keep out of the output.
            self.coverage.setdefault("denied", []).append(self.expand(logical))
            resolved = self.expand(logical)
        else:
            resolved = self.logical(current)
        return resolved.lower() if self.case_insensitive else resolved

    def walk(self, logical: str, max_depth: int = 3):
        """Depth- and count-bounded walk that never follows symlinked directories.

        A ceiling that fires is recorded. Silent truncation is indistinguishable
        from an empty directory, and reads as coverage nobody actually has.
        """
        base, refusal = self.resolve_target(logical)
        if refusal or base is None or not base.is_dir():
            return
        stack = [(base, 0)]
        visited = set()
        yielded = 0
        while stack:
            directory, depth = stack.pop()
            try:
                marker = os.stat(str(directory)).st_ino
            except OSError:
                continue
            if marker in visited:
                continue
            visited.add(marker)
            try:
                entries = sorted(directory.iterdir())
            except OSError:
                continue
            for entry in entries:
                yielded += 1
                if yielded > MAX_WALK_ENTRIES:
                    self.errors.append({
                        "probe": "env", "path": self.expand(logical),
                        "message": "walk truncated at %d entries" % MAX_WALK_ENTRIES})
                    self.coverage.setdefault("truncated_walks", []).append(self.expand(logical))
                    return
                yield self.logical(entry), entry
                if depth + 1 < min(max_depth, MAX_DEPTH):
                    try:
                        if entry.is_dir() and not entry.is_symlink():
                            stack.append((entry, depth + 1))
                    except OSError:
                        continue

    # -- bounded, hostile-input-safe reads --------------------------------

    def read(self, logical: str, limit: int = MAX_READ_BYTES) -> ReadResult:
        """Read a file with a byte ceiling, refusing anything that could block.

        Named pipes, devices and sockets are rejected outright: a probe that
        opens a FIFO on a developer's machine hangs the entire scan.
        """
        path, refusal = self.resolve_target(logical)
        if refusal:
            return ReadResult(error=refusal)
        try:
            info = os.lstat(str(path))
        except OSError as exc:
            return ReadResult(error="stat: %s" % (exc.strerror or exc))
        if stat.S_ISLNK(info.st_mode):
            try:
                info = os.stat(str(path))
            except OSError as exc:
                return ReadResult(error="stat: %s" % (exc.strerror or exc))
        if not stat.S_ISREG(info.st_mode):
            return ReadResult(error="not a regular file")
        try:
            expected = os.stat(str(Path(os.path.realpath(str(path)))))
        except OSError as exc:
            return ReadResult(error="stat: %s" % (exc.strerror or exc))
        try:
            handle = os.open(str(path), os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        except OSError as exc:
            if exc.errno in (errno.EACCES, errno.EPERM):
                return ReadResult(error="permission denied")
            return ReadResult(error="open: %s" % (exc.strerror or exc))
        # Checking a path and then opening it are two operations, and a symlink
        # can be swapped between them. Compare what was actually opened against
        # what was validated, so a swap is a refusal rather than a read.
        try:
            opened = os.fstat(handle)
        except OSError as exc:
            os.close(handle)
            return ReadResult(error="fstat: %s" % (exc.strerror or exc))
        if (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
            os.close(handle)
            self.errors.append({"probe": "env", "path": self.expand(logical),
                                "message": "refused: path changed between check and open"})
            return ReadResult(error="path changed during read")
        try:
            chunks = []
            total = 0
            # Read one byte past the ceiling so a file sitting exactly on it is
            # reported whole rather than as truncated.
            ceiling = limit + 1
            while total < ceiling:
                block = os.read(handle, min(65536, ceiling - total))
                if not block:
                    break
                chunks.append(block)
                total += len(block)
            truncated = total > limit
        except OSError as exc:
            return ReadResult(error="read: %s" % (exc.strerror or exc))
        finally:
            os.close(handle)
        return ReadResult(b"".join(chunks)[:limit], truncated)

    # -- injected services ------------------------------------------------

    def http_get(self, port: int, path: str) -> Optional[Any]:
        """Probe a localhost port. Returns parsed JSON, or None."""
        if self._http is None:
            return None
        try:
            return self._http(port, path)
        except Exception:
            return None

    def run(self, argv: List[str], timeout: float = 2.0) -> Optional[str]:
        """Run a command under a hard timeout. Returns stdout, or None.

        A timeout is recorded rather than raised: a binary that hangs on
        ``--version`` must cost one timeout, not the scan.
        """
        if self._runner is None:
            return None
        try:
            code, out = self._runner(list(argv), timeout)
        except TimeoutError:
            self.killed.append(list(argv))
            return None
        except Exception:
            return None
        return out if code == 0 else None

    def children_of(self, pid: int) -> List[ProcessInfo]:
        return [process for process in self.processes if process.ppid == pid]
