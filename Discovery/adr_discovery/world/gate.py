"""M1 -- the single door between the collector and the machine.

Everything else in this design is testable only because this module
exists: below the gate, a fixture directory and a live machine are
interchangeable, which is what lets the whole pipeline be graded.

Order is fixed and is the point:

    canonicalize -> contain -> deny-list -> open -> verify the descriptor -> read under budget

Containment and denial are decided on the *resolved* target rather than the
path handed in, because a permitted config can be a symlink into a personal
directory, and a relative segment inside a config can climb out of the tree.
"""

from __future__ import annotations

import errno
import os
import subprocess
from dataclasses import dataclass
from typing import Generic, Iterator, TypeVar

from ..coverage.ledger import Ledger
from ..redact import rules as redact
from .budget import Budget
from .platform.base import Providers

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class Ok(Generic[T]):
    value: T

    ok: bool = True


@dataclass(frozen=True, slots=True)
class Refused:
    """Never an empty result that could equally mean 'nothing there' and
    'could not look'. The reason is recorded where it is still known."""

    reason: str
    detail: str = ""

    ok: bool = False


Result = Ok[T] | Refused


@dataclass(frozen=True, slots=True)
class Entry:
    path: str
    is_dir: bool
    is_symlink: bool
    size: int
    is_exec: bool = False


@dataclass(frozen=True, slots=True)
class Stat:
    path: str
    real_path: str
    inode: str
    size: int
    mode: int
    mtime: float
    owner: str


@dataclass(frozen=True, slots=True)
class Ran:
    argv: tuple[str, ...]
    code: int
    stdout: str


class Gate:
    """The only object in the package that touches the host."""

    def __init__(
        self,
        root: str = "/",
        *,
        ledger: Ledger | None = None,
        budget: Budget | None = None,
        providers: Providers | None = None,
        env: dict[str, str] | None = None,
        allow_subprocess: bool = True,
    ) -> None:
        self._root = os.path.realpath(root)
        self.ledger = ledger if ledger is not None else Ledger()
        self.budget = budget if budget is not None else Budget()
        self.env = dict(env) if env is not None else {}
        self.allow_subprocess = allow_subprocess
        from .platform.base import NullProviders

        self.providers = providers if providers is not None else NullProviders()
        #: Call counters, so a test can assert the evidence ladder stopped
        #: early rather than merely reaching the right answer expensively.
        self.calls: dict[str, int] = {"read_bytes": 0, "run": 0, "package_owner": 0}
        #: Test hook. Called with the resolved path immediately after
        #: validation and before open(), so a case can swap the target and
        #: prove the descriptor check catches it.
        self.on_validated = None

    # ---------------------------------------------------------------- paths

    @property
    def root(self) -> str:
        return self._root

    def host_path(self, logical: str) -> str:
        """Map a logical (machine) path into this world."""
        if self._root == "/":
            return logical
        return os.path.join(self._root, logical.lstrip("/\\"))

    def logical_path(self, host: str) -> str:
        """Inverse of `host_path`, so records read the same in a fixture and
        on a real machine."""
        if self._root == "/":
            return host
        if host == self._root:
            return "/"
        if host.startswith(self._root + os.sep):
            return "/" + host[len(self._root) + 1 :]
        return host

    def _validate(self, logical: str) -> Result[str]:
        """Canonicalize, then decide. Returns the resolved host path."""
        candidate = self.host_path(logical)
        try:
            resolved = os.path.realpath(candidate)
        except (OSError, ValueError) as exc:
            return Refused("unresolvable", str(exc))

        if self._root != "/" and not (
            resolved == self._root or resolved.startswith(self._root + os.sep)
        ):
            self.ledger.deny(logical, "outside_root")
            return Refused("outside_root", self.logical_path(resolved))

        if redact.is_personal(self.logical_path(resolved)):
            self.ledger.deny(logical, "personal_path")
            return Refused("personal_path", "")

        return Ok(resolved)

    # ---------------------------------------------------------------- reads

    def _open_verified(self, resolved: str) -> Result[int]:
        """Checking a path and opening it are two operations.

        The descriptor is compared against the validated target, so a swap
        between the two is a refusal rather than a read.
        """
        try:
            before = os.stat(resolved, follow_symlinks=False)
        except FileNotFoundError:
            return Refused("absent", resolved)
        except OSError as exc:
            return Refused("stat_failed", exc.strerror or str(exc))

        if self.on_validated is not None:
            self.on_validated(resolved)

        try:
            fd = os.open(resolved, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError as exc:
            # The target was already resolved, so it cannot legitimately be a
            # symlink by the time we open it. ELOOP here means the path was
            # replaced between the check and the open.
            if exc.errno == errno.ELOOP:
                return Refused("swapped", "target became a symlink after validation")
            return Refused("open_failed", exc.strerror or str(exc))

        after = os.fstat(fd)
        if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
            os.close(fd)
            return Refused("swapped", "descriptor did not match the validated target")
        return Ok(fd)

    def read_bytes(self, logical: str, limit: int | None = None) -> Result[bytes]:
        self.calls["read_bytes"] += 1
        validated = self._validate(logical)
        if not validated.ok:
            return validated
        resolved = validated.value
        ceiling = self.budget.max_read_bytes if limit is None else min(limit, self.budget.max_read_bytes)

        opened = self._open_verified(resolved)
        if not opened.ok:
            if opened.reason in ("open_failed", "stat_failed"):
                self.ledger.deny(logical, opened.detail or opened.reason)
            elif opened.reason == "swapped":
                self.ledger.deny(logical, "target swapped after validation")
            return opened
        fd = opened.value
        try:
            size = os.fstat(fd).st_size
            data = os.read(fd, ceiling)
        finally:
            os.close(fd)

        if size > ceiling:
            self.ledger.truncate(logical, len(data), size)
            return Ok(data)
        return Ok(data)

    def read_text(self, logical: str, limit: int | None = None) -> Result[str]:
        raw = self.read_bytes(logical, limit)
        if not raw.ok:
            return raw
        return Ok(raw.value.decode("utf-8", errors="replace"))

    def stat(self, logical: str) -> Result[Stat]:
        validated = self._validate(logical)
        if not validated.ok:
            return validated
        resolved = validated.value
        try:
            st = os.stat(resolved)
        except FileNotFoundError:
            return Refused("absent", logical)
        except OSError as exc:
            self.ledger.deny(logical, exc.strerror or str(exc))
            return Refused("stat_failed", exc.strerror or str(exc))
        return Ok(
            Stat(
                path=logical,
                real_path=self.logical_path(resolved),
                inode=f"{st.st_dev}:{st.st_ino}",
                size=st.st_size,
                mode=st.st_mode,
                mtime=st.st_mtime,
                owner=self.providers.owner_of(st.st_uid),
            )
        )

    def list_dir(self, logical: str) -> Result[tuple[Entry, ...]]:
        validated = self._validate(logical)
        if not validated.ok:
            return validated
        resolved = validated.value
        try:
            raw = sorted(os.scandir(resolved), key=lambda e: e.name)
        except FileNotFoundError:
            # Absent is not denied. A surface that does not exist was not
            # refused, and recording it here would drown the real refusals
            # and make `coverage.is_complete` meaningless.
            return Refused("absent", logical)
        except OSError as exc:
            self.ledger.deny(logical, exc.strerror or str(exc))
            return Refused("listdir_failed", exc.strerror or str(exc))

        entries: list[Entry] = []
        for e in raw:
            try:
                info = e.stat(follow_symlinks=False)
                entries.append(
                    Entry(
                        path=os.path.join(logical, e.name) if logical != "/" else "/" + e.name,
                        is_dir=e.is_dir(follow_symlinks=False),
                        is_symlink=e.is_symlink(),
                        size=info.st_size,
                        is_exec=bool(info.st_mode & 0o111) and not e.is_dir(follow_symlinks=False),
                    )
                )
            except OSError:
                continue
        return Ok(tuple(entries))

    def walk(self, logical_root: str, max_depth: int | None = None) -> Iterator[Entry]:
        """Breadth-first under the shared entry ceiling.

        Breadth-first on purpose: a budget exhausted late still covered the
        likely places, which is not true of a depth-first walk that spends
        everything in the first deep subtree it meets.
        """
        depth_cap = self.budget.max_depth if max_depth is None else max_depth
        frontier: list[tuple[str, int]] = [(logical_root, 0)]
        seen: set[str] = set()
        deepest = 0
        count = 0

        while frontier:
            path, depth = frontier.pop(0)
            if depth > depth_cap:
                self.ledger.boundary(path, "depth", f"cap {depth_cap}")
                continue
            if self.budget.time_exhausted:
                self.ledger.boundary(path, "time_exhausted", f"cap {self.budget.max_seconds}s")
                self.ledger.swept(logical_root, deepest, count)
                return
            listing = self.list_dir(path)
            if not listing.ok:
                continue
            deepest = max(deepest, depth)
            for entry in listing.value:
                if not self.budget.take_entries():
                    self.ledger.boundary(path, "budget_exhausted", f"cap {self.budget.max_entries}")
                    self.ledger.swept(logical_root, deepest, count)
                    return
                count += 1
                yield entry
                if entry.is_dir and not entry.is_symlink and entry.path not in seen:
                    seen.add(entry.path)
                    frontier.append((entry.path, depth + 1))

        self.ledger.swept(logical_root, deepest, count)

    # ------------------------------------------------------------ processes

    def processes(self):
        return self.providers.processes(self)

    def sockets(self):
        return self.providers.sockets(self)

    def packages(self):
        return self.providers.packages(self)

    def applications(self):
        return self.providers.applications(self)

    def dns_cache(self):
        return self.providers.dns_cache(self)

    def exec_journal(self):
        return self.providers.exec_journal(self)

    def package_owner(self, path: str):
        self.calls["package_owner"] += 1
        return self.providers.package_owner(self, path)

    # ----------------------------------------------------------- subprocess

    def run(self, argv: tuple[str, ...], timeout: float | None = None) -> Result[Ran]:
        """One sandboxed subprocess, under the budget's time ceiling.

        The executable is resolved through the world like every other path,
        so a caller passes the same logical path it would pass to a read.
        Without that, a fixture and a live machine are not interchangeable
        and every case has to know which one it is running against.

        Output is capped and a timeout is a recorded refusal, so partial
        output can never be mistaken for a version string.
        """
        self.calls["run"] += 1
        if not self.allow_subprocess:
            return Refused("subprocess_disabled", "")
        if not argv:
            return Refused("no_argv", "")
        if self.budget.time_exhausted:
            self.ledger.probe(argv[0], "failed", "scan time budget exhausted")
            return Refused("time_budget_exhausted", f"{self.budget.max_seconds}s")

        target = argv[0]
        if self._root != "/" and target.startswith("/"):
            validated = self._validate(target)
            if not validated.ok:
                return validated
            target = validated.value

        limit = self.budget.max_subprocess_seconds if timeout is None else timeout
        try:
            proc = subprocess.run(
                [target, *argv[1:]],
                capture_output=True,
                text=True,
                timeout=limit,
                env={"PATH": self.env.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"},
                check=False,
            )
        except subprocess.TimeoutExpired:
            self.ledger.probe(argv[0] if argv else "?", "failed", "timeout")
            return Refused("timeout", f"{limit}s")
        except (OSError, ValueError) as exc:
            self.ledger.probe(argv[0] if argv else "?", "failed", str(exc))
            return Refused("spawn_failed", str(exc))
        return Ok(Ran(tuple(argv), proc.returncode, proc.stdout[:8192]))
