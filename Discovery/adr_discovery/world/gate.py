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
import signal
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Generic, Iterator, TypeVar

from ..coverage.ledger import Ledger
from ..redact import rules as redact
from .budget import Budget
from .platform.base import Providers

T = TypeVar("T")
MAX_SUBPROCESS_OUTPUT = 8192
_HELPER_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"


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
    ) -> None:
        self._root = os.path.realpath(root)
        self.ledger = ledger if ledger is not None else Ledger()
        self.budget = budget if budget is not None else Budget()
        self.env = dict(env) if env is not None else {}
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

    def _open_verified(self, logical: str, resolved: str, flags: int = os.O_RDONLY) -> Result[int]:
        """Open a target, then prove the descriptor still names the validated path.

        Revalidating after open closes the ancestor-swap race: checking only
        the final component with ``O_NOFOLLOW`` is insufficient when an
        attacker controls a directory above it.
        """
        if self.on_validated is not None:
            self.on_validated(resolved)

        try:
            fd = os.open(resolved, flags | getattr(os, "O_NOFOLLOW", 0))
        except FileNotFoundError:
            return Refused("absent", resolved)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                return Refused("swapped", "target became a symlink after validation")
            return Refused("open_failed", exc.strerror or str(exc))

        current = self._validate(logical)
        try:
            descriptor = os.fstat(fd)
            path_stat = os.stat(resolved, follow_symlinks=False)
        except OSError as exc:
            os.close(fd)
            return Refused("swapped", exc.strerror or str(exc))
        if (
            not current.ok
            or current.value != resolved
            or (descriptor.st_dev, descriptor.st_ino) != (path_stat.st_dev, path_stat.st_ino)
        ):
            os.close(fd)
            return Refused("swapped", "descriptor did not match the revalidated target")
        return Ok(fd)

    def read_bytes(self, logical: str, limit: int | None = None) -> Result[bytes]:
        self.calls["read_bytes"] += 1
        validated = self._validate(logical)
        if not validated.ok:
            return validated
        resolved = validated.value
        ceiling = self.budget.max_read_bytes if limit is None else min(limit, self.budget.max_read_bytes)

        opened = self._open_verified(logical, resolved)
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
        current = self._validate(logical)
        if not current.ok or current.value != resolved:
            self.ledger.deny(logical, "target swapped after validation")
            return Refused("swapped", "path changed during stat")
        try:
            after = os.stat(resolved)
        except OSError as exc:
            return Refused("swapped", exc.strerror or str(exc))
        if (st.st_dev, st.st_ino) != (after.st_dev, after.st_ino):
            self.ledger.deny(logical, "target swapped after validation")
            return Refused("swapped", "path changed during stat")
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
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        opened = self._open_verified(logical, resolved, directory_flags)
        if not opened.ok:
            if opened.reason not in ("absent",):
                self.ledger.deny(logical, opened.detail or opened.reason)
            return opened

        fd = opened.value
        entries: list[Entry] = []
        exhausted = False
        try:
            with os.scandir(fd) as listing:
                for e in listing:
                    if not self.budget.take_entries():
                        exhausted = True
                        break
                    try:
                        info = e.stat(follow_symlinks=False)
                        is_dir = e.is_dir(follow_symlinks=False)
                        entries.append(
                            Entry(
                                path=os.path.join(logical, e.name) if logical != "/" else "/" + e.name,
                                is_dir=is_dir,
                                is_symlink=e.is_symlink(),
                                size=info.st_size,
                                is_exec=bool(info.st_mode & 0o111) and not is_dir,
                            )
                        )
                    except OSError:
                        continue
        except (OSError, TypeError) as exc:
            self.ledger.deny(logical, getattr(exc, "strerror", None) or str(exc))
            return Refused("listdir_failed", str(exc))
        finally:
            os.close(fd)

        if exhausted:
            self.ledger.boundary(
                logical, "budget_exhausted", f"cap {self.budget.max_entries}; directory truncated"
            )
        entries.sort(key=lambda entry: entry.path)
        return Ok(tuple(entries))

    def walk(self, logical_root: str, max_depth: int | None = None) -> Iterator[Entry]:
        """Breadth-first under the shared entry ceiling.

        Breadth-first on purpose: a budget exhausted late still covered the
        likely places, which is not true of a depth-first walk that spends
        everything in the first deep subtree it meets.
        """
        depth_cap = self.budget.max_depth if max_depth is None else max_depth
        frontier = deque([(logical_root, 0)])
        seen: set[str] = set()
        deepest = 0
        count = 0

        while frontier:
            path, depth = frontier.popleft()
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

    def run_helper(self, argv: tuple[str, ...], timeout: float | None = None) -> Result[Ran]:
        """Run one absolute-path OS inventory helper with bounded output.

        This API is deliberately unavailable to discovered candidates. It
        does not search ``PATH`` and drains output incrementally, so neither
        path precedence nor post-exit slicing can turn inventory into code
        execution or an unbounded allocation.
        """
        self.calls["run"] += 1
        if not argv:
            return Refused("no_argv", "")
        if not os.path.isabs(argv[0]):
            return Refused("helper_not_absolute", argv[0])
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
        env = {"PATH": _HELPER_PATH, "LC_ALL": "C", "LANG": "C"}
        if os.name == "nt":
            env.update({"SystemRoot": r"C:\Windows", "WINDIR": r"C:\Windows"})
        try:
            proc = subprocess.Popen(
                [target, *argv[1:]],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                start_new_session=os.name != "nt",
            )
        except (OSError, ValueError) as exc:
            self.ledger.probe(argv[0] if argv else "?", "failed", str(exc))
            return Refused("spawn_failed", str(exc))

        stdout = bytearray()
        total = [0]
        lock = threading.Lock()
        overflow = threading.Event()

        def drain(stream, keep: bool) -> None:
            while True:
                chunk = stream.read(4096)
                if not chunk:
                    return
                with lock:
                    total[0] += len(chunk)
                    if keep and len(stdout) < MAX_SUBPROCESS_OUTPUT:
                        remaining = MAX_SUBPROCESS_OUTPUT - len(stdout)
                        stdout.extend(chunk[:remaining])
                    if total[0] > MAX_SUBPROCESS_OUTPUT:
                        overflow.set()

        threads = [
            threading.Thread(target=drain, args=(proc.stdout, True), daemon=True),
            threading.Thread(target=drain, args=(proc.stderr, False), daemon=True),
        ]
        for thread in threads:
            thread.start()

        deadline = time.monotonic() + limit
        reason = None
        while proc.poll() is None:
            if overflow.wait(timeout=min(0.02, max(0.0, deadline - time.monotonic()))):
                reason = "output_limit"
                break
            if time.monotonic() >= deadline:
                reason = "timeout"
                break

        if reason is not None:
            self._terminate(proc)
        else:
            proc.wait()
        for stream in (proc.stdout, proc.stderr):
            stream.close()
        for thread in threads:
            thread.join(timeout=0.2)

        if reason is not None:
            detail = f"{MAX_SUBPROCESS_OUTPUT} bytes" if reason == "output_limit" else f"{limit}s"
            self.ledger.probe(argv[0], "failed", reason)
            return Refused(reason, detail)
        return Ok(Ran(tuple(argv), proc.returncode, stdout.decode("utf-8", "replace")))

    @staticmethod
    def _terminate(proc: subprocess.Popen) -> None:
        try:
            if os.name != "nt":
                os.killpg(proc.pid, signal.SIGKILL)
            else:
                proc.kill()
        except (OSError, ProcessLookupError):
            pass
        try:
            proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
