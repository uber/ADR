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
import hashlib
import os
import signal
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass
from stat import S_ISDIR, S_ISLNK, S_ISREG
from typing import Callable, Generic, Iterator, Protocol, TypeVar

from ..contracts.text import decode_text
from ..coverage.ledger import Ledger
from ..redact import rules as redact
from .budget import Budget
from .platform.base import Providers

T = TypeVar("T")
#: First line of a valid CACHEDIR.TAG (https://bford.info/cachedir/).
_CACHEDIR_SIGNATURE = b"Signature: 8a477f597d28d172789f06886806bc55"
_MAX_RETAINED = 5000
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
class Tree:
    """What one complete pass over a directory tree covered."""

    files: int
    bytes: int


@dataclass(frozen=True, slots=True)
class TreeDigest:
    sha256: str
    files: int
    bytes: int


class TreeSink(Protocol):
    """Receives a tree's regular files in folder-hash order."""

    def begin(self, rel: bytes, mode: int) -> None: ...

    def update(self, chunk: bytes) -> None: ...


class FolderHash:
    """The folder hash: per file, ``<rel>\n<x>\n`` then the raw bytes, all
    into one running sha256. ``x`` is 1 when any execute bit is set."""

    def __init__(self) -> None:
        self.digest = hashlib.sha256()

    def begin(self, rel: bytes, mode: int) -> None:
        self.digest.update(rel + (b"\n1\n" if mode & 0o111 else b"\n0\n"))

    def update(self, chunk: bytes) -> None:
        self.digest.update(chunk)


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
        resolve_names: bool = False,
    ) -> None:
        self._root = os.path.realpath(root)
        self.ledger = ledger if ledger is not None else Ledger()
        self.budget = budget if budget is not None else Budget()
        self.env = dict(env) if env is not None else {}
        #: Whether provider hostnames may be looked up through the host's
        #: resolver. Off by default: a scan sends nothing over the network
        #: unless the operator asks for it.
        self.resolve_names = resolve_names
        from .platform.base import NullProviders

        self.providers = providers if providers is not None else NullProviders()
        #: Call counters, so a test can assert the evidence ladder stopped
        #: early rather than merely reaching the right answer expensively.
        self.calls: dict[str, int] = {"read_bytes": 0, "run": 0, "package_owner": 0}
        #: Test hook. Called with the resolved path immediately after
        #: validation and before open(), so a case can swap the target and
        #: prove the descriptor check catches it.
        self.on_validated = None
        #: Complete listings of directories a walk marked worth keeping, so a
        #: later stage reading the same surface directory is not charged
        #: twice. Only validated, untruncated listings are stored, and the
        #: number kept is bounded.
        self._retained: dict[str, tuple[Entry, ...]] = {}

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

    def _validate(self, logical: str, *, profile: bool = False) -> Result[str]:
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

        if profile:
            allowed = self._profile_path(logical, candidate, resolved)
            if not allowed.ok:
                return allowed
        elif redact.is_personal(self.logical_path(resolved)):
            self.ledger.deny(logical, "personal_path")
            return Refused("personal_path", "")

        return Ok(resolved)

    def _profile_path(self, logical: str, candidate: str, resolved: str) -> Result[str]:
        """A file-only exception for provider-enumerated PowerShell profiles.

        Never used by normal reads, walks or listings. Both the spelling and
        the resolved target must be the exact same allowlisted regular file;
        every ancestor is checked for links/reparse points on each validation.
        """
        paths = getattr(self.providers, "powershell_profile_paths", None)
        allowed = paths(self) if callable(paths) else ()

        def key(value):
            return os.path.normcase(os.path.abspath(value))

        normalized = logical.replace("\\", "/").casefold().split("/")
        probe = "/".join(normalized) + "/"
        if any(segment.casefold() in probe for segment in redact.PERSONAL_PATH_SEGMENTS
               if segment.casefold() != "/documents/"):
            self.ledger.deny(logical, "personal_path")
            return Refused("personal_path")
        known_name = (len(normalized) >= 2
                      and normalized[-2] in {"powershell", "windowspowershell"}
                      and normalized[-1] in {"profile.ps1", "microsoft.powershell_profile.ps1"})
        if not known_name or key(candidate) not in {key(self.host_path(path)) for path in allowed}:
            self.ledger.deny(logical, "not_a_known_profile")
            return Refused("not_a_known_profile")
        if key(candidate) != key(resolved):
            self.ledger.deny(logical, "profile_redirect")
            return Refused("profile_redirect")
        current = os.path.abspath(candidate)
        first = True
        while True:
            try:
                info = os.lstat(current)
            except FileNotFoundError:
                return Refused("absent", logical)
            except OSError as exc:
                self.ledger.deny(logical, "profile_stat_failed")
                return Refused("profile_stat_failed", exc.strerror or "stat failed")
            if S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                self.ledger.deny(logical, "profile_redirect")
                return Refused("profile_redirect")
            if first and (not S_ISREG(info.st_mode) or info.st_nlink != 1):
                self.ledger.deny(logical, "profile_not_regular")
                return Refused("profile_not_regular")
            parent = os.path.dirname(current)
            if parent == current:
                break
            current, first = parent, False
        return Ok(resolved)

    # ---------------------------------------------------------------- reads

    def _open_verified(self, logical: str, resolved: str, flags: int = os.O_RDONLY,
                       *, profile: bool = False) -> Result[int]:
        """Open a target, then prove the descriptor still names the validated path.

        Revalidating after open closes the ancestor-swap race: checking only
        the final component with ``O_NOFOLLOW`` is insufficient when an
        attacker controls a directory above it.
        """
        before = None
        if profile:
            try:
                before = os.lstat(resolved)
            except OSError:
                return Refused("swapped", "profile changed before open")
        if self.on_validated is not None:
            self.on_validated(resolved)

        try:
            fd = os.open(resolved, flags | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
        except FileNotFoundError:
            return Refused("absent", resolved)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                return Refused("swapped", "target became a symlink after validation")
            return Refused("open_failed", exc.strerror or str(exc))

        current = self._validate(logical, profile=profile)
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
            or before is not None and (before.st_dev, before.st_ino) != (descriptor.st_dev, descriptor.st_ino)
        ):
            os.close(fd)
            return Refused("swapped", "descriptor did not match the revalidated target")
        return Ok(fd)

    def read_bytes(self, logical: str, limit: int | None = None) -> Result[bytes]:
        return self._read_bytes(logical, limit)

    def _read_bytes(self, logical: str, limit: int | None = None, *, profile: bool = False) -> Result[bytes]:
        self.calls["read_bytes"] += 1
        validated = self._validate(logical, profile=profile)
        if not validated.ok:
            return validated
        resolved = validated.value
        ceiling = self.budget.max_read_bytes if limit is None else min(limit, self.budget.max_read_bytes)

        opened = self._open_verified(logical, resolved, profile=profile)
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
        return self._decode(logical, raw, allow_utf16=logical.casefold().endswith((".json", ".jsonc")))

    def read_profile(self, logical: str) -> Result[str]:
        """Read one exact, known PowerShell profile without opening Documents."""
        raw = self._read_bytes(logical, 256 * 1024, profile=True)
        return self._decode(logical, raw, allow_utf16=True)

    def _decode(self, logical: str, raw: Result[bytes], *, allow_utf16: bool) -> Result[str]:
        if not raw.ok:
            return raw
        try:
            return Ok(decode_text(raw.value, allow_utf16=allow_utf16))
        except ValueError as exc:
            self.ledger.probe("text_decode", "degraded", f"{logical}: {exc}")
            return Refused("invalid_encoding", str(exc))

    def stat(self, logical: str) -> Result[Stat]:
        return self._stat(logical)

    def stat_profile(self, logical: str) -> Result[Stat]:
        return self._stat(logical, profile=True)

    def _stat(self, logical: str, *, profile: bool = False) -> Result[Stat]:
        validated = self._validate(logical, profile=profile)
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
        current = self._validate(logical, profile=profile)
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

    def list_dir(self, logical: str, retain: bool = False) -> Result[tuple[Entry, ...]]:
        kept = self._retained.get(logical)
        if kept is not None:
            return Ok(kept)
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
                logical, "budget_exhausted", f"cap {self.budget.entry_cap}; directory truncated"
            )
        entries.sort(key=lambda entry: entry.path)
        if retain and not exhausted and len(self._retained) < _MAX_RETAINED:
            self._retained[logical] = tuple(entries)
        return Ok(tuple(entries))

    def walk(
        self,
        logical_root: str,
        max_depth: int | None = None,
        descend: Callable[[str], bool] | None = None,
        seen: set[str] | None = None,
        retain: Callable[[str], bool] | None = None,
    ) -> Iterator[Entry]:
        """Breadth-first under the shared entry ceiling.

        `descend` is asked before a directory joins the frontier, so a tree
        the caller does not want is never listed and never charged. The
        directory's own entry is still yielded: the caller filters results,
        this decides cost. Routine skips leave no ledger record -- a
        dependency cache is policy, not a gap in what was seen.

        `seen` holds directories already listed. Pass one set to several
        walks and a directory reachable from more than one root (`/home` and
        `/home/alice`, a code root inside a home) is listed, and charged,
        once; the later walk steps over it and still yields the entry.

        `retain` marks directories whose listing later stages will want
        again; those listings are kept and re-served without a charge.

        Breadth-first on purpose: a budget exhausted late still covered the
        likely places, which is not true of a depth-first walk that spends
        everything in the first deep subtree it meets. Breadth is also taken
        across the root's children, not only by depth: see the queues below.
        """
        depth_cap = self.budget.max_depth if max_depth is None else max_depth
        listed = set() if seen is None else seen
        queued: set[str] = set()
        deepest = 0
        count = 0
        if logical_root in listed:
            self.ledger.swept(logical_root, 0, 0)
            return

        # Fair share: one queue per top-level child of the root, served one
        # directory per turn. A single enormous subtree can then spend only
        # its own turns, and its siblings keep descending to the depth cap.
        # Within a queue the order is still breadth-first, and listings are
        # sorted, so the visit order is the same on every run.
        queues: list[deque[tuple[str, int]]] = [deque([(logical_root, 0)])]

        while queues:
            for queue in tuple(queues):
                if not queue:
                    continue
                path, depth = queue.popleft()
                if depth > depth_cap:
                    self.ledger.boundary(path, "depth", f"cap {depth_cap}")
                    continue
                if self.budget.time_exhausted:
                    self.ledger.boundary(path, "time_exhausted", f"cap {self.budget.max_seconds}s")
                    self.ledger.swept(logical_root, deepest, count)
                    return
                listing = self.list_dir(path, retain=retain is not None and retain(path))
                if not listing.ok:
                    continue
                # Marked when listed, not when queued: a directory a capped
                # walk never reached must stay available to the next walk.
                listed.add(path)
                deepest = max(deepest, depth)
                prune = self._prune_reason(path, listing.value)
                for entry in listing.value:
                    count += 1
                    yield entry
                    if prune:
                        continue
                    if (
                        entry.is_dir
                        and not entry.is_symlink
                        and entry.path not in listed
                        and entry.path not in queued
                    ):
                        if descend is not None and not descend(entry.path):
                            continue
                        queued.add(entry.path)
                        if depth == 0:
                            queues.append(deque([(entry.path, 1)]))
                        else:
                            queue.append((entry.path, depth + 1))
            queues = [q for q in queues if q]

        self.ledger.swept(logical_root, deepest, count)

    def _prune_reason(self, path: str, entries: tuple[Entry, ...]) -> str | None:
        """Why this directory's subtrees should not be walked, recorded.

        Both tests use only the listing already paid for, and name no tool:
        a tagged cache and a directory with a runaway fan-out look the same
        whoever made them.
        """
        for entry in entries:
            if entry.path.endswith("/CACHEDIR.TAG") and not entry.is_dir:
                tag = self.read_bytes(entry.path, limit=len(_CACHEDIR_SIGNATURE))
                if tag.ok and tag.value == _CACHEDIR_SIGNATURE:
                    self.ledger.boundary(path, "cache_dir", "CACHEDIR.TAG; subtrees not walked")
                    return "cache_dir"
                break
        if len(entries) > self.budget.max_children:
            self.ledger.boundary(
                path, "fan_out",
                f"{len(entries)} children; cap {self.budget.max_children}; subtrees not walked",
            )
            return "fan_out"
        return None

    # ---------------------------------------------------------------- trees

    def hash_tree(self, logical_root: str) -> Result[TreeDigest]:
        """The folder hash of a directory, or a recorded reason there is none.

        Every regular file under the root, symlinks never followed, sorted by
        its ``/``-separated relative path byte-wise, folded into one running
        sha256 as ``<rel>\\n<x>\\n`` then its bytes (``x`` is 1 when any
        execute bit is set). Equal trees hash equal wherever they sit.
        """
        sink = FolderHash()
        read = self.read_tree(logical_root, sink)
        if not read.ok:
            return read
        return Ok(TreeDigest(sink.digest.hexdigest(), read.value.files, read.value.bytes))

    def read_tree(self, logical_root: str, sink: TreeSink) -> Result[Tree]:
        """Feed every regular file under a directory to `sink`, in order.

        All or nothing: a tree over a cap, or with any file that cannot be
        listed or read, is refused and recorded, and whatever `sink` was
        given must be discarded. A partial hash would name a tree that does
        not exist. Bytes are charged to the hashing budget, not the entry
        ceiling, and are claimed for the whole tree before the first read.
        """
        validated = self._validate(logical_root)
        if not validated.ok:
            return validated
        resolved = validated.value
        listed = self._tree_members(logical_root, resolved)
        if not listed.ok:
            return listed
        members = listed.value
        declared = sum(size for _, _, size in members)
        if declared > self.budget.max_tree_bytes:
            return self._tree_refused(
                logical_root, "tree_too_large", f"{declared} bytes; cap {self.budget.max_tree_bytes}"
            )
        if not self.budget.take_hash_bytes(declared):
            return self._tree_refused(
                logical_root, "hash_budget_exhausted", f"cap {self.budget.max_hash_bytes} bytes"
            )

        total = 0
        for key, rel, _ in members:
            logical = self.logical_path(os.path.join(resolved, *rel.split("/")))
            fed = self._feed_file(logical, key, sink)
            if not fed.ok:
                return self._tree_refused(logical_root, "unreadable_member", f"{rel}: {fed.reason}")
            total += fed.value
            if total > self.budget.max_tree_bytes:
                return self._tree_refused(
                    logical_root, "tree_too_large", f"grew past {self.budget.max_tree_bytes} bytes"
                )
        return Ok(Tree(len(members), total))

    def _tree_members(self, logical_root: str, resolved: str) -> Result[list[tuple[bytes, str, int]]]:
        """(sort key, relative path, size) for each regular file, sorted.

        Not charged to the entry ceiling, which the sweep may already have
        spent: a truncated listing would become a partial hash. The per-tree
        file cap bounds it instead. Each file is still opened through the
        validated, descriptor-checked path before a byte is read.
        """
        members: list[tuple[bytes, str, int]] = []
        pending = [""]
        while pending:
            rel_dir = pending.pop()
            try:
                with os.scandir(os.path.join(resolved, *rel_dir.split("/")) if rel_dir else resolved) as listing:
                    entries = list(listing)
            except OSError as exc:
                return self._tree_refused(
                    logical_root, "unlistable", f"{rel_dir or '.'}: {exc.strerror or exc}"
                )
            for entry in entries:
                rel = f"{rel_dir}/{entry.name}" if rel_dir else entry.name
                try:
                    info = entry.stat(follow_symlinks=False)
                except OSError:
                    return self._tree_refused(logical_root, "unlistable", rel)
                if S_ISDIR(info.st_mode):
                    pending.append(rel)
                elif S_ISREG(info.st_mode):
                    if info.st_size > self.budget.max_tree_file_bytes:
                        return self._tree_refused(
                            logical_root, "file_too_large",
                            f"{rel}: {info.st_size} bytes; cap {self.budget.max_tree_file_bytes}",
                        )
                    members.append((os.fsencode(rel), rel, info.st_size))
                    if len(members) > self.budget.max_tree_files:
                        return self._tree_refused(
                            logical_root, "too_many_files", f"cap {self.budget.max_tree_files}"
                        )
        members.sort()
        return Ok(members)

    def _feed_file(self, logical: str, key: bytes, sink: TreeSink) -> Result[int]:
        validated = self._validate(logical)
        if not validated.ok:
            return validated
        opened = self._open_verified(logical, validated.value)
        if not opened.ok:
            return opened
        fd = opened.value
        size = 0
        try:
            mode = os.fstat(fd).st_mode
            if not S_ISREG(mode):
                return Refused("not_regular", logical)
            sink.begin(key, mode)
            while chunk := os.read(fd, 1 << 20):
                size += len(chunk)
                if size > self.budget.max_tree_file_bytes:
                    return Refused("file_too_large", logical)
                sink.update(chunk)
        except OSError as exc:
            return Refused("read_failed", exc.strerror or str(exc))
        finally:
            os.close(fd)
        return Ok(size)

    def _tree_refused(self, logical_root: str, reason: str, detail: str) -> Refused:
        self.ledger.boundary(logical_root, "no_folder_hash", f"{reason}: {detail}")
        return Refused(reason, detail)

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

    def resolve(self, hostnames: tuple[str, ...]):
        if not self.resolve_names:
            self.ledger.unavailable("resolver", "name resolution not requested (--resolve)")
            return Refused("unavailable", "name resolution not requested")
        return self.providers.resolve(self, hostnames)

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
        output_limit = self.budget.max_subprocess_output_bytes
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
                    if keep and len(stdout) < output_limit:
                        remaining = output_limit - len(stdout)
                        stdout.extend(chunk[:remaining])
                    if total[0] > output_limit:
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
            detail = f"{output_limit} bytes" if reason == "output_limit" else f"{limit}s"
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
