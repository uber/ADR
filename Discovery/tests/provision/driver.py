"""The guest interface, and the driver that needs no guest.

One interface, three hypervisors. Keeping the Linux phase behind this contract
is what stops it hard-coding assumptions that macOS and Windows later have to
unpick - and the dry driver is what lets the runner be tested at all before
any image exists.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Protocol, Sequence, Tuple

DEFAULT_TIMEOUT = 600


@dataclass(frozen=True)
class Result:
    argv: Tuple[str, ...]
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    @property
    def command(self) -> str:
        return " ".join(shlex.quote(a) for a in self.argv)


class Driver(Protocol):
    """Restore, run, push, pull. Deliberately four verbs and no more."""

    def restore(self) -> None:
        """Back to the golden snapshot."""

    def run(self, argv: Sequence[str], *, timeout: int = DEFAULT_TIMEOUT) -> Result:
        """Execute in the guest."""

    def push(self, local: str, remote: str) -> None:
        """Host to guest."""

    def pull(self, remote: str, local: str) -> None:
        """Guest to host."""


@dataclass
class DryDriver:
    """Records what would have happened, and runs nothing.

    Every command is recorded in order so the runner's dependency ordering can
    be asserted directly - which is the property most worth testing and the
    one a real guest makes slowest to check.
    """

    name: str = "dry"
    restores: int = 0
    commands: List[Tuple[str, ...]] = field(default_factory=list)
    pushed: List[Tuple[str, str]] = field(default_factory=list)
    pulled: List[Tuple[str, str]] = field(default_factory=list)
    failures: Dict[str, int] = field(default_factory=dict)
    outputs: Dict[str, str] = field(default_factory=dict)
    files: Dict[str, str] = field(default_factory=dict)

    def restore(self) -> None:
        self.restores += 1
        self.commands.clear()

    def run(self, argv: Sequence[str], *, timeout: int = DEFAULT_TIMEOUT) -> Result:
        argv = tuple(str(a) for a in argv)
        self.commands.append(argv)
        joined = " ".join(argv)
        for needle, code in self.failures.items():
            if needle in joined:
                return Result(argv, returncode=code, stderr=f"dry failure for {needle!r}")
        return Result(argv, returncode=0, stdout=self.outputs.get(joined, ""))

    def push(self, local: str, remote: str) -> None:
        self.pushed.append((local, remote))

    def pull(self, remote: str, local: str) -> None:
        self.pulled.append((remote, local))

    #: A dry guest still has a home, because paths are written relative to one.
    home: str = "/home/dry"

    def sh(self, script: str, *, timeout: int = DEFAULT_TIMEOUT) -> Result:
        return self.run(["sh", "-lc", script], timeout=timeout)

    def expand(self, path: str) -> str:
        return self.home.rstrip("/") + path[1:] if path.startswith("~/") else path

    def write(self, path: str, body: str) -> Result:
        self.files[self.expand(path)] = body
        return self.run(["write", self.expand(path)])

    def exists(self, path: str) -> bool:
        return self.expand(path) in self.files

    def ran(self, needle: str) -> bool:
        return any(needle in " ".join(argv) for argv in self.commands)

    def index_of(self, needle: str) -> Optional[int]:
        for position, argv in enumerate(self.commands):
            if needle in " ".join(argv):
                return position
        return None


__all__ = ["DEFAULT_TIMEOUT", "Driver", "DryDriver", "Result"]
