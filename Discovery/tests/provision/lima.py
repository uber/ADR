"""The Linux guest, driven through lima.

lima is what is actually installed on this host, so it is what the Linux phase
uses. The four verbs are the same four every driver implements; nothing above
this file knows that lima is in play.

``restore`` is the honest exception. This guest runs under vz, where
``limactl snapshot`` is unimplemented, so restore refuses loudly rather than
returning silently and letting a caller believe it got a clean machine.
"""

from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple

from .driver import DEFAULT_TIMEOUT, Result


class NoSnapshot(RuntimeError):
    """This guest cannot be returned to a known state."""


@dataclass
class LimaDriver:
    """Commands run inside a lima instance over ``limactl shell``."""

    instance: str = "adr-disco-linux"
    _home: Optional[str] = field(default=None, init=False, repr=False)
    commands: List[Tuple[str, ...]] = field(default_factory=list)

    @property
    def home(self) -> str:
        """The guest's home, cached; manifest paths are written relative to it."""
        if self._home is None:
            self._home = self.run(["sh", "-lc", "printf %s \"$HOME\""]).stdout.strip() or "~"
        return self._home

    def restore(self) -> None:
        raise NoSnapshot(
            f"{self.instance} runs under vz, where limactl snapshot is unimplemented; "
            "a run against it mutates the guest permanently"
        )

    def run(self, argv: Sequence[str], *, timeout: int = DEFAULT_TIMEOUT) -> Result:
        argv = tuple(str(a) for a in argv)
        self.commands.append(argv)
        completed = subprocess.run(
            ["limactl", "shell", "--workdir", "/", self.instance, *argv],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
        return Result(argv, completed.returncode, completed.stdout, completed.stderr)

    def sh(self, script: str, *, timeout: int = DEFAULT_TIMEOUT) -> Result:
        """A convenience for the many recipes that are really one shell line."""
        return self.run(["sh", "-lc", script], timeout=timeout)

    def push(self, local: str, remote: str) -> None:
        subprocess.run(["limactl", "copy", local, f"{self.instance}:{remote}"], check=True)

    def pull(self, remote: str, local: str) -> None:
        subprocess.run(["limactl", "copy", f"{self.instance}:{remote}", local], check=True)

    def expand(self, path: str) -> str:
        """``~`` means the guest's home, not this Mac's."""
        if path.startswith("~/"):
            return self.home.rstrip("/") + path[1:]
        return path

    def write(self, path: str, body: str) -> Result:
        """Create a file in the guest, parents and all."""
        target = self.expand(path)
        quoted = shlex.quote(target)
        return self.sh(
            f"mkdir -p \"$(dirname {quoted})\" && cat > {quoted} <<'ADR_HARNESS_EOF'\n{body}\nADR_HARNESS_EOF"
        )

    def exists(self, path: str) -> bool:
        return self.sh(f"test -e {shlex.quote(self.expand(path))}").ok


__all__ = ["LimaDriver", "NoSnapshot"]
