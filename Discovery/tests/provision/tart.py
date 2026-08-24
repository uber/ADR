"""The macOS guest, driven through tart over SSH.

macOS guests must run on Apple hardware, so this driver only ever works on an
Apple-silicon host. SSH rather than anything Mac-specific, so the guest is
driven with the same verbs, the same quoting and the same recipe code as the
Linux one.
"""

from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple

from .driver import DEFAULT_TIMEOUT, Result

SSH_OPTIONS = (
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "BatchMode=yes",
    "-o", "ConnectTimeout=10",
    "-o", "LogLevel=ERROR",
)


class NoSnapshot(RuntimeError):
    """This guest cannot be returned to a known state."""


@dataclass
class TartDriver:
    """Commands run inside a tart VM over SSH."""

    vm: str = "adr-macos"
    user: str = "admin"
    _ip: Optional[str] = field(default=None, init=False, repr=False)
    _home: Optional[str] = field(default=None, init=False, repr=False)
    commands: List[Tuple[str, ...]] = field(default_factory=list)

    @property
    def ip(self) -> str:
        if self._ip is None:
            found = subprocess.run(["tart", "ip", self.vm], capture_output=True,
                                   text=True, check=True)
            self._ip = found.stdout.strip()
        return self._ip

    @property
    def home(self) -> str:
        if self._home is None:
            self._home = self.sh('printf %s "$HOME"').stdout.strip() or f"/Users/{self.user}"
        return self._home

    def restore(self) -> None:
        """`tart clone` from a golden VM is the restore path, and it is not wired up.

        Refused rather than silently skipped: a caller that believes it has a
        clean machine and does not will report the previous run's leftovers as
        this run's findings.
        """
        raise NoSnapshot(
            f"no golden clone configured for {self.vm}; restore would leave the "
            "guest carrying whatever the last run installed"
        )

    def run(self, argv: Sequence[str], *, timeout: int = DEFAULT_TIMEOUT) -> Result:
        argv = tuple(str(a) for a in argv)
        self.commands.append(argv)
        remote = " ".join(shlex.quote(a) for a in argv)
        completed = subprocess.run(
            ["ssh", *SSH_OPTIONS, f"{self.user}@{self.ip}", remote],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
        return Result(argv, completed.returncode, completed.stdout, completed.stderr)

    #: A login shell here picks up neither Homebrew nor pipx's bin directory, so
    #: tools installed with either are invisible to every command the harness
    #: runs - and would be reported missing when they are sitting right there.
    #: A real user's shell has both, so the harness gives itself the same one.
    PRELUDE = ('if [ -x /opt/homebrew/bin/brew ]; then eval "$(/opt/homebrew/bin/brew shellenv)"; fi; '
               'PATH="$HOME/.local/bin:$PATH"; export PATH; ')

    def sh(self, script: str, *, timeout: int = DEFAULT_TIMEOUT) -> Result:
        return self.run(["/bin/sh", "-lc", self.PRELUDE + script], timeout=timeout)

    def push(self, local: str, remote: str) -> None:
        subprocess.run(["scp", *SSH_OPTIONS, local, f"{self.user}@{self.ip}:{remote}"], check=True)

    def pull(self, remote: str, local: str) -> None:
        subprocess.run(["scp", *SSH_OPTIONS, f"{self.user}@{self.ip}:{remote}", local], check=True)

    def expand(self, path: str) -> str:
        if path.startswith("~/"):
            return self.home.rstrip("/") + path[1:]
        return path

    def write(self, path: str, body: str) -> Result:
        target = shlex.quote(self.expand(path))
        return self.sh(
            f"mkdir -p \"$(dirname {target})\" && cat > {target} <<'ADR_HARNESS_EOF'\n{body}\nADR_HARNESS_EOF"
        )

    def exists(self, path: str) -> bool:
        return self.sh(f"test -e {shlex.quote(self.expand(path))}").ok


__all__ = ["NoSnapshot", "SSH_OPTIONS", "TartDriver"]
