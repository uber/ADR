"""macOS guests, via tart on Apple silicon.

macOS guests must run on Apple hardware and Apple's licence limits how many a
host may run - a hardware and policy question rather than an engineering one,
and the reason macOS is a later phase than Linux despite having the richest
manifest.

Restore is ``tart clone`` from a golden VM, which is why the golden VM must
already carry the authenticated sessions AG-08..AG-11 need: those sign-ins
cannot be scripted, so they are made by hand once and inherited by every run.
"""

import json
import subprocess
import time
from typing import Optional

from .driver import SSHDriver


class TartDriver(SSHDriver):
    def __init__(self, golden: str, working: str = "adr-disco-mac-run",
                 user: str = "admin", identity: Optional[str] = None,
                 boot_timeout: int = 300, home: Optional[str] = None):
        super().__init__(host="", user=user, identity=identity, platform="mac", image=golden)
        self.golden = golden
        self.working = working
        self.boot_timeout = boot_timeout
        self._home = home

    def ensure_running(self) -> str:
        """Attach to a guest that is already up, without discarding it.

        Separate from `restore` for the same reason as on Linux: building an
        image and measuring a collector are different jobs, and only the second
        needs the machine pristine. Bootstrapping a macOS guest costs tens of
        gigabytes, so throwing one away to check that an installer works would
        be an expensive way to learn nothing.
        """
        if self._state(self.working) != "running":
            subprocess.Popen(["tart", "run", "--no-graphics", self.working],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.host = self._wait_for_ip()
        return self.host

    def _state(self, name: str) -> str:
        completed = subprocess.run(["tart", "list", "--format", "json"],
                                   capture_output=True, text=True)
        if completed.returncode:
            return ""
        for row in json.loads(completed.stdout or "[]"):
            if row.get("Name") == name:
                return str(row.get("State", "")).lower()
        return ""

    def home(self) -> str:
        if self._home is None:
            self._home = self.run(["sh", "-c", "echo $HOME"]).text() or "/Users/admin"
        return self._home

    def restore(self) -> None:
        self._tart("stop", self.working, allow_failure=True)
        self._tart("delete", self.working, allow_failure=True)
        self._tart("clone", self.golden, self.working)
        subprocess.Popen(["tart", "run", "--no-graphics", self.working],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.host = self._wait_for_ip()

    def _wait_for_ip(self) -> str:
        deadline = time.time() + self.boot_timeout
        while time.time() < deadline:
            completed = subprocess.run(["tart", "ip", self.working], capture_output=True, text=True)
            if completed.returncode == 0 and completed.stdout.strip():
                return completed.stdout.strip()
            time.sleep(3)
        raise RuntimeError("guest did not report an address within %ds" % self.boot_timeout)

    def _tart(self, *args: str, allow_failure: bool = False) -> None:
        completed = subprocess.run(["tart"] + list(args), capture_output=True, text=True)
        if completed.returncode and not allow_failure:
            raise RuntimeError("tart %s failed: %s" % (" ".join(args), completed.stderr))
