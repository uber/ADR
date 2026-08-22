"""Linux guests on an Apple-silicon host, via lima.

The plan assumes QEMU/KVM, which is right for a Linux build host and wrong for
the Mac most of this work gets done on: KVM does not exist there, and an x86
guest would be emulated rather than virtualized. Lima drives Apple's own
Virtualization framework, so an aarch64 Ubuntu guest runs at native speed.

Same four verbs as every other driver, so nothing above this file knows the
difference - which is the property the driver interface exists to buy.
"""

import os
import subprocess
from typing import List, Optional, Sequence

from .driver import Driver, Result


class LimaDriver(Driver):
    platform = "linux"

    def __init__(self, instance: str = "adr-disco-linux", template: str = "template://ubuntu-24.04",
                 cpus: int = 4, memory: int = 6, disk: int = 40, home: Optional[str] = None):
        self.instance = instance
        self.template = template
        self.cpus, self.memory, self.disk = cpus, memory, disk
        self.image = "lima:%s" % instance
        self._home = home

    # -- lifecycle -----------------------------------------------------

    def restore(self) -> None:
        """Back to a clean guest.

        Lima has no snapshot of its own, so "restore" is delete-and-recreate.
        Slower than a qcow2 overlay, and honest about it: the guarantee the
        method depends on is that a run starts from a machine with no AI tooling
        on it, and a fresh instance provides that guarantee unconditionally.
        """
        self._lima("stop", "-f", self.instance, allow_failure=True)
        self._lima("delete", "-f", self.instance, allow_failure=True)
        self._lima("create", "--name=" + self.instance, "--tty=false",
                   "--cpus=%d" % self.cpus, "--memory=%d" % self.memory,
                   "--disk=%d" % self.disk, self.template)
        self._lima("start", self.instance)

    def ensure_running(self) -> None:
        """Start an existing instance without discarding it.

        Separate from `restore` on purpose: bootstrapping an image and measuring
        a collector are different jobs, and only the second one requires the
        machine to be pristine.
        """
        if self.status() != "Running":
            self._lima("start", self.instance)

    def status(self) -> str:
        completed = subprocess.run(["limactl", "list", self.instance, "--format", "{{.Status}}"],
                                   capture_output=True, text=True)
        return completed.stdout.strip()

    # -- the four verbs ------------------------------------------------

    def run(self, argv: Sequence[str], timeout: int = 600, check: bool = False) -> Result:
        completed = subprocess.run(
            ["limactl", "shell", "--workdir", "/", self.instance] + [str(item) for item in argv],
            capture_output=True, text=True, timeout=timeout)
        result = Result(argv, completed.returncode, completed.stdout, completed.stderr)
        if check and not result.ok:
            raise RuntimeError("guest command failed: %s\n%s" % (" ".join(argv), result.stderr))
        return result

    def push(self, local: str, remote: str) -> None:
        self._lima("copy", local, "%s:%s" % (self.instance, remote))

    def pull(self, remote: str, local: str) -> None:
        self._lima("copy", "%s:%s" % (self.instance, remote), local)

    def write(self, remote: str, content: str, privileged: bool = False) -> None:
        """Write generated content without a shell in the path.

        `limactl copy` refuses a destination whose directory does not exist, so
        the directory is created first - which is also what a recipe writing a
        config site into a fresh guest needs. It also copies as the login user,
        which is why a privileged destination goes through the staged path in
        the base class rather than straight to /etc.
        """
        if not privileged:
            self.mkdir(os.path.dirname(remote), check=True)
        super().write(remote, content, privileged=privileged)

    def home(self) -> str:
        if self._home is None:
            self._home = self.run(["sh", "-c", "echo $HOME"]).text() or "/root"
        return self._home

    # -- plumbing ------------------------------------------------------

    def _lima(self, *args: str, allow_failure: bool = False) -> None:
        completed = subprocess.run(["limactl"] + list(args), capture_output=True, text=True)
        if completed.returncode and not allow_failure:
            raise RuntimeError("limactl %s failed: %s" % (" ".join(args), completed.stderr[-500:]))
