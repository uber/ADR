"""The transport contract, and a driver that executes nothing.

``restore``/``run``/``push``/``pull`` is the whole interface. Everything the
harness does to a guest is one of those four verbs, so a new hypervisor is a
new file rather than a change to the runner.
"""

import os
import shlex
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence


@dataclass
class Result:
    """What running a command in the guest produced."""

    argv: Sequence[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def text(self) -> str:
        return (self.stdout or "").strip()


class Driver:
    """One guest, four verbs.

    Subclasses implement ``restore`` and ``run``; ``push``/``pull`` default to
    an SSH-shaped implementation because all three guests speak SSH. Windows 11
    ships an optional OpenSSH Server, and enabling it in the golden image means
    one transport, one ``run`` and one set of quoting rules across every guest
    instead of a WinRM special case only one person understands.
    """

    #: Set by subclasses. Reported into score.json so a scoring shift can be
    #: attributed to the image rather than to the collector.
    image: str = ""
    platform: str = "linux"

    def restore(self) -> None:
        raise NotImplementedError

    def run(self, argv: Sequence[str], timeout: int = 600, check: bool = False) -> Result:
        raise NotImplementedError

    def push(self, local: str, remote: str) -> None:
        raise NotImplementedError

    def pull(self, remote: str, local: str) -> None:
        raise NotImplementedError

    # -- conveniences every recipe needs ------------------------------

    def shell(self, command: str, timeout: int = 600) -> Result:
        """Run a command through the guest's shell.

        Recipes that need a pipe or a redirect use this; everything else uses
        ``run`` with an argv, because an argv cannot be re-parsed by a shell and
        therefore cannot be mis-quoted by one.
        """
        if self.platform == "win":
            return self.run(["powershell", "-NoProfile", "-Command", command], timeout=timeout)
        return self.run(["/bin/sh", "-c", command], timeout=timeout)

    def write(self, remote: str, content: str, privileged: bool = False) -> None:
        """Place generated content at a path in the guest.

        Generated rather than copied, because most of what the harness installs
        is a config file it composes: a temp file locally, then one push, so the
        content never passes through a shell that could mangle it.

        A privileged destination is staged in the user's own tree and moved into
        place as root. Transports do not elevate - `scp` and `limactl copy` both
        write as the login user - so a policy file written straight to /etc
        fails, and it fails in a way that reads like the site not existing.
        """
        handle = tempfile.NamedTemporaryFile("w", suffix=".tmp", delete=False, encoding="utf-8")
        try:
            handle.write(content)
            handle.close()
            if privileged:
                staged = "/tmp/adr-e2e-staged-%d" % abs(hash(remote))
                self.push(handle.name, staged)
                self.mkdir(os.path.dirname(remote), privileged=True)
                self.sudo(["mv", staged, remote], check=True)
                # macOS has no `root` group - the administrative group is
                # `wheel` - so a single spelling silently fails on one of the
                # two platforms and leaves a policy file owned by the user it
                # is meant to constrain.
                self.sudo(["chown", "root:wheel" if self.platform == "mac" else "root:root",
                           remote], check=True)
                # A staged temp file arrives 0600, and root-owned 0600 is not
                # what policy looks like: the agents it governs have to be able
                # to read it, and so does the next entry that merges into it.
                self.sudo(["chmod", "0644", remote])
                return
            self.mkdir(os.path.dirname(remote), check=True)
            self.push(handle.name, remote)
        finally:
            os.unlink(handle.name)

    def sudo(self, argv: Sequence[str], timeout: int = 600, check: bool = False) -> Result:
        """Run as root. Non-interactive: a run that stops for a password has hung.

        Managed policy is the reason this exists at all. `M-SITE-12` and
        `M-SITE-13` write files a user must not be able to write - a policy file
        anyone could edit would not be policy - so the harness has to be able to
        create them the way real policy arrives.
        """
        if self.platform == "win":
            return self.run(list(argv), timeout=timeout, check=check)
        return self.run(["sudo", "-n"] + [str(item) for item in argv], timeout=timeout, check=check)

    def mkdir(self, remote: str, privileged: bool = False, check: bool = False) -> None:
        """Create a directory, and say so plainly when that is not possible.

        Worth checking rather than assuming. A directory the login user cannot
        create - a root-owned `~/.config` in a stock image, say - makes the
        *transfer* fail two steps later, and `scp: Connection closed` names
        neither the directory nor the reason. The run then looks like a broken
        harness instead of an image that needs one `chown`.
        """
        if not remote:
            return
        if self.platform == "win":
            result = self.shell("New-Item -ItemType Directory -Force -Path %s | Out-Null"
                                % _ps_quote(remote))
        elif privileged:
            result = self.sudo(["mkdir", "-p", remote])
        else:
            result = self.run(["mkdir", "-p", remote])
        if check and not result.ok:
            raise RuntimeError("cannot create %s in the guest: %s"
                               % (remote, (result.stderr or "").strip()[:160]))

    def exists(self, remote: str) -> bool:
        """Whether the path exists - including a symlink whose target does not.

        `test -e` follows the link and answers no for N-09, whose whole purpose
        is to be a link to a missing target. Verifying with it would report the
        one entry that is deliberately broken as a failed install.
        """
        if self.platform == "win":
            return self.shell("Test-Path %s" % _ps_quote(remote)).text().lower() == "true"
        return self.run(["test", "-e", remote]).ok or self.run(["test", "-L", remote]).ok

    def realpath(self, remote: str) -> str:
        """The canonical path, because usr-merge means a binary has two names."""
        if self.platform == "win":
            return self.shell("(Resolve-Path %s).Path" % _ps_quote(remote)).text()
        result = self.run(["readlink", "-f", remote])
        return result.text() if result.ok else remote


class DryRunDriver(Driver):
    """A guest that records what it was asked to do and does none of it.

    The runner is as much of the harness as the scorer, and it is much harder to
    test - it exists to mutate a machine. This makes the mutation inspectable:
    the ordering rules, the canary substitution and the recorded outcomes can
    all be asserted without a hypervisor anywhere near them.
    """

    def __init__(self, platform: str = "linux", home: str = "/home/tester",
                 responses: Optional[Dict[str, Result]] = None):
        self.platform = platform
        self.home = home
        self.image = "dry-run"
        self.commands: List[Sequence[str]] = []
        self.files: Dict[str, str] = {}
        self.privileged_writes: List[str] = []
        self.responses = responses or {}
        self.restored = 0

    def restore(self) -> None:
        self.restored += 1
        self.commands.append(("<restore>",))

    def run(self, argv: Sequence[str], timeout: int = 600, check: bool = False) -> Result:
        self.commands.append(tuple(argv))
        key = " ".join(argv)
        if key in self.responses:
            return self.responses[key]
        # The point of a dry driver is to exercise the runner's logic, so it
        # answers the two questions every recipe asks the way a working guest
        # would. Anything less and half the recipes take their failure path and
        # the ordering rules never get tested at all.
        if len(argv) == 3 and argv[0] == "test":
            return Result(argv, 0 if argv[2] in self.files else 1)
        if len(argv) == 3 and argv[:2] == ["command", "-v"]:
            return Result(argv, 0, stdout="/usr/local/bin/%s\n" % argv[2])
        # A link is a thing that now exists, even when its target does not, and
        # the recipe verifies afterwards that it does. A dry driver that ignored
        # `ln` would report N-09 - the one entry deliberately left broken - as a
        # failed install.
        plain = [item for item in argv if item not in ("sudo", "-n")]
        if len(plain) == 4 and plain[0] == "ln":
            self.files[plain[3]] = "symlink -> %s" % plain[2]
        return Result(argv, 0, stdout="")

    def push(self, local: str, remote: str) -> None:
        with open(local, encoding="utf-8") as handle:
            self.files[remote] = handle.read()

    def pull(self, remote: str, local: str) -> None:
        with open(local, "w", encoding="utf-8") as handle:
            handle.write(self.files.get(remote, ""))

    def write(self, remote: str, content: str, privileged: bool = False) -> None:
        self.files[remote] = content
        if privileged:
            self.privileged_writes.append(remote)

    def sudo(self, argv, timeout: int = 600, check: bool = False) -> Result:
        return self.run(["sudo", "-n"] + [str(item) for item in argv], timeout=timeout)

    def exists(self, remote: str) -> bool:
        """A directory exists once something has been written inside it.

        The plugin entry creates a directory, not a file, and a dry driver that
        only knew about exact paths would report the recipe's own verification
        as a failed install - a fault in the simulation, not in the harness.
        """
        if remote in self.files:
            return True
        prefix = remote.rstrip("/") + "/"
        return any(path.startswith(prefix) for path in self.files)

    def realpath(self, remote: str) -> str:
        return remote


class SSHDriver(Driver):
    """Shared SSH plumbing for the hypervisor drivers.

    The host is a guest reached over SSH in all three cases; only the lifecycle
    - how a snapshot is restored - differs, and that is what the subclasses add.
    """

    def __init__(self, host: str, user: str = "tester", port: int = 22,
                 identity: Optional[str] = None, platform: str = "linux", image: str = ""):
        self.host = host
        self.user = user
        self.port = port
        self.identity = identity
        self.platform = platform
        self.image = image

    def _ssh_base(self) -> List[str]:
        argv = ["ssh", "-p", str(self.port), "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null", "-o", "BatchMode=yes"]
        if self.identity:
            argv += ["-i", self.identity]
        return argv + ["%s@%s" % (self.user, self.host)]

    def run(self, argv: Sequence[str], timeout: int = 600, check: bool = False) -> Result:
        remote = " ".join(shlex.quote(str(item)) for item in argv)
        completed = subprocess.run(self._ssh_base() + [remote], capture_output=True,
                                   text=True, timeout=timeout)
        result = Result(argv, completed.returncode, completed.stdout, completed.stderr)
        if check and not result.ok:
            raise RuntimeError("guest command failed: %s\n%s" % (remote, result.stderr))
        return result

    def push(self, local: str, remote: str) -> None:
        self._scp(local, "%s@%s:%s" % (self.user, self.host, remote))

    def pull(self, remote: str, local: str) -> None:
        self._scp("%s@%s:%s" % (self.user, self.host, remote), local)

    def _scp(self, source: str, destination: str) -> None:
        argv = ["scp", "-P", str(self.port), "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null"]
        if self.identity:
            argv += ["-i", self.identity]
        completed = subprocess.run(argv + [source, destination], capture_output=True, text=True)
        if completed.returncode:
            raise RuntimeError("scp failed: %s -> %s\n%s" % (source, destination, completed.stderr))


def _ps_quote(value: str) -> str:
    return "'%s'" % str(value).replace("'", "''")
