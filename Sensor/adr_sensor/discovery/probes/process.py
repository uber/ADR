"""Stage 2b: what is actually running, and what it spawned.

The process tree is the only place the agent-to-MCP-server binding can be
*observed* rather than inferred from a config file. A server running that
appears in no config is close to a working definition of unsanctioned.
"""

import posixpath
from typing import List

from ..base_probe import BaseProbe, Observation
from ..env import DiscoveryEnv, ProcessInfo
from ..paths import install_method, install_root
from ..redact import redact_argv
from .mcp import EPHEMERAL_LAUNCHERS, classify_launch, server_identity

#: Interpreters that say nothing on their own - the payload is in argv.
INTERPRETERS = frozenset({"node", "python", "python3", "bun", "deno", "ruby", "sh", "bash"})

#: Directories searched when ``ps`` reports a bare command name rather than a
#: path, so a running agent resolves to the same real path the filesystem
#: probes found and the two observations merge instead of double-counting.
PATH_FALLBACK_DIRS = ("/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin")

#: A child of an agent is only a *candidate* MCP server. An agent also spawns
#: shells, ripgrep and build tools, and calling all of them servers manufactures
#: undeclared-server findings on every developer laptop. Require a positive hint.
SERVER_HINTS = ("mcp", "-server", "server-")


class ProcessProbe(BaseProbe):
    name = "process"

    def collect(self, env: DiscoveryEnv) -> List[Observation]:
        out: List[Observation] = []
        by_pid = {process.pid: process for process in env.processes}
        for process in env.processes:
            entry = self.catalog.match("binaries", posixpath.basename(process.exe))
            if entry:
                out.append(self._agent(env, process, entry))
                continue
            parent = by_pid.get(process.ppid)
            if parent is None or not self.catalog.match("binaries", posixpath.basename(parent.exe)):
                continue
            if looks_like_server(process.argv):
                out.append(self._child_server(env, process, parent))
        return out

    def _resolve_exe(self, env: DiscoveryEnv, exe: str) -> str:
        """Turn a bare command name from ``ps`` into a path, when we can."""
        if exe.startswith("/"):
            return exe
        directories = [d for d in env.env_vars.get("PATH", "").split(":") if d]
        directories.extend(PATH_FALLBACK_DIRS)
        for directory in directories:
            candidate = posixpath.join(directory, exe)
            if env.exists(candidate):
                return candidate
        return exe

    def _agent(self, env: DiscoveryEnv, process: ProcessInfo, entry) -> Observation:
        exe = self._resolve_exe(env, process.exe)
        realpath = env.realpath(exe)
        # An executable deleted after launch still ran. Dropping it for failing a
        # stat would lose the most interesting process on the box.
        flags = [] if env.exists(exe) else ["exe_missing"]
        return Observation(
            probe=self.name, channel="runtime", kind=entry.get("kind", "cli_agent"),
            name=entry["name"], path=exe,
            matched_on="process:%s" % posixpath.basename(exe),
            catalog_id=entry["id"], vendor=entry.get("vendor"),
            realpath=exe if flags else realpath,
            install_root=install_root(realpath), install_method=install_method(realpath),
            owner=process.user or env.user,
            extra={"pid": process.pid, "argv": redact_argv(process.argv), "cwd": process.cwd,
                   "running": True, "flags": flags},
            confidence=0.65,
        )

    def _child_server(self, env: DiscoveryEnv, process: ProcessInfo, parent: ProcessInfo) -> Observation:
        """A child of an agent process is an MCP server until shown otherwise."""
        argv = redact_argv(process.argv)
        launcher = posixpath.basename(process.exe)
        args = argv[1:]
        pinned, factors, method = classify_launch(launcher, args, "")
        parent_entry = self.catalog.match("binaries", posixpath.basename(parent.exe))
        return Observation(
            probe=self.name, channel="runtime", kind="mcp_server", name=_server_name(argv),
            path=process.exe, matched_on="child_of:%s" % posixpath.basename(parent.exe),
            install_method=method, identity_hint=server_identity("stdio", launcher, args, ""),
            owner=process.user or env.user,
            extra={"pid": process.pid, "ppid": parent.pid, "argv": argv,
                   "parent_agent": (parent_entry or {}).get("id"), "transport": "stdio",
                   "pinned": pinned, "risk_factors": factors, "running": True,
                   "flags": [] if env.exists(process.exe) else ["exe_missing"]},
            confidence=0.6,
        )


def looks_like_server(argv: List[str]) -> bool:
    """Whether a child process is plausibly an MCP server rather than a tool call.

    Deliberately conservative. Missing a server that names itself nothing costs
    one false negative; calling every ``bash -c`` a server costs the operator
    their trust in the whole findings list.
    """
    if not argv:
        return False
    launcher = posixpath.basename(argv[0])
    if launcher in EPHEMERAL_LAUNCHERS or launcher == "docker":
        return True
    joined = " ".join(argv).lower()
    return any(hint in joined for hint in SERVER_HINTS)


def _server_name(argv: List[str]) -> str:
    """Name a server from what it launches, skipping flags and interpreters."""
    for token in argv[1:]:
        if token.startswith("-") or token == "[REDACTED]":
            continue
        base = posixpath.basename(token)
        if not base:
            continue
        return base if base.startswith("@") else base.rsplit("@", 1)[0]
    return posixpath.basename(argv[0]) if argv else "unknown"
