"""Stage 2b: what is actually running, and what it spawned.

The process tree is the only place the agent-to-MCP-server binding can be
*observed* rather than inferred from a config file. A server running that
appears in no config is close to a working definition of unsanctioned.
"""

import posixpath
import re
from typing import Dict, List, Optional

from ..base_probe import BaseProbe, Observation
from ..env import DiscoveryEnv, ProcessInfo
from ..paths import install_method, install_root
from ..redact import redact_argv
from .mcp import DOCKER_VALUE_OPTIONS, classify_launch, first_operand, server_identity

#: Interpreters that say nothing on their own - the payload is in argv.
INTERPRETERS = frozenset({"node", "python", "python3", "bun", "deno", "ruby", "sh", "bash"})

#: Directories searched when ``ps`` reports a bare command name rather than a
#: path, so a running agent resolves to the same real path the filesystem
#: probes found and the two observations merge instead of double-counting.
PATH_FALLBACK_DIRS = ("/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin")

#: A child of an agent is only a *candidate* MCP server. An agent also spawns
#: shells, linters, bundlers and build tools, and calling those servers
#: manufactures high-severity findings out of ordinary development. The
#: evidence has to be MCP-specific: the word "mcp" as a component of a token,
#: or the protocol's own package scope. "server" is not evidence - a file named
#: my-server-test.py is a test.
SERVER_MARKERS = ("mcp", "modelcontextprotocol")

#: ``npm run x`` executes a package script, whatever the script is called.
TASK_RUNNERS = frozenset({"npm", "yarn", "pnpm", "bun", "just", "make"})


class ProcessProbe(BaseProbe):
    name = "process"

    def collect(self, env: DiscoveryEnv) -> List[Observation]:
        out: List[Observation] = []
        by_pid = {process.pid: process for process in env.processes}
        agents: Dict[tuple, List[ProcessInfo]] = {}
        for process in env.processes:
            entry = self.catalog.match("binaries", posixpath.basename(process.exe))
            if entry:
                key = (entry["id"], process.user or env.user, self._resolve_exe(env, process.exe))
                agents.setdefault(key, []).append(process)
                continue
            containerized = self._containerized(env, process)
            if containerized is not None:
                out.append(containerized)
                continue
            parent = by_pid.get(process.ppid)
            if parent is None or not self.catalog.match("binaries", posixpath.basename(parent.exe)):
                continue
            if looks_like_server(process.argv):
                out.append(self._child_server(env, process, parent))
        for (catalog_id, _, _), processes in sorted(agents.items()):
            out.append(self._agent(env, processes, self.catalog.get(catalog_id)))
        return out

    def _containerized(self, env: DiscoveryEnv, process: ProcessInfo) -> Optional[Observation]:
        """An agent inside a container is invisible to a host-path scan."""
        if posixpath.basename(process.exe) != "docker" or "run" not in process.argv:
            return None
        image = first_operand(process.argv[1:], DOCKER_VALUE_OPTIONS,
                              skip={"run", "exec", "create"})
        entry = None
        for candidate in self.catalog.entries:
            names = candidate.get("binaries", []) + [candidate["id"]]
            if any(name and name in image for name in names):
                entry = candidate
                break
        if entry is None:
            return None
        mounts = [token for index, token in enumerate(process.argv)
                  if index and process.argv[index - 1] in ("-v", "--volume")]
        return Observation(
            probe=self.name, channel="runtime", kind=entry.get("kind", "cli_agent"),
            name=entry["name"], path=image, matched_on="container_image",
            catalog_id=entry["id"], vendor=entry.get("vendor"), install_method="container",
            owner=process.user or env.user, identity_hint="attr:%s" % entry["id"],
            extra={"flags": ["containerized"], "image": image, "mounts": mounts,
                   "running": True, "location": "container"},
            confidence=0.55,
        )

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

    def _agent(self, env: DiscoveryEnv, processes: List[ProcessInfo], entry) -> Observation:
        """One asset per agent per user, carrying how many sessions are running.

        Six concurrent sessions are one agent used six times, not six agents.
        """
        first = processes[0]
        exe = self._resolve_exe(env, first.exe)
        realpath = env.realpath(exe)
        # An executable deleted after launch still ran. Dropping it for failing a
        # stat would lose the most interesting process on the box.
        flags = [] if env.exists(exe) else ["exe_missing"]
        factors: List[str] = []
        for process in processes:
            for token in process.argv:
                if token in ("-p", "--print") and "unattended_run" not in factors:
                    factors.append("unattended_run")
                if token == "--dangerously-skip-permissions" and "permission_bypass" not in factors:
                    factors.append("permission_bypass")
        repositories, worktrees = self._repositories(env, processes)
        sensitive = [path for path in repositories
                     if path in (env.policy.get("sensitive_repos") or [])]
        if sensitive:
            factors.append("sensitive_repository")
        location = self._location_of(env, exe)
        if location:
            flags.append("remote_location")
        return Observation(
            probe=self.name, channel="runtime", kind=entry.get("kind", "cli_agent"),
            name=entry["name"], path=exe,
            matched_on="process:%s" % posixpath.basename(exe),
            catalog_id=entry["id"], vendor=entry.get("vendor"),
            realpath=exe if "exe_missing" in flags else realpath,
            install_root=install_root(realpath), install_method=install_method(realpath, env.home),
            owner=first.user or env.user,
            extra={"pid": first.pid, "argv": redact_argv(first.argv), "cwd": first.cwd,
                   "running": True, "flags": flags, "session_count": len(processes),
                   "risk_factors": factors, "repositories": sorted(set(repositories)),
                   "worktrees": sorted(set(worktrees)), "location": location,
                   "mode": self._mode(processes)},
            confidence=0.65,
        )

    def _mode(self, processes: List[ProcessInfo]) -> Optional[str]:
        """Sandboxed and permission-bypassed are different facts, not one."""
        for process in processes:
            for index, token in enumerate(process.argv):
                if token == "--permission-mode" and index + 1 < len(process.argv):
                    return process.argv[index + 1]
                if token in ("--sandbox", "--sandboxed"):
                    return "sandbox"
                if token == "--dangerously-skip-permissions":
                    return "bypassPermissions"
        return None

    def _repositories(self, env: DiscoveryEnv, processes: List[ProcessInfo]):
        """Resolve each working directory to its repository, worktrees included."""
        repositories, worktrees = [], []
        for process in processes:
            if not process.cwd:
                continue
            marker = posixpath.join(process.cwd, ".git")
            result = env.read(marker, limit=4096)
            if result and result.text.startswith("gitdir:"):
                # A worktree's .git is a file pointing back at the main repo, so
                # three worktrees are three sessions in one repository.
                pointer = result.text.split(":", 1)[1].strip()
                repositories.append(pointer.split("/.git/")[0])
                worktrees.append(process.cwd)
            else:
                repositories.append(process.cwd)
        return repositories, worktrees

    def _location_of(self, env: DiscoveryEnv, exe: str) -> Optional[str]:
        for location in env.locations:
            root = location.get("root", "").rstrip("/")
            if root and exe.startswith(root + "/"):
                return "%s:%s" % (location.get("kind", "location"), location.get("name", "unnamed"))
        return None

    def _child_server(self, env: DiscoveryEnv, process: ProcessInfo, parent: ProcessInfo) -> Observation:
        """A child of an agent process is an MCP server until shown otherwise."""
        # Identity from the raw launch, storage from the redacted one - the same
        # split the config side makes, or the two channels describe one server
        # with two identities and never merge.
        raw_args = list(process.argv[1:])
        argv = redact_argv(process.argv)
        pinned, factors, method = classify_launch(process.exe, raw_args, "")
        parent_entry = self.catalog.match("binaries", posixpath.basename(parent.exe))
        return Observation(
            probe=self.name, channel="runtime", kind="mcp_server", name=_server_name(argv),
            path=process.exe, matched_on="child_of:%s" % posixpath.basename(parent.exe),
            install_method=method,
            identity_hint=server_identity("stdio", process.exe, raw_args, ""),
            owner=process.user or env.user,
            extra={"pid": process.pid, "ppid": parent.pid, "argv": argv,
                   "parent_agent": (parent_entry or {}).get("id"), "transport": "stdio",
                   "pinned": pinned, "risk_factors": factors, "running": True,
                   "flags": [] if env.exists(process.exe) else ["exe_missing"]},
            confidence=0.6,
        )


def looks_like_server(argv: List[str]) -> bool:
    """Whether a child process is plausibly an MCP server rather than a tool call.

    Deliberately conservative, and deliberately not satisfied by the launcher
    alone: ``npx`` runs eslint far more often than it runs a server. Anything
    this misses that a config declares is recovered by correlation in the
    runner, so the cost of being strict here is close to nothing, while the cost
    of being loose is a security finding on every ``npx vite``.
    """
    if not argv:
        return False
    launcher = posixpath.basename(argv[0]).lower()
    if launcher in TASK_RUNNERS and len(argv) > 1 and argv[1] in ("run", "run-script", "exec"):
        return False
    for token in argv:
        lowered = str(token).lower()
        if "modelcontextprotocol" in lowered:
            return True
        components = re.split(r"[^a-z0-9]+", lowered)
        if "mcp" in components:
            return True
    return False


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
