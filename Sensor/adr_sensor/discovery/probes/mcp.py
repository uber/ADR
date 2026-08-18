"""MCP servers: the highest-risk surface, and the one that is only ever declared.

An ``npx -y`` server leaves essentially nothing on disk. It exists as a line in
a config file and, briefly, as a child process. This probe reads every config a
host application may use; the process probe catches what never got declared.
"""

import hashlib
import posixpath
import re
from typing import Any, Dict, List, Optional, Tuple

from ..base_probe import BaseProbe, Observation
from ..env import DiscoveryEnv
from ..redact import redact_env_block, redact_url, sanitize

#: (logical path, host application, config key), per platform.
CONFIG_LOCATIONS = {
    "darwin": [
        ("~/.claude.json", "claude-code", "mcpServers"),
        ("~/Library/Application Support/Claude/claude_desktop_config.json", "claude-desktop", "mcpServers"),
        ("~/.cursor/mcp.json", "cursor", "mcpServers"),
        ("~/Library/Application Support/Code/User/mcp.json", "vscode", "servers"),
        ("~/.config/opencode/opencode.json", "opencode", "mcp"),
        ("~/.codex/config.toml", "codex", "mcp_servers"),
    ],
    "windows": [
        ("%APPDATA%/Claude/claude_desktop_config.json", "claude-desktop", "mcpServers"),
        ("~/.claude.json", "claude-code", "mcpServers"),
        ("~/.cursor/mcp.json", "cursor", "mcpServers"),
        ("%APPDATA%/Code/User/mcp.json", "vscode", "servers"),
        ("~/.codex/config.toml", "codex", "mcp_servers"),
    ],
    "linux": [
        ("~/.claude.json", "claude-code", "mcpServers"),
        ("~/.config/Claude/claude_desktop_config.json", "claude-desktop", "mcpServers"),
        ("~/.cursor/mcp.json", "cursor", "mcpServers"),
        ("~/.config/opencode/opencode.json", "opencode", "mcp"),
        ("~/.codex/config.toml", "codex", "mcp_servers"),
    ],
}

#: Project roots scanned for ``.mcp.json``, depth-bounded.
PROJECT_ROOTS = ("~/dev", "~/src", "~/workspace", "~/code")

#: Launchers that resolve a package at run time. Whether that resolution is
#: pinned is the single highest-yield finding in the module.
EPHEMERAL_LAUNCHERS = frozenset({"npx", "uvx", "bunx", "pipx", "pnpm", "yarn", "dlx"})

PYPI_LAUNCHERS = frozenset({"uvx", "pipx"})

#: Cap on servers read from one config, so a hostile file cannot exhaust memory.
#: A cap that fires is reported, never silently applied.
MAX_SERVERS_PER_CONFIG = 500


class McpProbe(BaseProbe):
    name = "mcp"

    def collect(self, env: DiscoveryEnv) -> List[Observation]:
        out: List[Observation] = []
        for logical, host, key in CONFIG_LOCATIONS.get(env.platform, []):
            if not env.exists(logical):
                continue
            servers = self._parse(env, logical, key)
            if not servers:
                continue
            if len(servers) > MAX_SERVERS_PER_CONFIG:
                self.error(env, logical, "server list capped at %d of %d"
                           % (MAX_SERVERS_PER_CONFIG, len(servers)))
                servers = dict(list(servers.items())[:MAX_SERVERS_PER_CONFIG])
            for name, spec in servers.items():
                out.append(self._observe(env, logical, host, name, spec, "user"))
        out.extend(self._project_scoped(env))
        return out

    # -- parsing ----------------------------------------------------------

    def _parse(self, env: DiscoveryEnv, logical: str, key: str) -> Optional[Dict[str, Any]]:
        if logical.endswith(".toml"):
            return self._parse_toml(env, logical, key)
        data = self.read_json(env, logical)
        if not isinstance(data, dict):
            return None
        servers = data.get(key)
        return servers if isinstance(servers, dict) else {}

    def _parse_toml(self, env: DiscoveryEnv, logical: str, key: str) -> Optional[Dict[str, Any]]:
        """Minimal TOML subset: ``[key.name]`` tables of strings and arrays.

        Codex ships TOML and the collector targets Python 3.9, which has no
        ``tomllib``. A full parser is not warranted for one fixed shallow shape.
        """
        result = env.read(logical)
        if not result:
            self.error(env, logical, result.error or "unreadable")
            return None
        servers: Dict[str, Any] = {}
        current: Optional[str] = None
        sub_table: Optional[str] = None
        for raw_line in result.text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            header = re.match(r"^\[%s\.([^\]]+)\]$" % re.escape(key), line)
            if header:
                # ``[mcp_servers.name.env]`` is a sub-table of ``name``, not a
                # second server. Treating it as one invents an asset per section.
                parts = [piece.strip('"') for piece in header.group(1).split(".")]
                current = parts[0]
                servers.setdefault(current, {})
                if len(parts) > 1:
                    servers[current].setdefault(parts[1], {})
                    section = parts[1]
                else:
                    section = None
                sub_table = section
                continue
            if line.startswith("["):
                current = None
                sub_table = None
                continue
            if current is None or "=" not in line:
                continue
            field, _, value = line.partition("=")
            target = servers[current][sub_table] if sub_table else servers[current]
            target[field.strip()] = _toml_value(value.strip())
        return servers

    def _project_scoped(self, env: DiscoveryEnv) -> List[Observation]:
        out: List[Observation] = []
        for root in PROJECT_ROOTS:
            for logical, _ in env.walk(env.expand(root), max_depth=2):
                if posixpath.basename(logical) != ".mcp.json":
                    continue
                data = self.read_json(env, logical)
                if not isinstance(data, dict):
                    continue
                for name, spec in (data.get("mcpServers") or {}).items():
                    out.append(self._observe(env, logical, "claude-code", name, spec, "project"))
        return out

    # -- one server -------------------------------------------------------

    def _observe(self, env: DiscoveryEnv, config_path: str, host: str,
                 name: str, spec: Any, scope: str) -> Observation:
        spec = spec if isinstance(spec, dict) else {}
        command = sanitize(str(spec.get("command", "")))
        args = [sanitize(str(arg)) for arg in (spec.get("args") or [])]
        url = redact_url(str(spec.get("url"))) if spec.get("url") else ""
        transport = spec.get("type") or ("http" if url.startswith("http") else "stdio")
        env_names, credential_kinds = redact_env_block(spec.get("env"))
        pinned, factors, method = classify_launch(command, args, url)
        return Observation(
            probe=self.name, channel="config", kind="mcp_server", name=sanitize(str(name)),
            path=config_path, matched_on="config:%s" % host, install_method=method,
            identity_hint=server_identity(transport, command, args, url),
            owner=env.user, confidence=0.6,
            extra={
                "command": command, "args": args, "url": url, "transport": transport,
                "env_names": env_names, "credential_kinds": credential_kinds, "scope": scope,
                "host_app": host, "pinned": pinned, "risk_factors": factors,
            },
        )


def _toml_value(raw: str) -> Any:
    value = raw.split(" #", 1)[0].strip()
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [piece.strip().strip('"').strip("'") for piece in inner.split(",") if piece.strip()]
    return value.strip('"').strip("'")


def server_identity(transport: str, command: str, args: List[str], url: str) -> str:
    """Identity of an MCP server is what it launches, never what it is called.

    Two configs naming the same command are one server declared twice; two
    servers both called ``github`` with different commands are two servers.
    """
    payload = "|".join([transport or "", url or "", command or "", " ".join(args or [])])
    return "mcp:" + hashlib.sha256(payload.encode()).hexdigest()[:16]


def classify_launch(command: str, args: List[str], url: str) -> Tuple[bool, List[str], str]:
    """Decide whether a launch is version-pinned, and why it might not be."""
    factors: List[str] = []
    base = posixpath.basename(command or "")
    args = args or []
    if url:
        if url.startswith("http://"):
            factors.append("plaintext_remote")
        return True, factors, "remote"
    if base == "docker":
        image = next((arg for arg in args if "/" in arg or ":" in arg), "")
        tag = image.rsplit("/", 1)[-1]
        if not image or image.endswith(":latest") or ":" not in tag:
            factors.append("unpinned_supply_chain")
            return False, factors, "container"
        return True, factors, "container"
    if base in EPHEMERAL_LAUNCHERS:
        method = "pypi-ephemeral" if base in PYPI_LAUNCHERS else "npm-ephemeral"
        package = next((arg for arg in args if not arg.startswith("-")), "")
        pinned = bool(package) and "@" in package.lstrip("@")
        if not pinned:
            factors.append("unpinned_supply_chain")
        return pinned, factors, method
    return True, factors, "unknown"
