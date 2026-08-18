"""MCP servers: the highest-risk surface, and the only one that is purely declared.

An ``npx -y`` server leaves essentially nothing on disk. It exists as a line in
a config file and, briefly, as a child process. Every host application keeps
that line somewhere different, under a different key, so a probe that knows only
one layout sees a fraction of the fleet's servers.
"""

import hashlib
import json
import posixpath
import re
from typing import Any, Dict, List, Optional, Tuple

from ..base_probe import BaseProbe, Observation
from ..env import DiscoveryEnv
from ..net import host_of, matches_any
from ..paths import is_descendant
from ..redact import redact_env_block, redact_url, sanitize

#: (path, host application, config key, scope). The key differs per host on
#: purpose: VS Code uses "servers", Zed uses "context_servers", everyone else
#: uses "mcpServers", and a probe that assumes one of them misses the others.
CONFIG_LOCATIONS = {
    "darwin": [
        ("~/.claude.json", "claude-code", "mcpServers", "user"),
        ("~/Library/Application Support/Claude/claude_desktop_config.json",
         "claude-desktop", "mcpServers", "user"),
        ("~/.cursor/mcp.json", "cursor", "mcpServers", "user"),
        ("~/.codeium/windsurf/mcp_config.json", "windsurf", "mcpServers", "user"),
        ("~/Library/Application Support/Zed/settings.json", "zed", "context_servers", "user"),
        ("~/Library/Application Support/Code/User/mcp.json", "vscode", "servers", "user"),
        ("~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/"
         "settings/cline_mcp_settings.json", "cline", "mcpServers", "user"),
        ("~/Library/Application Support/JetBrains/options/mcp.json", "jetbrains", "mcpServers", "user"),
        ("~/.config/opencode/opencode.json", "opencode", "mcp", "user"),
        ("~/.codex/config.toml", "codex", "mcp_servers", "user"),
        ("~/.config/goose/config.yaml", "goose", "extensions", "user"),
        ("/Library/Application Support/ClaudeCode/managed-settings.json",
         "claude-code", "mcpServers", "enterprise_managed"),
        ("/Library/Application Support/ADR/managed-mcp.json",
         "claude-code", "mcpServers", "enterprise_managed"),
    ],
    "windows": [
        ("%APPDATA%/Claude/claude_desktop_config.json", "claude-desktop", "mcpServers", "user"),
        ("~/.claude.json", "claude-code", "mcpServers", "user"),
        ("~/.cursor/mcp.json", "cursor", "mcpServers", "user"),
        ("%APPDATA%/Codeium/windsurf/mcp_config.json", "windsurf", "mcpServers", "user"),
        ("%APPDATA%/Code/User/mcp.json", "vscode", "servers", "user"),
        ("%APPDATA%/Zed/settings.json", "zed", "context_servers", "user"),
        ("~/.codex/config.toml", "codex", "mcp_servers", "user"),
        ("C:/Program Files/ClaudeCode/managed-settings.json",
         "claude-code", "mcpServers", "enterprise_managed"),
    ],
    "linux": [
        ("~/.claude.json", "claude-code", "mcpServers", "user"),
        ("~/.config/claude-desktop/claude_desktop_config.json",
         "claude-desktop", "mcpServers", "user"),
        ("~/.cursor/mcp.json", "cursor", "mcpServers", "user"),
        ("~/.codeium/windsurf/mcp_config.json", "windsurf", "mcpServers", "user"),
        ("~/.config/zed/settings.json", "zed", "context_servers", "user"),
        ("~/.config/Code/User/mcp.json", "vscode", "servers", "user"),
        ("~/.config/opencode/opencode.json", "opencode", "mcp", "user"),
        ("~/.codex/config.toml", "codex", "mcp_servers", "user"),
        ("~/.config/goose/config.yaml", "goose", "extensions", "user"),
        ("/etc/claude-code/managed-settings.json",
         "claude-code", "mcpServers", "enterprise_managed"),
    ],
}

#: Project-scoped configs, found by a depth-bounded walk of the usual roots.
PROJECT_CONFIGS = ((".mcp.json", "claude-code", "mcpServers"),
                   (".cursor/mcp.json", "cursor", "mcpServers"),
                   (".vscode/mcp.json", "vscode", "servers"))

PROJECT_ROOTS = ("~/dev", "~/src", "~/workspace", "~/code")

#: Where Claude Desktop keeps installed .mcpb bundles (formerly .dxt).
BUNDLE_DIRS = {
    "darwin": "~/Library/Application Support/Claude/Claude Extensions",
    "windows": "%APPDATA%/Claude/Claude Extensions",
    "linux": "~/.config/claude-desktop/Claude Extensions",
}

#: Where each host application caches an OAuth credential. The fact of standing
#: delegated access is the finding; the token itself never leaves the machine.
CREDENTIAL_FILES = {
    "claude-code": "~/.claude/.credentials.json",
    "claude-desktop": "~/Library/Application Support/Claude/credentials.json",
    "cursor": "~/.cursor/credentials.json",
}

#: MDM-delivered policy: a preference domain on macOS, a policy key on Windows.
MDM_PREFERENCE_DOMAIN = "com.anthropic.claudecode"
MDM_REGISTRY_KEY = r"HKLM\SOFTWARE\Policies\ClaudeCode"

#: Launchers that resolve a package at run time.
EPHEMERAL_LAUNCHERS = frozenset({"npx", "uvx", "bunx", "pipx", "pnpm", "yarn", "dlx"})
PYPI_LAUNCHERS = frozenset({"uvx", "pipx"})

#: Version specifiers that still float even though a version is written down.
FLOATING_SPECIFIERS = ("@latest", "@next", "@^", "@~", "@*", "@>", "@<")

#: Sources that resolve to whatever a branch happens to hold.
VCS_PREFIXES = ("github:", "git+", "gitlab:", "bitbucket:")

#: Shell shapes that fetch and execute code at launch. Deliberately loose about
#: what sits between the download and the interpreter: an ``env`` prefix, an
#: absolute path, a flag, or PowerShell's own spelling all describe one thing.
DOWNLOADERS = r"curl|wget|iwr|invoke-webrequest|fetch|httpie|http"
INTERPRETERS_RE = r"sh|bash|zsh|dash|fish|ksh|python[0-9.]*|node|perl|ruby|iex|invoke-expression"
REMOTE_EXEC = re.compile(
    r"\b(?:%s)\b[^|;&]*\|[^|]*?\b(?:%s)\b" % (DOWNLOADERS, INTERPRETERS_RE),
    re.IGNORECASE)

MAX_SERVERS_PER_CONFIG = 500


class McpProbe(BaseProbe):
    name = "mcp"

    def collect(self, env: DiscoveryEnv) -> List[Observation]:
        out: List[Observation] = []
        for logical, host, key, scope in CONFIG_LOCATIONS.get(env.platform, []):
            if not env.exists(logical):
                continue
            servers = self._parse(env, logical, key)
            if not servers:
                continue
            servers = self._cap(env, logical, servers)
            for name, spec in servers.items():
                observation = self.isolate(env, "%s#%s" % (logical, name),
                                           lambda n=name, sp=spec: self._observe(
                                               env, logical, host, n, sp, scope))
                if observation is not None:
                    out.append(observation)
        out.extend(self._project_scoped(env))
        out.extend(self._plugin_servers(env))
        out.extend(self._managed_policy(env))
        out.extend(self._bundles(env))
        self._apply_enablement(env, out)
        return out

    def _cap(self, env: DiscoveryEnv, logical: str, servers: Dict[str, Any]) -> Dict[str, Any]:
        """A cap that fires is reported. Silent truncation reads as coverage."""
        if len(servers) <= MAX_SERVERS_PER_CONFIG:
            return servers
        self.error(env, logical, "server list capped at %d of %d"
                   % (MAX_SERVERS_PER_CONFIG, len(servers)))
        env.coverage.setdefault("capped", []).append(
            {"path": logical, "kept": MAX_SERVERS_PER_CONFIG, "declared": len(servers)})
        return dict(list(servers.items())[:MAX_SERVERS_PER_CONFIG])

    # -- parsing ----------------------------------------------------------

    def _parse(self, env: DiscoveryEnv, logical: str, key: str) -> Optional[Dict[str, Any]]:
        if logical.endswith(".toml"):
            return self._parse_toml(env, logical, key)
        if logical.endswith((".yaml", ".yml")):
            return self._parse_yaml(env, logical, key)
        data = self._read_jsonc(env, logical)
        if not isinstance(data, dict):
            return None
        servers = data.get(key)
        return servers if isinstance(servers, dict) else {}

    def _read_jsonc(self, env: DiscoveryEnv, logical: str) -> Optional[Any]:
        """Editor configs are JSON with comments in practice, not strict JSON."""
        from .location import strip_jsonc

        result = env.read(logical)
        if not result:
            self.error(env, logical, result.error or "unreadable")
            return None
        if result.truncated:
            self.error(env, logical, "truncated at read ceiling")
        try:
            return json.loads(strip_jsonc(result.text))
        except ValueError as exc:
            self.error(env, logical, "malformed json: %s" % exc)
            return None

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
                sub_table = parts[1] if len(parts) > 1 else None
                if sub_table:
                    servers[current].setdefault(sub_table, {})
                continue
            if line.startswith("["):
                current = sub_table = None
                continue
            if current is None or "=" not in line:
                continue
            field, _, value = line.partition("=")
            target = servers[current][sub_table] if sub_table else servers[current]
            target[field.strip()] = _toml_value(value.strip())
        return servers

    def _parse_yaml(self, env: DiscoveryEnv, logical: str, key: str) -> Optional[Dict[str, Any]]:
        """Minimal YAML subset for goose-style ``extensions:`` blocks.

        Reported as an error rather than skipped when it does not parse: a
        silently ignored config is indistinguishable from an empty one.
        """
        result = env.read(logical)
        if not result:
            self.error(env, logical, result.error or "unreadable")
            return None
        servers: Dict[str, Any] = {}
        in_block = False
        current: Optional[str] = None
        for raw_line in result.text.splitlines():
            if not raw_line.strip() or raw_line.lstrip().startswith("#"):
                continue
            indent = len(raw_line) - len(raw_line.lstrip())
            line = raw_line.strip()
            if indent == 0:
                in_block = line.rstrip(":") == key
                current = None
                continue
            if not in_block:
                continue
            if line.endswith(":") and indent <= 2:
                current = line[:-1].strip()
                servers[current] = {}
                continue
            if current is None or ":" not in line:
                continue
            field, _, value = line.partition(":")
            servers[current][field.strip()] = _yaml_value(value.strip())
        return servers

    # -- additional surfaces ----------------------------------------------

    def _project_scoped(self, env: DiscoveryEnv) -> List[Observation]:
        out: List[Observation] = []
        for root in PROJECT_ROOTS:
            for logical, _ in env.walk(env.expand(root), max_depth=3):
                for suffix, host, key in PROJECT_CONFIGS:
                    if not logical.endswith("/" + suffix):
                        continue
                    servers = self._cap(env, logical, self._parse(env, logical, key) or {})
                    for name, spec in servers.items():
                        out.append(self._observe(env, logical, host, name, spec, "project"))
        return out

    def _plugin_servers(self, env: DiscoveryEnv) -> List[Observation]:
        """A plugin install is a supply-chain event for MCP too."""
        base = env.expand("~/.claude/plugins")
        if not env.is_dir(base):
            return []
        out: List[Observation] = []
        for plugin in env.listdir(base):
            logical = posixpath.join(base, plugin, ".mcp.json")
            if not env.exists(logical):
                continue
            for name, spec in self._cap(env, logical,
                                        self._parse(env, logical, "mcpServers") or {}).items():
                observation = self._observe(env, logical, "claude-code", name, spec, "plugin")
                observation.extra["plugin"] = plugin
                out.append(observation)
        return out

    def _managed_policy(self, env: DiscoveryEnv) -> List[Observation]:
        """Policy delivered by MDM rather than by a file on disk."""
        out: List[Observation] = []
        payload = env.preferences.get(MDM_PREFERENCE_DOMAIN)
        if isinstance(payload, dict):
            for name, spec in self._cap(env, "defaults:%s" % MDM_PREFERENCE_DOMAIN,
                                        payload.get("mcpServers") or {}).items():
                observation = self._observe(env, "defaults:%s" % MDM_PREFERENCE_DOMAIN,
                                            "claude-code", name, spec, "enterprise_managed")
                observation.extra["source"] = "mdm"
                out.append(observation)
        for record in env.registry:
            if str(record.get("Key", "")).upper() != MDM_REGISTRY_KEY.upper():
                continue
            try:
                settings = json.loads(record.get("Settings", "{}"))
            except ValueError as exc:
                self.error(env, MDM_REGISTRY_KEY, "malformed policy json: %s" % exc)
                continue
            for name, spec in self._cap(env, MDM_REGISTRY_KEY,
                                        settings.get("mcpServers") or {}).items():
                observation = self._observe(env, MDM_REGISTRY_KEY, "claude-code", name,
                                            spec, "enterprise_managed")
                observation.extra["source"] = "mdm"
                out.append(observation)
        return out

    def _bundles(self, env: DiscoveryEnv) -> List[Observation]:
        """Installed .mcpb bundles carry their own runtime and reveal nothing else."""
        base = env.expand(BUNDLE_DIRS.get(env.platform, ""))
        if not base or not env.is_dir(base):
            return []
        out: List[Observation] = []
        for name in env.listdir(base):
            folder = posixpath.join(base, name)
            manifest = self.read_json(env, posixpath.join(folder, "manifest.json"))
            if not isinstance(manifest, dict):
                continue
            server = manifest.get("server") or {}
            spec = {"command": server.get("command", ""), "args": server.get("args", [])}
            observation = self._observe(env, folder, "claude-desktop",
                                        manifest.get("name", name), spec, "user")
            observation.install_method = "mcpb"
            observation.version = manifest.get("version")
            observation.extra["bundle"] = manifest.get("name", name)
            if not manifest.get("signature"):
                observation.extra["risk_factors"].append("unsigned_bundle")
            out.append(observation)
        return out

    def _apply_enablement(self, env: DiscoveryEnv, observations: List[Observation]) -> None:
        """Project servers are inert until approved, and that is worth recording."""
        approved: Dict[str, List[str]] = {}
        for root in PROJECT_ROOTS:
            for logical, _ in env.walk(env.expand(root), max_depth=3):
                if not logical.endswith("/.claude/settings.json"):
                    continue
                data = self._read_jsonc(env, logical)
                if isinstance(data, dict):
                    project = posixpath.dirname(posixpath.dirname(logical))
                    approved[project] = list(data.get("enabledMcpjsonServers") or [])
        for observation in observations:
            if observation.extra.get("scope") != "project":
                continue
            project = posixpath.dirname(observation.path)
            for candidate, names in approved.items():
                if is_descendant(project, candidate):
                    observation.extra["enabled"] = observation.name in names
                    break

    # -- one server -------------------------------------------------------

    def _observe(self, env: DiscoveryEnv, config_path: str, host: str,
                 name: str, spec: Any, scope: str) -> Observation:
        spec = spec if isinstance(spec, dict) else {}
        malformed: List[str] = []
        command = sanitize(str(spec.get("command", "")))
        args = _as_args(spec.get("args"), malformed)
        env_block = _as_env(spec.get("env"), malformed)
        raw_url = spec.get("url") or spec.get("uri") or ""
        url = redact_url(str(raw_url)) if raw_url else ""
        transport = spec.get("type") or spec.get("transport") or (
            "http" if url.startswith("http") else "stdio")
        env_names, credential_kinds = redact_env_block(env_block)
        pinned, factors, method = classify_launch(command, args, url)
        factors.extend(self._contextual_factors(env, transport, url, env_block, args))
        flags = list(malformed)
        if command.startswith("/") and not env.exists(command):
            # A declaration whose command is absent is still a real declaration.
            flags.append("command_missing")
        credential = bool(url) and env.exists(CREDENTIAL_FILES.get(host, ""))
        return Observation(
            probe=self.name, channel="config", kind="mcp_server", name=sanitize(str(name)),
            path=config_path, matched_on="config:%s" % host, install_method=method,
            identity_hint=server_identity(transport, command, args, url),
            owner=env.user, confidence=0.6,
            extra={
                "command": command, "args": args, "url": url, "transport": transport,
                "env_names": env_names, "credential_kinds": credential_kinds, "scope": scope,
                "host_app": host, "pinned": pinned, "risk_factors": factors,
                "enabled": _enablement(spec, scope), "flags": flags,
                "stored_credential": credential,
            },
        )

    def _contextual_factors(self, env: DiscoveryEnv, transport: str, url: str,
                            env_block: Any, args: List[str]) -> List[str]:
        """Risk that depends on the tenant or on what the server was granted."""
        factors = []
        if transport == "sse":
            # Deprecated in 2025, with removals landing through 2026.
            factors.append("deprecated_transport")
        if url:
            corporate = env.policy.get("corporate_domains") or []
            if corporate and not matches_any(host_of(url), corporate):
                factors.append("third_party_remote")
        if env_block is None and not url:
            # No env block does not mean no credentials. It means all of them.
            factors.append("inherits_environment")
        if any(arg in ("/", "~", "/Users", "/home") for arg in args):
            factors.append("broad_filesystem_scope")
        if any("gateway" in arg or "mcp-gateway" in arg for arg in args):
            factors.append("aggregator")
        return factors


def _enablement(spec: Dict[str, Any], scope: str) -> Optional[bool]:
    """Whether a declaration is live, or None when the host has not said.

    A project server is inert until the project's settings approve it, so
    "declared here, approval unknown" is a third state and not a synonym for
    enabled. Collapsing it into True is what let one project's approval appear
    to cover a neighbouring one.
    """
    if spec.get("disabled") is True:
        return False
    return None if scope == "project" else True


def _as_args(value: Any, malformed: List[str]) -> List[str]:
    """Arguments are an array of scalars, whatever a config actually contains.

    A bare string is the common mistake, and iterating it yields one argument
    per character - which changes both the server's identity and its pinning
    verdict. Treated as a single argument, and the record is marked.
    """
    if value is None:
        return []
    if isinstance(value, str):
        malformed.append("malformed_config")
        return [sanitize(value)]
    if not isinstance(value, (list, tuple)):
        malformed.append("malformed_config")
        return [sanitize(str(value))]
    out = []
    for item in value:
        if isinstance(item, (dict, list, tuple)):
            malformed.append("malformed_config")
            continue
        out.append(sanitize(str(item)))
    return out


def _as_env(value: Any, malformed: List[str]) -> Optional[Dict[str, Any]]:
    """An env block is a mapping. Anything else is reported, never fatal."""
    if value is None:
        return None
    if isinstance(value, dict):
        return value
    malformed.append("malformed_config")
    return {}


def _toml_value(raw: str) -> Any:
    value = raw.split(" #", 1)[0].strip()
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [piece.strip().strip('"').strip("'") for piece in inner.split(",") if piece.strip()]
    return value.strip('"').strip("'")


def _yaml_value(raw: str) -> Any:
    value = raw.strip()
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        return [piece.strip().strip('"').strip("'") for piece in inner.split(",") if piece.strip()]
    if value in ("true", "false"):
        return value == "true"
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
    args = list(args or [])
    joined = " ".join([command or ""] + args)
    if REMOTE_EXEC.search(joined):
        # Fetching a script and piping it to a shell is the highest-severity
        # shape a stdio server can take.
        factors.append("remote_code_execution")
        return False, factors, "shell"
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
        if any(package.startswith(prefix) for prefix in VCS_PREFIXES):
            factors.extend(["unpinned_supply_chain", "vcs_source"])
            return False, factors, method
        if any(marker in package for marker in FLOATING_SPECIFIERS):
            # A range resolves to something new whenever upstream publishes.
            factors.append("floating_range")
            return False, factors, method
        pinned = bool(package) and "@" in package.lstrip("@")
        if not pinned:
            factors.append("unpinned_supply_chain")
        return pinned, factors, method
    return True, factors, "unknown"
