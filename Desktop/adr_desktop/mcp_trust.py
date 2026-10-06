"""Recognize only verified, packaged ADR MCP servers; names alone grant no trust."""

import json
import os
import stat
import sys
import tomllib
from pathlib import Path

from .config import read_private_json
from .local_client import request

TOOLS = {
    "adr": {
        "adr_status", "adr_search_conversations", "adr_list_conversations", "adr_get_conversation",
        "adr_list_environment", "adr_run_command",
    },
    "adr_history": {"adr_status", "adr_search_history", "adr_list_sessions", "adr_get_session"},
    "adr_vault": {"adr_status", "adr_list_credentials", "adr_request_service", "adr_service_result"},
    "adr_vault_env": {"adr_status", "adr_list_environment", "adr_run_command"},
    "adr_context": {
        "adr_status",
        "adr_search_conversations",
        "adr_list_conversations",
        "adr_get_conversation",
    },
}


def _read(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
            raise ValueError("Unsupported MCP configuration")
        raw = handle.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError("MCP configuration is too large")
    return tomllib.loads(raw.decode()) if path.suffix == ".toml" else json.loads(raw)


def trusted_tool(event, harness, state_dir):
    return bool(trusted_grant_id(event, harness, state_dir))


def trusted_grant_id(event, harness, state_dir):
    """Return the verified local grant identity, never a capability or secret."""
    # A Python development launcher can be shadowed by project-local modules.
    # Exempt only the packaged core, not arbitrary wrappers or a familiar name.
    if not getattr(sys, "frozen", False):
        return False
    name = event.get("tool_name", event.get("toolName", ""))
    matches = [
        server
        for server, tools in TOOLS.items()
        if any(
            name
            in (
                f"mcp__{server}__{tool}",
                f"{server}_{tool}",
                f"mcp__plugin_adr-agent_{server}__{tool}",
                f"mcp__plugin_adr_agent_{server}__{tool}",
            )
            for tool in tools
        )
    ]
    if not matches:
        return False
    server = matches[0]
    try:
        from .agent_plugins import plugin_root
        from .hooks import configuration_path

        cwd = Path(event.get("cwd", ""))
        if not cwd.is_absolute():
            return False
        roots = [cwd, *cwd.parents]
        if harness == "claude":
            files, key = [Path.home() / ".claude.json", *(root / ".mcp.json" for root in roots)], "mcpServers"
        elif harness == "codex":
            directory = configuration_path("codex").parent
            files, key = (
                [directory / "config.toml", *(root / ".codex/config.toml" for root in roots)],
                "mcp_servers",
            )
        elif harness == "opencode":
            directory = configuration_path("opencode").parent.parent
            files = [
                *(directory / name for name in ("opencode.json", "opencode.jsonc")),
                *(root / name for root in roots for name in ("opencode.json", "opencode.jsonc")),
            ]
            key = "mcp"
        else:
            files, key = [Path.home() / ".copilot/mcp-config.json"], "mcpServers"
        definitions = []
        root = plugin_root(state_dir, harness)
        if root and server in ("adr", "adr_context"):
            definitions.append(_read(root / ".mcp.json")["mcpServers"][server])
        for file in dict.fromkeys(files):
            if not file.exists():
                continue
            data = _read(file)
            if server in data.get(key, {}):
                definitions.append(data[key][server])
            if harness == "claude":
                for root in roots:
                    project = data.get("projects", {}).get(str(root), {})
                    if server in project.get("mcpServers", {}):
                        definitions.append(project["mcpServers"][server])
        if not definitions:
            return False
        grant_ids = set()
        for definition in definitions:
            supported = {
                "command",
                "args",
                "enabled",
                "type",
                "tools",
                "description",
                "timeout",
                "startup_timeout_sec",
                "tool_timeout_sec",
                "enabled_tools",
                "disabled_tools",
                "env",
            }
            if set(definition) - supported or definition.get("type") not in (None, "local", "stdio"):
                return False
            if definition.get("enabled") is False or definition.get("env") or definition.get("env_vars"):
                return False
            if definition.get("url") or definition.get("cwd"):
                return False
            command = definition.get("command")
            arguments = command if isinstance(command, list) else [command, *definition.get("args", [])]
            if len(arguments) != 4 or arguments[:3] != [sys.executable, "mcp", "--access-file"]:
                return False
            access_file = Path(arguments[3])
            if access_file.parent.resolve() != (state_dir / "agents").resolve():
                return False
            access = read_private_json(access_file, maximum=16384)
            if access.get("state_dir") != str(state_dir):
                return False
            if access.get("id") != access_file.stem:
                return False
            authorized = request(state_dir, "GET", "/api/agent/status", token=access["token"], timeout=0.3)
            if authorized.get("id") != access["id"]:
                return False
            expected = {
                "adr_history": "history", "adr_context": "context", "adr_vault": "vault",
                "adr_vault_env": "execution",
                "adr": "agent",
            }[server]
            if authorized.get("kind") != expected:
                return False
            grant_ids.add(access["id"])
        return next(iter(grant_ids)) if len(grant_ids) == 1 else False
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, AttributeError):
        return False
