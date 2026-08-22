"""Skills, commands, hooks, plugins, rules and instruction files.

The programmable surface of an installed agent. An inventory that records only
that Claude Code is installed cannot say what somebody taught it to do, and the
teaching is where the risk lives: a hook is arbitrary code on every turn, a
plugin can ship its own MCP servers, and an instruction file steers every
session in the repository.

Bodies are never captured. A skill body holds business context and is not
inventory data; the path, the front matter and the line count are.
"""

import posixpath
import re
from typing import Any, Dict, List, Optional, Tuple

from ..base_probe import BaseProbe, Observation
from ..env import DiscoveryEnv
from ..redact import redact_url

PROJECT_ROOTS = ("~/dev", "~/src", "~/workspace", "~/code")

#: (relative path, kind, host application) for personal-scope surfaces.
PERSONAL_SURFACES = (
    ("~/.claude/skills", "skill", "claude-code"),
    ("~/.claude/commands", "command", "claude-code"),
    ("~/.claude/output-styles", "output_style", "claude-code"),
    ("~/.claude/agents", "agent_definition", "claude-code"),
    ("~/.codex/prompts", "command", "codex"),
    ("~/.gemini/commands", "command", "gemini-cli"),
    ("~/.cursor/agents", "agent_definition", "cursor"),
    ("~/.codeium/windsurf/agents", "agent_definition", "windsurf"),
)

#: Instruction files, by filename. AGENTS.md is read by thirty-plus agents;
#: the rest are one vendor each.
INSTRUCTION_FILES = {
    "AGENTS.md": ("agents.md", None),
    "CLAUDE.md": ("claude.md", "claude-code"),
    "GEMINI.md": ("gemini.md", "gemini-cli"),
    "copilot-instructions.md": ("copilot-instructions", "copilot"),
    ".cursorrules": ("cursorrules-legacy", "cursor"),
    ".windsurfrules": ("windsurfrules", "windsurf"),
}

#: Settings files that can declare hooks, in precedence order.
SETTINGS_SCOPES = (("~/.claude/settings.json", "personal"),
                   (".claude/settings.json", "project"),
                   (".claude/settings.local.json", "project_local"))

#: Hooks fire on lifecycle events. The list keeps growing, so an unrecognized
#: event is reported as unknown rather than dropped.
KNOWN_HOOK_EVENTS = frozenset({
    "SessionStart", "Setup", "SessionEnd", "UserPromptSubmit", "UserPromptExpansion",
    "Stop", "StopFailure", "PreToolUse", "PostToolUse", "PostToolUseFailure", "PostToolBatch",
    "PermissionRequest", "PermissionDenied", "SubagentStart", "SubagentStop", "TeammateIdle",
    "TaskCreated", "TaskCompleted", "FileChanged", "CwdChanged", "ConfigChange",
    "InstructionsLoaded", "WorktreeCreate", "WorktreeRemove", "Notification", "MessageDisplay",
    "PreCompact", "PostCompact", "Elicitation", "ElicitationResult",
})

#: Body content is not captured, but a few shapes inside it are risk signals.
NETWORK_CALL = re.compile(r"(curl|wget|fetch|requests\.(get|post))\s[^\n]*?(https?://[^\s'\"]+)")
OUTSIDE_WRITE = re.compile(r"(cp|mv|rsync|scp)\s[^\n]*\s(~/Library|/Volumes/|//|/etc/)")

MAX_BODY_BYTES = 200_000


class AgentArtifactProbe(BaseProbe):
    name = "agent_artifact"

    def collect(self, env: DiscoveryEnv) -> List[Observation]:
        out: List[Observation] = []
        out.extend(self._personal_surfaces(env))
        out.extend(self._plugins(env))
        out.extend(self._projects(env))
        out.extend(self._hooks(env, env.expand("~/.claude/settings.json"), "personal"))
        out.extend(self._personal_instructions(env))
        return out

    def _personal_instructions(self, env: DiscoveryEnv) -> List[Observation]:
        """Instruction files that apply to every project, not just one."""
        out: List[Observation] = []
        for template, name in (("~/.claude/CLAUDE.md", "CLAUDE.md"),
                               ("~/.codex/AGENTS.md", "AGENTS.md"),
                               ("~/.gemini/GEMINI.md", "GEMINI.md")):
            logical = env.expand(template)
            if not env.exists(logical):
                continue
            fmt, host = INSTRUCTION_FILES[name]
            out.append(self._instruction_file(env, logical, fmt, host, "personal"))
        return out

    # -- skills, commands, styles, agent definitions ----------------------

    def _personal_surfaces(self, env: DiscoveryEnv) -> List[Observation]:
        out: List[Observation] = []
        for template, kind, host in PERSONAL_SURFACES:
            base = env.expand(template)
            out.extend(self._surface(env, base, kind, host, "personal"))
        return out

    def _surface(self, env: DiscoveryEnv, base: str, kind: str, host: str, scope: str,
                 plugin: Optional[str] = None) -> List[Observation]:
        if not env.is_dir(base):
            return []
        out: List[Observation] = []
        if kind == "skill":
            for name in env.listdir(base):
                folder = posixpath.join(base, name)
                manifest = posixpath.join(folder, "SKILL.md")
                if not env.exists(manifest):
                    continue
                out.append(self._skill(env, manifest, folder, name, host, scope, plugin))
            return out
        for logical in self._markdown_files(env, base):
            name = self._command_name(base, logical)
            out.append(self._document(env, logical, kind, name, host, scope, plugin))
        return out

    def _markdown_files(self, env: DiscoveryEnv, base: str) -> List[str]:
        """Markdown one or two levels down; a directory is not itself a command."""
        found = []
        for logical, path in env.walk(base, max_depth=2):
            try:
                if path.is_file() and logical.endswith(".md"):
                    found.append(logical)
            except OSError:
                continue
        return sorted(found)

    def _command_name(self, base: str, logical: str) -> str:
        relative = logical[len(base):].strip("/")
        return relative[:-3].replace("/", ":") if relative.endswith(".md") else relative

    def _skill(self, env, manifest, folder, name, host, scope, plugin) -> Observation:
        meta, line_count, body = self._front_matter(env, manifest)
        extra = {"scope": scope, "host_app": host, "line_count": line_count,
                 "description": meta.get("description"), "risk_factors": [],
                 "plugin": plugin}
        helpers = self._helpers(env, folder)
        if helpers:
            # A skill is not only prose; it can carry code.
            extra["risk_factors"].append("bundled_executable")
            extra["helpers"] = helpers
        hosts = self._network_hosts(body)
        if hosts:
            extra["risk_factors"].append("external_network")
            extra["network_hosts"] = hosts
        if meta.get("_malformed"):
            self.error(env, manifest, "malformed front matter")
        return Observation(
            probe=self.name, channel="filesystem", kind="skill",
            name=meta.get("name") or name, path=manifest, matched_on="skill:%s" % scope,
            version=meta.get("version"), install_root=folder, install_method="agent_artifact",
            owner=_owner(manifest, env), extra=extra, confidence=0.6,
        )

    def _helpers(self, env: DiscoveryEnv, folder: str) -> List[str]:
        found = []
        for logical, path in env.walk(folder, max_depth=2):
            if logical.endswith(("SKILL.md", ".md")):
                continue
            try:
                if path.is_file():
                    found.append(posixpath.basename(logical))
            except OSError:
                continue
        return sorted(found)

    def _document(self, env, logical, kind, name, host, scope, plugin) -> Observation:
        meta, line_count, body = self._front_matter(env, logical)
        extra = {"scope": scope, "host_app": host, "line_count": line_count,
                 "description": meta.get("description"), "risk_factors": [], "plugin": plugin}
        if kind == "agent_definition":
            tools = meta.get("tools")
            extra["tools"] = tools
            extra["model"] = meta.get("model")
            if tools and ("*" in str(tools) or "all" in str(tools).lower()):
                extra["risk_factors"].append("unrestricted_tools")
        hosts = self._network_hosts(body)
        if hosts:
            extra["risk_factors"].append("external_network")
            extra["network_hosts"] = hosts
        return Observation(
            probe=self.name, channel="filesystem", kind=kind,
            name=meta.get("name") or name, path=logical, matched_on="%s:%s" % (kind, scope),
            version=meta.get("version"), install_root=posixpath.dirname(logical),
            install_method="agent_artifact", owner=_owner(logical, env),
            extra=extra, confidence=0.6,
        )

    def _front_matter(self, env: DiscoveryEnv, logical: str) -> Tuple[Dict[str, Any], int, str]:
        """Parse the YAML header. The body is measured, never captured."""
        result = env.read(logical, limit=MAX_BODY_BYTES)
        if not result:
            self.error(env, logical, result.error or "unreadable")
            return {}, 0, ""
        text = result.text
        meta: Dict[str, Any] = {}
        body = text
        if text.startswith("---"):
            end = text.find("\n---", 3)
            if end == -1:
                meta["_malformed"] = True
            else:
                for line in text[3:end].splitlines():
                    if ":" in line:
                        key, _, value = line.partition(":")
                        meta[key.strip()] = value.strip().strip('"').strip("'")
                body = text[end + 4:]
        return meta, len(text.splitlines()), body

    def _network_hosts(self, body: str) -> List[str]:
        return sorted({redact_url(match.group(3)) for match in NETWORK_CALL.finditer(body or "")})

    # -- plugins ----------------------------------------------------------

    def _plugins(self, env: DiscoveryEnv) -> List[Observation]:
        base = env.expand("~/.claude/plugins")
        if not env.is_dir(base):
            return []
        out: List[Observation] = []
        for name in env.listdir(base):
            folder = posixpath.join(base, name)
            out.extend(self._plugin(env, folder, name))
        return out

    def _plugin(self, env: DiscoveryEnv, folder: str, name: str) -> List[Observation]:
        manifest = None
        for candidate in (".claude-plugin/plugin.json", "plugin.json"):
            path = posixpath.join(folder, candidate)
            if env.exists(path):
                manifest = self.read_json(env, path)
                manifest_path = path
                break
        if not isinstance(manifest, dict):
            return []
        source = manifest.get("source") or manifest.get("marketplace")
        factors = []
        corporate = env.policy.get("plugin_registries") or []
        if source and corporate and not any(str(source).startswith(entry) for entry in corporate):
            factors.append("third_party_marketplace")
        elif source and not corporate:
            factors.append("third_party_marketplace")
        out = [Observation(
            probe=self.name, channel="filesystem", kind="plugin",
            name=manifest.get("name", name), path=manifest_path, matched_on="plugin",
            version=manifest.get("version"), install_root=folder,
            install_method="agent_artifact", owner=_owner(folder, env),
            extra={"author": manifest.get("author"), "source": source,
                   "risk_factors": factors, "scope": "plugin"},
            confidence=0.6,
        )]
        plugin_name = manifest.get("name", name)
        # A plugin bundles everything an agent can be extended with.
        out.extend(self._surface(env, posixpath.join(folder, "skills"), "skill",
                                 "claude-code", "plugin", plugin_name))
        out.extend(self._surface(env, posixpath.join(folder, "agents"), "agent_definition",
                                 "claude-code", "plugin", plugin_name))
        out.extend(self._surface(env, posixpath.join(folder, "commands"), "command",
                                 "claude-code", "plugin", plugin_name))
        out.extend(self._hooks(env, posixpath.join(folder, "hooks", "hooks.json"),
                               "plugin", plugin_name))
        return out

    # -- hooks ------------------------------------------------------------

    def _hooks(self, env: DiscoveryEnv, settings_path: str, scope: str,
               plugin: Optional[str] = None) -> List[Observation]:
        if not env.exists(settings_path):
            return []
        data = self.read_json(env, settings_path)
        if not isinstance(data, dict):
            return []
        out: List[Observation] = []
        for event, groups in (data.get("hooks") or {}).items():
            for group in groups if isinstance(groups, list) else []:
                matcher = group.get("matcher") if isinstance(group, dict) else None
                for handler in (group.get("hooks") or []) if isinstance(group, dict) else []:
                    out.append(self._hook(env, settings_path, event, matcher, handler,
                                          scope, plugin))
        return out

    def _hook(self, env, settings_path, event, matcher, handler, scope, plugin) -> Observation:
        handler_type = handler.get("type", "command")
        command = str(handler.get("command", ""))
        # Every hook runs on an agent lifecycle event, which is what makes this
        # the richest persistence surface an agent has.
        factors = ["executes_on_every_turn"]
        flags = []
        extra: Dict[str, Any] = {"event": event, "matcher": matcher, "handler": handler_type,
                                 "scope": scope, "plugin": plugin, "risk_factors": factors,
                                 "flags": flags}
        if event not in KNOWN_HOOK_EVENTS:
            extra["event_known"] = False
        if handler_type == "http":
            # An http hook sends agent activity off the machine by design.
            factors.append("external_egress")
            extra["destination"] = redact_url(str(handler.get("url", "")))
        elif handler_type == "agent":
            factors.append("spawns_subagent")
        elif handler_type == "mcp_tool":
            extra["server"] = handler.get("server") or handler.get("tool")
        elif command:
            target = env.expand(command.split()[0]) if command else ""
            extra["target"] = target
            if target.startswith("/") and not env.exists(target):
                flags.append("command_missing")
            else:
                body = env.read(target, limit=MAX_BODY_BYTES)
                if body and OUTSIDE_WRITE.search(body.text):
                    factors.append("writes_outside_workspace")
        return Observation(
            probe=self.name, channel="config", kind="hook",
            name="%s:%s" % (event, matcher or "*"), path=settings_path,
            matched_on="hook:%s" % scope, install_root=posixpath.dirname(settings_path),
            install_method="agent_artifact", owner=_owner(settings_path, env),
            extra=extra, confidence=0.6,
        )

    # -- project scope ----------------------------------------------------

    def _projects(self, env: DiscoveryEnv) -> List[Observation]:
        out: List[Observation] = []
        for root in PROJECT_ROOTS:
            base = env.expand(root)
            for project in env.listdir(base):
                folder = posixpath.join(base, project)
                if not env.is_dir(folder):
                    continue
                out.extend(self._project(env, folder))
        return out

    def _project(self, env: DiscoveryEnv, folder: str) -> List[Observation]:
        out: List[Observation] = []
        out.extend(self._surface(env, posixpath.join(folder, ".claude/skills"), "skill",
                                 "claude-code", "project"))
        out.extend(self._surface(env, posixpath.join(folder, ".claude/commands"), "command",
                                 "claude-code", "project"))
        out.extend(self._surface(env, posixpath.join(folder, ".claude/agents"),
                                 "agent_definition", "claude-code", "project"))
        out.extend(self._hooks(env, posixpath.join(folder, ".claude/settings.json"), "project"))
        out.extend(self._hooks(env, posixpath.join(folder, ".claude/settings.local.json"),
                               "project_local"))
        out.extend(self._instructions(env, folder))
        out.extend(self._cursor_rules(env, folder))
        return out

    def _instructions(self, env: DiscoveryEnv, folder: str) -> List[Observation]:
        out: List[Observation] = []
        candidates = [(name, posixpath.join(folder, name)) for name in INSTRUCTION_FILES]
        candidates.append(("copilot-instructions.md",
                           posixpath.join(folder, ".github/copilot-instructions.md")))
        for name, logical in candidates:
            if not env.exists(logical):
                continue
            fmt, host = INSTRUCTION_FILES[name]
            out.append(self._instruction_file(env, logical, fmt, host, "project"))
        return out

    def _instruction_file(self, env, logical, fmt, host, scope) -> Observation:
        result = env.read(logical, limit=MAX_BODY_BYTES)
        imports = _imports(result.text if result else "")
        return Observation(
            probe=self.name, channel="filesystem", kind="instructions",
            name=posixpath.basename(logical), path=logical, matched_on="instructions:%s" % fmt,
            install_root=posixpath.dirname(logical), install_method="agent_artifact",
            owner=_owner(logical, env),
            extra={"format": fmt, "host_app": host, "scope": scope,
                   "line_count": len((result.text if result else "").splitlines()),
                   "imports": imports, "risk_factors": []},
            confidence=0.55,
        )

    def _cursor_rules(self, env: DiscoveryEnv, folder: str) -> List[Observation]:
        base = posixpath.join(folder, ".cursor/rules")
        if not env.is_dir(base):
            return []
        out: List[Observation] = []
        for name in env.listdir(base):
            if not name.endswith((".mdc", ".md")):
                continue
            logical = posixpath.join(base, name)
            meta, line_count, _ = self._front_matter(env, logical)
            out.append(Observation(
                probe=self.name, channel="filesystem", kind="rules", name=name,
                path=logical, matched_on="instructions:cursor-rules",
                install_root=base, install_method="agent_artifact", owner=_owner(logical, env),
                extra={"format": "cursor-rules", "host_app": "cursor", "scope": "project",
                       "globs": meta.get("globs"), "line_count": line_count,
                       "risk_factors": []},
                confidence=0.55,
            ))
        return out


def _imports(text: str) -> List[str]:
    """Instruction files import one another; the graph is part of the inventory."""
    return sorted({match.group(1) for match in
                   re.finditer(r"@([A-Za-z0-9_./-]+\.md)", text or "")})


def _owner(path: str, env: DiscoveryEnv) -> str:
    parts = [part for part in str(path).split("/") if part]
    if len(parts) >= 2 and parts[0] in ("Users", "home"):
        return parts[1]
    return env.user
