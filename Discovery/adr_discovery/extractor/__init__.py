"""M3 -- turns a located surface into declarations.

The least glamorous module, and the one where hostile or merely sloppy
input does the most damage. Two things are true of every return value: one
malformed record never removes its valid siblings, and the count reported
is the count that was in the file.
"""

from __future__ import annotations

import re
import shlex
from types import MappingProxyType

from ..contracts.records import Candidate, Declaration, ExtractError, Extraction, Kind
from ..redact import rules as redact
from .formats import format_for, parse_bytes
from .formats.workflow import agent_steps, env_names_of
from .isolate import as_args, as_env, as_text, per_record
from .surfaces import SURFACE_NAMES, extract_surface, surface_for

__all__ = ["extract", "SCOPES", "SURFACE_NAMES"]

#: Every settings scope a host application actually loads. Reading two of
#: four and reporting the result as a count is how the hooks probe returned
#: eight of twenty-eight.
SCOPES: tuple[tuple[str, str], ...] = (
    ("user", "settings.json"),
    ("project", ".mcp.json"),
    ("project_local", "settings.local.json"),
    ("plugin", "mcp.json"),
)

#: Declarations are capped per surface; a cap that fires reports the true count.
RECORD_CAP = 500


def extract(gate, candidate: Candidate) -> Extraction:
    """Read one surface and emit the declarations inside it.

    Two shapes of surface reach this function: a config *file* holding
    records, and a *directory* whose members are the records. They share
    the isolation rule and the true-count rule; only the reader differs.
    """
    if candidate.kind == "instruction_file":
        return Extraction(
            declarations=(Declaration(
                kind=Kind.INSTRUCTIONS,
                name=candidate.path.rsplit("/", 1)[-1],
                path=candidate.path,
                scope=_scope_of(candidate.path),
                raw={"surface": Kind.INSTRUCTIONS.value},
            ),),
            declared=1,
        )

    if candidate.kind == "shell_profile":
        return _shell_profile(gate, candidate.path)

    if surface_for(candidate.path) is not None:
        directory = extract_surface(gate, candidate, _scope_of(candidate.path))
        if directory is not None:
            if directory.truncated:
                gate.ledger.truncate(candidate.path, len(directory.declarations), directory.declared)
            return directory
        return Extraction(declared=0)

    fmt = format_for(candidate.path)
    if fmt is None:
        return Extraction(declared=0)

    raw = gate.read_bytes(candidate.path)
    if not raw.ok:
        return Extraction(errors=(ExtractError(candidate.path, None, raw.reason),), declared=0)

    try:
        document = parse_bytes(raw.value, fmt)
    except Exception as exc:
        if "/.mcpb/" in candidate.path and candidate.path.endswith("/manifest.json"):
            return Extraction(
                declarations=(Declaration(
                    kind=Kind.MCP_BUNDLE,
                    name=candidate.path.rstrip("/").rsplit("/", 2)[-2],
                    path=candidate.path,
                    scope=_scope_of(candidate.path),
                    raw={"flags": ("malformed",), "surface": Kind.MCP_BUNDLE.value},
                ),),
                errors=(ExtractError(candidate.path, None, f"{type(exc).__name__}: {exc}"),),
                declared=1,
            )
        gate.ledger.probe("extractor", "degraded", f"{candidate.path}: {type(exc).__name__}")
        return Extraction(
            errors=(ExtractError(candidate.path, None, f"{type(exc).__name__}: {exc}"),),
            declared=0,
        )

    if not isinstance(document, dict):
        return Extraction(
            errors=(ExtractError(candidate.path, None, "document root is not a mapping"),),
            declared=0,
        )

    scope = _scope_of(candidate.path)

    if fmt == "workflow":
        return _workflow(document, candidate.path)

    servers = _server_block(document)
    chunks: list[Extraction] = []
    if servers:
        records = list(servers.items())
        chunks.append(per_record(
            records,
            lambda i, rec: _server(rec, candidate.path, scope),
            candidate.path,
            cap=RECORD_CAP,
        ))

    hooks = list(_hook_records(document))
    if hooks:
        chunks.append(per_record(
            hooks,
            lambda i, rec: _hook(rec, candidate.path, scope, i),
            candidate.path,
            cap=RECORD_CAP,
        ))

    if not chunks:
        return Extraction(declared=0)

    result = Extraction(
        declarations=tuple(d for chunk in chunks for d in chunk.declarations),
        errors=tuple(e for chunk in chunks for e in chunk.errors),
        declared=sum(chunk.declared for chunk in chunks),
        truncated=any(chunk.truncated for chunk in chunks),
    )

    if result.truncated:
        gate.ledger.truncate(candidate.path, len(result.declarations), result.declared)
    return result


def _hook_records(document: dict):
    """Yield each executable hook independently, preserving its event."""
    block = document.get("hooks")
    if not isinstance(block, dict):
        return
    for event, matchers in block.items():
        if not isinstance(matchers, list):
            continue
        for matcher in matchers:
            if not isinstance(matcher, dict):
                continue
            nested = matcher.get("hooks")
            if not isinstance(nested, list):
                continue
            for hook in nested:
                if isinstance(hook, dict) and hook.get("type") == "command" and hook.get("command"):
                    yield str(event), hook


def _hook(record, path: str, scope: str, index: int) -> Declaration:
    event, body = record
    command = as_text(body.get("command"), "command")
    label = {
        "ADR: check file access": "ADR file protection",
        "ADR: check tool output": "ADR output protection",
    }.get(str(body.get("statusMessage", "")), _hook_label(command))
    # A shell command is not one argv word. Passing the whole string to
    # scrub_argv would leave "--token value" operands intact.
    try:
        scrubbed = shlex.join(redact.scrub_argv(shlex.split(command)))
    except ValueError:
        scrubbed = redact.REDACTED
    event_label = _HOOK_EVENTS.get(event, "Agent hook")
    return Declaration(
        kind=Kind.HOOK,
        name=f"{label} · {event_label}",
        path=path,
        scope=scope,
        command=scrubbed,
        raw={"event": event, "surface": Kind.HOOK.value, "hook_id": index, "executable": label},
    )


_HOOK_EVENTS = MappingProxyType({
    "PreToolUse": "Before tool use",
    "PostToolUse": "After tool use",
    "PostToolUseFailure": "After a tool error",
    "UserPromptSubmit": "Before prompt submission",
    "SessionStart": "Session start",
    "SessionEnd": "Session end",
    "Stop": "Agent finished",
    "SubagentStart": "Sub-agent start",
    "SubagentStop": "Sub-agent finished",
    "PreCompact": "Before context compaction",
    "Notification": "Notification",
    "PermissionRequest": "Permission requested",
    "preToolUse": "Before tool use",
    "postToolUse": "After tool use",
})
_HOOK_EXECUTABLE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_HOOK_SCRIPT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\.(?:py|sh|js|mjs|cjs|ps1|rb)$")
_HOOK_INTERPRETERS = frozenset({
    "python", "python3", "node", "ruby", "bash", "sh", "zsh", "pwsh", "powershell",
})


def _hook_label(command: str) -> str:
    """Only the executable/script basename, never flags or their operands."""
    try:
        words = shlex.split(command)
    except ValueError:
        return "Configured command"
    while words and (re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", words[0]) or words[0] == "env"):
        words.pop(0)
    if not words:
        return "Configured command"
    executable = words[0].replace("\\", "/").rsplit("/", 1)[-1]
    if not _HOOK_EXECUTABLE.fullmatch(executable):
        return "Configured command"
    if executable in {"adr-desktop", "ADRCore", "adr-hook", "adr-hook-bridge"}:
        return "ADR protection"
    if executable in _HOOK_INTERPRETERS and len(words) > 1:
        script = words[1].replace("\\", "/").rsplit("/", 1)[-1]
        if _HOOK_SCRIPT.fullmatch(script):
            return script
    return executable


_EXPORT = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=")


def _shell_profile(gate, path: str) -> Extraction:
    """Collect only AI credential variable names, never profile values."""
    raw = gate.read_text(path, limit=256 * 1024)
    if not raw.ok:
        return Extraction(errors=(ExtractError(path, None, raw.reason),), declared=0)
    names = []
    for line in raw.value.splitlines():
        match = _EXPORT.match(line)
        if match and redact.credential_kinds((match.group(1),)):
            names.append(match.group(1))
    if not names:
        return Extraction(declared=0)
    return Extraction(
        declarations=(Declaration(
            kind=Kind.AGENT_PLATFORM,
            name="AI credential environment",
            path=path,
            scope="user",
            env_names=tuple(sorted(set(names))),
            raw={"surface": "shell_profile", "env_names": tuple(sorted(set(names)))},
        ),),
        declared=1,
    )


def _workflow(document: dict, path: str) -> Extraction:
    """An agent arranged to run with no person present."""
    steps = list(agent_steps(document))
    return per_record(
        steps,
        lambda index, record: _ci_agent(record, path),
        path,
        cap=RECORD_CAP,
    )


def _ci_agent(record, path: str) -> Declaration:
    job_name, step, reference, catalog_id = record
    return Declaration(
        kind=Kind.CI_AGENT,
        name=f"{reference} ({job_name})",
        path=path,
        scope="ci",
        command=reference,
        env_names=env_names_of(step),
        raw={"catalog_id": catalog_id, "job": job_name, "unattended": True,
             "transport": "ci"},
    )


def _server_block(document: dict) -> dict:
    """MCP servers live under different keys in different host apps."""
    for key in ("mcpServers", "mcp_servers", "servers", "mcp"):
        block = document.get(key)
        if isinstance(block, dict):
            inner = block.get("servers")
            return inner if isinstance(inner, dict) else block
    return {}


def _server(record: tuple[str, object], path: str, scope: str) -> Declaration:
    name, body = record
    if not isinstance(body, dict):
        raise TypeError(f"server {name!r} must be a mapping, got {type(body).__name__}")

    args = as_args(body.get("args"))
    env = as_env(body.get("env"))
    url = body.get("url")

    return Declaration(
        kind=Kind.MCP_SERVER,
        name=str(name),
        path=path,
        scope=scope,
        command=as_text(body["command"], "command") if "command" in body else None,
        args=redact.scrub_argv(args),
        env_names=redact.env_names(env),
        url=redact.strip_url(as_text(url, "url")) if url is not None else None,
        raw={"transport": body.get("type") or ("http" if url else "stdio")},
    )


def _scope_of(path: str) -> str:
    name = path.rsplit("/", 1)[-1]
    for scope, filename in SCOPES:
        if name == filename:
            return scope
    if path.startswith(("/etc/", "/Library/Application Support/ADR/", "/Library/Application Support/ClaudeCode/")):
        return "enterprise_managed"
    if "/plugins/" in path or "/plugin/" in path:
        return "plugin"
    if "/Library/" in path or "/.config/" in path or path.count("/") <= 3:
        return "user"
    return "project"
