"""Managed harness hooks with backups, cached policy, and bounded execution."""

import hashlib
import json
import os
import re
import shlex
import sys
import threading
from pathlib import Path

from .config import (
    MAX_JSON_BYTES,
    atomic_json,
    canonical,
    command_prefix,
    read_private_json,
    strict_json,
    utcnow,
)
from .credential_activity import NATIVE_SESSION_ID, credential_command, result_run_ids
from .guard import _atomic_bytes, install_guard, publish_target
from .local_client import request
from .mcp_trust import trusted_grant_id
from .policy import DENIAL_REASONS, DIRECT_TOOLS, SHELL_TOOLS, Decision, event_fields, hook_output
from .protection import evaluate_operation
from .secret_guard import VAULT_MESSAGE, check_file, detect_credentials

MARKER = "adr-desktop-file-guard"
HARNESS_LABELS = {
    "claude": "Claude Code",
    "codex": "Codex",
    "opencode": "opencode",
    "copilot": "GitHub Copilot CLI",
}


def configuration_path(harness: str, home: Path | None = None) -> Path:
    explicit_home = home is not None
    home = home or Path.home()
    if harness == "claude":
        return home / ".claude" / "settings.json"
    if harness == "copilot":
        return home / ".copilot" / "hooks" / "adr-desktop.json"
    if harness == "codex":
        root = home / ".codex" if explicit_home else Path(os.environ.get("CODEX_HOME", str(home / ".codex")))
        return root / "hooks.json"
    if harness == "opencode":
        root = (
            home / ".config"
            if explicit_home
            else Path(os.environ.get("XDG_CONFIG_HOME", str(home / ".config")))
        )
        return root / "opencode" / "plugins" / "adr-desktop.js"
    raise ValueError("Unsupported hook harness")


def _is_ours(command: dict) -> bool:
    for key in ("command", "bash"):
        try:
            parts = shlex.split(command.get(key, ""))
            if "--managed-by" in parts and parts[parts.index("--managed-by") + 1] == MARKER:
                return True
        except (ValueError, IndexError, TypeError):
            continue
    return False


def _claude_ours(group: dict) -> bool:
    return any(_is_ours(hook) for hook in group.get("hooks", []) if isinstance(hook, dict))


def install(
    harness: str,
    state_dir: Path,
    home: Path | None = None,
    prefix=None,
    *,
    context_server=None,
    context_root=None,
    server_name="adr_context",
) -> dict:
    if os.name == "nt":
        raise ValueError("Native Windows hook installation is not validated in this preview")
    target = configuration_path(harness, home)
    if target.is_symlink():
        raise ValueError("Hook configuration is a symlink; configure the adapter manually")
    if harness == "opencode":
        guardian = install_guard(state_dir)
        publish_target(state_dir, prefix or command_prefix())
        source = Path(__file__).parent / "adapters" / "opencode.js"
        script = (
            source.read_text()
            .replace("__ADR_BRIDGE_ARGUMENTS__", json.dumps([str(guardian), "opencode", str(state_dir)]))
            .replace("__ADR_CONTEXT_SERVER__", json.dumps(context_server))
            .replace("__ADR_CONTEXT_ROOT__", json.dumps(str(context_root) if context_root else None))
            .replace("__ADR_SERVER_NAME__", json.dumps(server_name))
        )
        previous = target.read_bytes() if target.exists() else None
        receipt = state_dir / "opencode-plugin.json"
        if previous is not None:
            record = read_private_json(receipt) if receipt.exists() else {}
            if record.get("digest") != hashlib.sha256(previous).hexdigest():
                raise ValueError(
                    "The existing opencode plugin was not created by ADR or was edited; it was kept"
                )
        if (target.read_bytes() if target.exists() else None) != previous:
            raise ValueError("The opencode plugin changed during installation; retry")
        _atomic_bytes(target, script.encode(), 0o600)
        atomic_json(receipt, {"path": str(target), "digest": hashlib.sha256(script.encode()).hexdigest()})
        return {"harness": harness, "path": str(target), "backup": None}
    old = target.read_bytes() if target.exists() else None
    config = strict_json(old, max_bytes=1024 * 1024) if old is not None else {}
    if not isinstance(config, dict):
        raise ValueError("Existing hook configuration is not a JSON object")
    guardian = install_guard(state_dir)
    publish_target(state_dir, prefix or command_prefix())
    command = shlex.join([str(guardian), harness, str(state_dir), "--managed-by", MARKER])
    hooks = config.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError("Existing hooks field is not an object")
    key = "PreToolUse" if harness in ("claude", "codex") else "preToolUse"
    current = hooks.setdefault(key, [])
    if not isinstance(current, list) or not all(isinstance(item, dict) for item in current):
        raise ValueError("Existing pre-tool hooks have an unsupported shape")
    if harness in ("claude", "codex"):
        updated = []
        for group in current:
            if _claude_ours(group):
                preserved = [hook for hook in group.get("hooks", []) if not _is_ours(hook)]
                if preserved:
                    updated.append({**group, "hooks": preserved})
            else:
                updated.append(group)
        updated.append(
            {
                "matcher": ".*",
                "hooks": [
                    {
                        "type": "command",
                        "command": command,
                        "timeout": 130 if harness == "codex" else 10,
                    }
                ],
            }
        )
    else:
        config["version"] = 1
        updated = [item for item in current if not _is_ours(item)]
        updated.append(
            {
                "type": "command",
                "bash": command,
                "timeoutSec": 130,
            }
        )
    hooks[key] = updated
    if harness in ("claude", "codex"):
        post = hooks.setdefault("PostToolUse", [])
        if not isinstance(post, list) or not all(isinstance(group, dict) for group in post):
            raise ValueError("Existing post-tool hooks have an unsupported shape")
        preserved = []
        for group in post:
            if _claude_ours(group):
                others = [hook for hook in group.get("hooks", []) if not _is_ours(hook)]
                if others:
                    preserved.append({**group, "hooks": others})
            else:
                preserved.append(group)
        post_command = shlex.join([str(guardian), harness, str(state_dir), "post", "--managed-by", MARKER])
        preserved.append(
            {"matcher": ".*", "hooks": [{"type": "command", "command": post_command, "timeout": 10}]}
        )
        hooks["PostToolUse"] = preserved
        origin_file = state_dir / f"prompt-hook-origin-{harness}.json"
        origin = read_private_json(origin_file) if origin_file.exists() else {}
        previous_prompt = hooks.get("UserPromptSubmit", [])
        if not isinstance(previous_prompt, list):
            raise ValueError("Existing prompt hooks have an unsupported shape")
        if origin.get("path") != str(target) or not any(
            isinstance(group, dict) and _claude_ours(group)
            for group in previous_prompt
        ):
            atomic_json(origin_file, {"path": str(target), "had_key": "UserPromptSubmit" in hooks})
        groups = hooks.setdefault("UserPromptSubmit", [])
        if not isinstance(groups, list) or not all(isinstance(group, dict) for group in groups):
            raise ValueError("Existing prompt hooks have an unsupported shape")
        prompt_groups = []
        for group in groups:
            if _claude_ours(group):
                others = [hook for hook in group.get("hooks", []) if not _is_ours(hook)]
                if others:
                    prompt_groups.append({**group, "hooks": others})
            else:
                prompt_groups.append(group)
        prompt_command = shlex.join([
            str(guardian), harness, str(state_dir), "prompt", "--managed-by", MARKER,
        ])
        prompt_groups.append({"hooks": [{
            "type": "command", "command": prompt_command, "timeout": 5,
            "statusMessage": "ADR: check prompt for credentials",
        }]})
        hooks["UserPromptSubmit"] = prompt_groups
    backup = None
    if old is not None:
        backup = state_dir / "backups" / f"{harness}-{hashlib.sha256(old).hexdigest()[:16]}.json"
        if not backup.exists():
            atomic_json(backup, {"path": str(target), "original": old.decode("utf-8"), "saved_at": utcnow()})
    # Reject a concurrent edit instead of replacing a newer vendor/user setting.
    if (target.read_bytes() if target.exists() else None) != old:
        raise ValueError("Hook settings changed during installation; retry")
    atomic_json(target, config)
    return {"harness": harness, "path": str(target), "backup": str(backup) if backup else None}


def uninstall(harness: str, state_dir: Path, home: Path | None = None) -> dict:
    target = configuration_path(harness, home)
    if not target.exists():
        return {"removed": False, "path": str(target)}
    if target.is_symlink():
        raise ValueError("Refusing to edit a symlinked hook configuration")
    old = target.read_bytes()
    if harness == "opencode":
        receipt = state_dir / "opencode-plugin.json"
        record = read_private_json(receipt) if receipt.exists() else {}
        if record.get("digest") != hashlib.sha256(old).hexdigest():
            raise ValueError("ADR's opencode plugin was edited; remove or review it manually")
        backup = state_dir / "backups" / f"opencode-{hashlib.sha256(old).hexdigest()[:16]}.json"
        atomic_json(backup, {"path": str(target), "original": old.decode(), "saved_at": utcnow()})
        if target.read_bytes() != old:
            raise ValueError("The opencode plugin changed during removal; retry")
        target.unlink()
        return {"removed": True, "path": str(target), "backup": str(backup)}
    config = strict_json(old, max_bytes=1024 * 1024)
    if not isinstance(config, dict) or not isinstance(config.get("hooks", {}), dict):
        raise ValueError("Existing hook configuration has an unsupported shape")
    key = "PreToolUse" if harness in ("claude", "codex") else "preToolUse"
    groups = config.get("hooks", {}).get(key, [])
    if not isinstance(groups, list) or not all(isinstance(item, dict) for item in groups):
        raise ValueError("Existing pre-tool hooks have an unsupported shape")
    if harness in ("claude", "codex"):
        remaining = []
        for group in groups:
            if _claude_ours(group):
                preserved = [hook for hook in group.get("hooks", []) if not _is_ours(hook)]
                if preserved:
                    remaining.append({**group, "hooks": preserved})
            else:
                remaining.append(group)
    else:
        remaining = [item for item in groups if not _is_ours(item)]
    changed = remaining != groups
    if harness in ("claude", "codex"):
        for event_name in ("PostToolUse", "UserPromptSubmit"):
            post = config.get("hooks", {}).get(event_name, [])
            if not isinstance(post, list) or not all(isinstance(group, dict) for group in post):
                raise ValueError("Existing hooks have an unsupported shape")
            post_remaining = []
            for group in post:
                others = (
                    [hook for hook in group.get("hooks", []) if not _is_ours(hook)]
                    if _claude_ours(group)
                    else None
                )
                if others is None:
                    post_remaining.append(group)
                elif others:
                    post_remaining.append({**group, "hooks": others})
            changed = changed or post_remaining != post
            if post_remaining != post:
                origin_file = state_dir / f"prompt-hook-origin-{harness}.json"
                origin = read_private_json(origin_file) if origin_file.exists() else {}
                if (
                    event_name == "UserPromptSubmit" and not post_remaining
                    and origin.get("path") == str(target) and origin.get("had_key") is False
                ):
                    config["hooks"].pop(event_name, None)
                else:
                    config["hooks"][event_name] = post_remaining
    if changed:
        config["hooks"][key] = remaining
        if target.read_bytes() != old:
            raise ValueError("Hook settings changed during removal; retry")
        atomic_json(target, config)
    return {"removed": changed, "path": str(target)}


def installed(harness: str, home: Path | None = None, *, phase="pre", state_dir: Path | None = None) -> bool:
    if phase == "prompt" and harness not in ("claude", "codex"):
        return False
    if state_dir is not None and harness != "opencode":
        from .agent_plugins import configured

        if configured(state_dir, harness):
            if phase == "prompt":
                from .agent_plugins import _bundle_root

                config = read_private_json(_bundle_root(state_dir, harness) / "hooks/hooks.json")
                return bool(config.get("hooks", {}).get("UserPromptSubmit"))
            return phase == "pre" or harness != "copilot"
    try:
        if harness == "opencode":
            source = configuration_path(harness, home).read_bytes()
            if state_dir is not None:
                record = read_private_json(state_dir / "opencode-plugin.json")
                if record.get("digest") != hashlib.sha256(source).hexdigest():
                    return False
            return source.startswith(b"// ADR managed plugin: adr-desktop-file-guard")
        if phase == "post" and harness == "copilot":
            return False
        config = strict_json(configuration_path(harness, home).read_bytes(), max_bytes=1024 * 1024)
        key = (
            "UserPromptSubmit" if phase == "prompt" else "PostToolUse"
            if phase == "post"
            else ("PreToolUse" if harness in ("claude", "codex") else "preToolUse")
        )
        groups = config.get("hooks", {}).get(key, [])
        commands = [
            command
            for group in groups
            for command in (group.get("hooks", []) if harness in ("claude", "codex") else [group])
            if isinstance(command, dict) and _is_ours(command)
        ]
        if state_dir is None:
            return bool(commands)
        return any(
            str(state_dir) in shlex.split(command.get("command", command.get("bash", "")))
            for command in commands
        )
    except (OSError, ValueError, AttributeError, TypeError):
        return False


def _current_hook_policy(state_dir: Path, harness: str):
    snapshot = read_private_json(state_dir / "policy.json", maximum=1024 * 1024)
    if not isinstance(snapshot, dict) or snapshot.get("version") != 1:
        raise ValueError("Unsupported policy version")
    from .agent_plugins import plugin_root

    root = plugin_root(state_dir, harness)
    if root:
        snapshot.setdefault("control_paths", []).append([str(root), "directory"])
    return snapshot


def run_hook(state_dir: Path, harness: str, guard_protocol=False, phase="pre") -> int:
    """Return a native permission decision even if the local UI/daemon is stopped."""
    finished = threading.Event()
    emitted = threading.Event()
    awaiting_approval = threading.Event()
    output_lock = threading.Lock()
    timeout_decision = Decision(
        "deny", DENIAL_REASONS["safety_timeout"], phase=phase, reason_code="safety_timeout"
    )

    def watchdog():
        if not finished.wait(3):
            if awaiting_approval.is_set() and not finished.wait(115):
                pass
            elif finished.is_set():
                return
            with output_lock:
                if not finished.is_set():
                    if not emitted.is_set():
                        raw = (
                            b"deny:safety_timeout\n"
                            if guard_protocol
                            else (json.dumps(hook_output(timeout_decision, harness)).encode() + b"\n")
                        )
                        os.write(sys.stdout.fileno(), raw)
                    os._exit(0)

    threading.Thread(target=watchdog, daemon=True).start()
    failure_code = "invalid_request"
    try:
        event = strict_json(sys.stdin.buffer.read(MAX_JSON_BYTES + 1))
        if not isinstance(event, dict):
            raise ValueError("Expected a hook event")
        failure_code = "policy_unavailable"
        snapshot = _current_hook_policy(state_dir, harness)
        failure_code = "invalid_request"
        alias_file = state_dir / "vault-aliases.json"
        aliases = read_private_json(alias_file, maximum=16384).get("names", []) if alias_file.exists() else []
        if not isinstance(aliases, list) or len(aliases) > 64 or any(
            not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", name)
            for name in aliases
        ):
            raise ValueError("Invalid vault alias metadata")
        if phase == "post":
            tool, _, _, session = event_fields(event, harness)
            kinds = (
                detect_credentials(event.get("tool_response", {})) if snapshot.get("enabled", True) else []
            )
            unavailable = False
            if aliases and harness in ("claude", "codex", "opencode"):
                try:
                    auth = read_private_json(state_dir / "hook-access.json", maximum=16384)
                    checked = request(
                        state_dir, "POST", "/api/hooks/output-check", token=auth["token"],
                        payload={"harness": harness, "text": canonical(event.get("tool_response", {}))},
                        timeout=2.5,
                    )
                    if checked.get("unavailable") or not isinstance(checked.get("blocked"), bool):
                        unavailable = True
                    elif checked.get("blocked") is True:
                        kinds.append("Saved credential")
                except Exception:
                    unavailable = True
            decision = Decision(
                "deny" if kinds or unavailable else "pass",
                VAULT_MESSAGE if kinds else DENIAL_REASONS["credential_check_unavailable"]
                if unavailable else "Result checked",
                tool=tool,
                session_id=session,
                credential_kinds=kinds,
                phase="post",
                reason_code="credential_check_unavailable" if unavailable and not kinds else "no_match",
            )
        else:
            decision = evaluate_operation(event, harness, snapshot, state_dir=state_dir)
            if decision.decision != "deny" and decision.tool.lower() in SHELL_TOOLS and aliases:
                _, arguments, _, _ = event_fields(event, harness)
                command = arguments.get("command", arguments.get("cmd", ""))
                if isinstance(command, str) and any(
                    re.search(
                        r"\$(?:\{" + re.escape(name) + r"(?:\}|:)|" + re.escape(name) + r"\b)",
                        command,
                    )
                    or re.search(
                        r"""(?:getenv|environ|process\.env)[^\n]{0,20}["']?"""
                        + re.escape(name) + r"\b", command,
                    )
                    for name in aliases
                ):
                    decision.decision = "deny"
                    decision.reason_code = "vault_execution_required"
                    decision.reason = DENIAL_REASONS["vault_execution_required"]
            if decision.decision != "deny" and snapshot.get("enabled", True):
                kinds = []
                if decision.tool.lower() in DIRECT_TOOLS:
                    for path in decision.paths:
                        kinds.extend(check_file(Path(path)))
                if kinds:
                    decision.decision, decision.reason = "deny", VAULT_MESSAGE
                    decision.credential_kinds = sorted(set(kinds))
            if decision.decision == "ask" and harness != "claude":
                if len(canonical(event).encode()) > 16384 or detect_credentials(event):
                    decision.decision, decision.reason = (
                        "deny",
                        "ADR requires a smaller, credential-free request",
                    )
                    decision.reason_code = "invalid_request"
                else:
                    decision.approval_requested = True
                    awaiting_approval.set()
                    if guard_protocol:
                        print("waiting", flush=True)
                    try:
                        auth = read_private_json(state_dir / "hook-access.json", maximum=16384)
                        response = request(
                            state_dir,
                            "POST",
                            "/api/hooks/approve",
                            token=auth["token"],
                            payload={"harness": harness, "event": event},
                            timeout=110,
                        )
                        allowed = response.get("allowed") is True
                        code = response.get("reason_code")
                        if allowed and code not in ("approved", "no_match"):
                            allowed, code = False, "invalid_request"
                        elif not allowed and code not in DENIAL_REASONS:
                            code = "app_unavailable"
                    except Exception:
                        allowed = False
                        code = "app_unavailable"
                    if allowed:
                        owner_approved = code == "approved"
                        # The daemon has a different process environment and
                        # the policy may have changed after its final check.
                        # Recheck every positive response here, using the
                        # original harness context and a fresh offline policy.
                        failure_code = "policy_unavailable"
                        snapshot = _current_hook_policy(state_dir, harness)
                        current = evaluate_operation(event, harness, snapshot, state_dir=state_dir)
                        failure_code = "invalid_request"
                        current.approval_requested = owner_approved
                        if current.decision != "deny" and snapshot.get("enabled", True):
                            kinds = []
                            if current.tool.lower() in DIRECT_TOOLS:
                                for path in current.paths:
                                    kinds.extend(check_file(Path(path)))
                            if kinds:
                                current.decision, current.reason = "deny", VAULT_MESSAGE
                                current.credential_kinds = sorted(set(kinds))
                        if current.decision == "ask" and not owner_approved:
                            # An automatic no-match pass was not an owner's
                            # approval of a rule added while this was pending.
                            current.decision = "deny"
                            current.reason_code = "invalid_request"
                            current.reason = DENIAL_REASONS["invalid_request"]
                        elif current.decision != "deny":
                            current.decision = "pass"
                            current.reason_code = "approved" if owner_approved else "no_match"
                            current.reason = (
                                "Allowed once in ADR" if owner_approved else "No protected path matched"
                            )
                        decision = current
                    else:
                        decision.decision = "deny"
                        decision.reason_code = code
                        decision.reason = DENIAL_REASONS[code]
    except Exception:
        decision = Decision(
            "deny",
            DENIAL_REASONS[failure_code],
            phase=phase,
            reason_code=failure_code,
        )
    with output_lock:
        protocol = "secret" if decision.credential_kinds else decision.decision
        if protocol == "deny" and decision.reason_code in DENIAL_REASONS:
            protocol = f"deny:{decision.reason_code}"
        print(protocol if guard_protocol else json.dumps(hook_output(decision, harness)), flush=True)
        emitted.set()
    # Enforcement is already decided; offline audit delivery must not block it.
    try:
        auth = read_private_json(state_dir / "hook-access.json", maximum=16384)
        request(
            state_dir,
            "POST",
            "/api/hooks/events",
            token=auth["token"],
            payload={"harness": harness, **decision.as_dict()},
            timeout=0.3,
        )
    except Exception:
        pass
    # Attribution is best-effort, after enforcement. Match the actual MCP result
    # receipt to this hook's session; never infer from another recent tool call.
    try:
        if phase == "post" and credential_command(event.get("tool_name")):
            identifiers = result_run_ids(event.get("tool_response"))
            session_id = event.get("session_id")
            if len(identifiers) == 1 and isinstance(session_id, str) and NATIVE_SESSION_ID.fullmatch(
                session_id
            ):
                grant_id = trusted_grant_id(event, harness, state_dir)
                if grant_id:
                    request(
                        state_dir, "POST", "/api/hooks/credential-use", token=auth["token"],
                        payload={"run_id": next(iter(identifiers)), "grant_id": grant_id,
                                 "harness": harness, "session_id": session_id},
                        timeout=0.3,
                    )
    except Exception:
        pass
    finished.set()
    return 0
