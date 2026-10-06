"""Pre-tool file policy. Hooks are cooperative controls, not a kernel sandbox."""

import io
import os
import platform
import shlex
import unicodedata
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import unquote, urlsplit

DIRECT_TOOLS = {
    "read",
    "write",
    "edit",
    "multiedit",
    "notebookedit",
    "read_file",
    "write_file",
    "edit_file",
    "create_file",
    "view",
    "str_replace",
    "str_replace_editor",
}
SEARCH_TOOLS = {"glob", "grep", "list_dir", "list_directory", "find_files", "search_files"}
SAFE_TOOLS = {
    "todowrite",
    "askuserquestion",
    "enterplanmode",
    "exitplanmode",
    "taskcreate",
    "taskupdate",
    "tasklist",
    "taskget",
    "toolsearch",
    "collaboration.send_message",
    "collaborationsend_message",
    "collaboration.list_agents",
    "collaborationlist_agents",
    "collaboration.wait_agent",
    "collaborationwait_agent",
    "functions.get_goal",
    "functions.request_user_input",
}
PATH_KEYS = ("file_path", "filePath", "filepath", "path", "notebook_path")
SHELL_TOOLS = {"bash", "exec_command", "functions.exec_command", "shell", "shell_command"}

DENIAL_REASONS = {
    "protected_path": "ADR blocked access to a protected file or configuration.",
    "execution_policy": "ADR's strict execution policy blocks this command or unrecognized tool.",
    "approval_denied": "This operation was denied in ADR's approval dialog.",
    "approval_expired": "ADR's approval request expired. Retry the operation if it is still needed.",
    "approval_queue_full": "ADR's approval queue is full. Finish pending approvals, then retry.",
    "app_unavailable": "ADR's approval dialog is unavailable. Open the ADR menu-bar app and retry.",
    "invalid_request": "ADR could not validate this tool request; no approval was granted.",
    "policy_unavailable": "ADR could not load its local protection policy. Open ADR to check its status.",
    "safety_timeout": "ADR's safety check timed out; no approval was granted.",
    "vault_execution_required": (
        "Use adr_run_command for saved $VARIABLE credentials. "
        "It is built into the ADR plugin; no separate vault setup is needed. "
        "Local programs receive the values and the model receives filtered output."
    ),
    "credential_check_unavailable": (
        "ADR could not check this tool result against saved credentials. "
        "The result was withheld. Open Credential vault in ADR to check storage."
    ),
    "known_malicious_artifact": (
        "ADR blocked a known malicious artifact. Review Malicious artifacts in ADR."
    ),
}


def printable(value: str) -> str:
    return "".join(
        f"\\u{ord(char):04x}" if unicodedata.category(char).startswith("C") else char for char in value
    )


def resolve_path(value: str, cwd: str) -> Path:
    if not isinstance(value, str) or not value or len(value) > 8192 or "\x00" in value:
        raise ValueError("Invalid file path")
    if value.startswith("file:"):
        parsed = urlsplit(value)
        if parsed.netloc not in ("", "localhost") or parsed.query or parsed.fragment:
            raise ValueError("Unsupported file URL")
        value = unquote(parsed.path)
    elif "://" in value:
        raise ValueError("Not a local file path")
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = Path(cwd) / path
    return path.resolve(strict=False)


def _comparison(path: Path) -> str:
    value = unicodedata.normalize("NFC", str(path))
    # Conservative on macOS/Windows: overblocking a case-sensitive volume is
    # preferable to a case-variant bypass on the common case-insensitive volume.
    return value.casefold() if platform.system() in ("Darwin", "Windows") else value


def _same_file(left: Path, right: Path) -> bool:
    try:
        return os.path.samefile(left, right)
    except OSError:
        return False


def _within(candidate: Path, directory: Path) -> bool:
    expected = _comparison(directory)
    for ancestor in (candidate, *candidate.parents):
        if _comparison(ancestor) == expected or _same_file(ancestor, directory):
            return True
    return False


def project_path(value: str) -> str:
    return str(resolve_path(value, str(Path.home())))


def validate_rule(path: str, action: str, kind: str, label: str) -> dict:
    original = Path(path).expanduser()
    if not original.is_absolute():
        raise ValueError("Choose an absolute path or a path beginning with ~/")
    if action not in ("ask", "block") or kind not in ("file", "directory"):
        raise ValueError("Choose ask/block and file/directory")
    resolved = resolve_path(path, str(Path.home()))
    if resolved == Path(resolved.anchor):
        raise ValueError("Protect a specific file or directory, not the filesystem root")
    return {
        "path": str(original.absolute()),
        "action": action,
        "kind": kind,
        "label": printable(label.strip() or resolved.name)[:100],
    }


@dataclass
class Decision:
    decision: str = "pass"
    reason: str = "No protected path matched"
    paths: list[str] = field(default_factory=list)
    rule_id: str | None = None
    tool: str = ""
    session_id: str = ""
    credential_kinds: list[str] = field(default_factory=list)
    phase: str = "pre"
    reason_code: str = "no_match"
    approval_requested: bool = False
    artifact: dict | None = None

    def as_dict(self):
        result = asdict(self)
        # Closed reason codes are for the native bridge. The optional approval
        # marker distinguishes owner-approved operations from routine passes.
        result.pop("reason_code")
        result["approval_requested"] = self.approval_requested or self.decision == "ask"
        if not result["approval_requested"]:
            result.pop("approval_requested")
        if result["artifact"] is None:
            result.pop("artifact")
        return result


def event_fields(event: dict, harness: str) -> tuple[str, dict, str, str]:
    if harness in ("claude", "codex", "opencode"):
        tool = event.get("tool_name")
        arguments = event.get("tool_input")
        session = event.get("session_id", "")
    else:
        tool = event.get("toolName")
        arguments = event.get("toolArgs")
        session = event.get("sessionId", "")
        if isinstance(arguments, str):
            from .config import strict_json

            arguments = strict_json(arguments, max_bytes=256 * 1024)
    if not isinstance(tool, str) or not tool or not isinstance(arguments, dict):
        raise ValueError("The hook input is missing its tool name or arguments")
    cwd = event.get("cwd") or str(Path.cwd())
    if not isinstance(cwd, str) or not Path(cwd).expanduser().is_absolute():
        raise ValueError("The hook working directory must be absolute")
    return tool[:200], arguments, cwd, str(session)[:512]


def literal_shell_files(arguments: dict, cwd: str) -> list[Path]:
    """Recognize a small set of literal reads, without executing or expanding shell.

    This deliberately is not a shell interpreter. Pipelines, substitutions,
    redirects, compound commands, scripts, and other executables remain subject
    to the user's existing unclassified-execution setting.
    """
    command = arguments.get("command", arguments.get("cmd"))
    if not isinstance(command, str) or len(command) > 16384:
        return []
    def words_with_quoting(text):
        # Keep whether a leading tilde was quoted: "~/file" is relative to
        # cwd, while ~/file uses the shell's home expansion.
        text = text.strip()
        stream = io.StringIO(text)
        lexer = shlex.shlex(stream, posix=True)
        lexer.whitespace_split = True
        lexer.commenters = ""
        result = []
        try:
            while True:
                offset = stream.tell()
                if text[offset:].lstrip().startswith("#"):
                    break
                word = lexer.get_token()
                if word is None:
                    break
                raw = text[offset:stream.tell()]
                if any(character in raw for character in "\n\r;&|<>`$()*?[]{}"):
                    return []
                result.append((word, raw.lstrip().startswith("~")))
                if len(result) > 128:
                    return []
        except ValueError:
            return []
        return result

    words = words_with_quoting(command)
    if not words or len(words) > 128:
        return []
    executable = Path(words[0][0]).name
    if executable in {"sh", "bash", "zsh", "dash"}:
        if len(words) != 3 or words[1][0] not in {"-c", "-lc"}:
            return []
        # Codex may supply the canonical shell wrapper rather than just the
        # command text. Accept only one bounded wrapper, not nested scripts.
        words = words_with_quoting(words[2][0])
        if not words or len(words) > 128:
            return []
        executable = Path(words[0][0]).name
    if executable not in {"cat", "head", "tail"}:
        return []
    directory = arguments.get("workdir", arguments.get("cwd", cwd))
    directory = str(resolve_path(directory, cwd))
    files = []
    options = True
    skip_count = False
    for word, expand_tilde in words[1:]:
        if skip_count:
            # Counts are not paths. Anything not a literal count is outside
            # this bounded recognizer (including a missing option argument).
            if not word.lstrip("+-").isdigit():
                return []
            skip_count = False
            continue
        if options and word == "--":
            options = False
            continue
        if options and word.startswith("-") and word != "-":
            if executable == "cat":
                short = word.startswith("-") and not word.startswith("--") and set(word[1:]) <= set(
                    "AbeEnstTuv"
                )
                long = word in {
                    "--show-all", "--number-nonblank", "--show-ends", "--number",
                    "--squeeze-blank", "--show-tabs", "--show-nonprinting",
                }
                if not short and not long:
                    return []
            elif word in {"-n", "-c", "--lines", "--bytes"}:
                skip_count = True
            elif word in {"-q", "-v", "--quiet", "--silent", "--verbose"}:
                pass
            elif executable == "tail" and word in {"-f", "-F", "--follow", "--retry"}:
                pass
            elif word[1:].isdigit() or (
                word.startswith(("-n", "-c")) and word[2:].lstrip("+-").isdigit()
            ):
                pass
            elif word.startswith(("--lines=", "--bytes=")) and word.split("=", 1)[1].lstrip("+-").isdigit():
                pass
            else:
                return []
            continue
        # BSD tools stop option processing at the first operand. Treat later
        # option-looking words as possible filenames on every host, rather
        # than silently ignoring an actually accessed "-n" file on macOS.
        options = False
        if word != "-":
            if word.startswith("~") and not expand_tilde:
                word = str(Path(directory) / word)
            files.append(resolve_path(word, directory))
    return [] if skip_count else files


def evaluate(event: dict, harness: str, snapshot: dict) -> Decision:
    tool, arguments, cwd, session = event_fields(event, harness)
    result = Decision(tool=tool, session_id=session)
    rules = list(snapshot.get("rules", [])) if snapshot.get("enabled", True) else []
    # Control files remain protected even when user file rules are paused.
    rules += [
        {
            "id": "adr-control-plane",
            "path": path,
            "kind": kind,
            "action": "block",
            "label": "ADR security configuration",
        }
        for path, kind in snapshot.get("control_paths", [])
    ]
    if snapshot.get("control_paths"):
        # A project-local configuration can also weaken a user-level hook.
        project_controls = (
            (
                (".claude/settings.json", "file"),
                (".claude/settings.local.json", "file"),
                (".mcp.json", "file"),
            )
            if harness == "claude"
            else ((".codex/hooks.json", "file"), (".codex/config.toml", "file"))
            if harness == "codex"
            else (
                (".opencode/plugins", "directory"),
                (".opencode/plugin", "directory"),
                ("opencode.json", "file"),
                ("opencode.jsonc", "file"),
            )
            if harness == "opencode"
            else ((".github/hooks", "directory"),)
        )
        rules += [
            {
                "id": "adr-control-plane",
                "path": str(root / name),
                "kind": kind,
                "action": "block",
                "label": "Agent hook configuration",
            }
            for root in (Path(cwd), *Path(cwd).parents)
            for name, kind in project_controls
        ]
    if not rules:
        return result
    name = tool.lower()
    if name in SAFE_TOOLS:
        return result
    paths = []
    for key in PATH_KEYS:
        value = arguments.get(key)
        if value is not None:
            paths.append(resolve_path(value, cwd))
    if name in SHELL_TOOLS:
        paths.extend(literal_shell_files(arguments, cwd))
    if name in SEARCH_TOOLS and not paths:
        paths.append(resolve_path(cwd, cwd))
    result.paths = [str(path) for path in paths]
    if name in DIRECT_TOOLS and not paths:
        result.decision, result.reason = "deny", "ADR could not determine the file being accessed"
        result.reason_code = "invalid_request"
        return result

    matches = []
    for rule in rules:
        protected = resolve_path(rule["path"], cwd)
        for path in paths:
            exact = _comparison(path) == _comparison(protected) or _same_file(path, protected)
            contained = rule["kind"] == "directory" and _within(path, protected)
            # A recursive query of an ancestor can read the protected descendant.
            ancestor_query = name in SEARCH_TOOLS and _within(protected, path)
            if exact or contained or ancestor_query:
                matches.append(rule)
                break
    if matches:
        rule = next((item for item in matches if item["action"] == "block"), matches[0])
        result.rule_id = rule["id"]
        result.reason_code = "protected_path"
        result.decision = "deny" if rule["action"] == "block" else "ask"
        action = "blocked" if result.decision == "deny" else "requires your approval"
        result.reason = f"ADR: {rule['label']} is protected; this access is {action}."
        strict = snapshot.get("strict_execution", snapshot.get("opaque_tools") == "block")
        if not isinstance(strict, bool):
            raise ValueError("Invalid strict execution setting")
        if (
            result.decision == "ask" and name in SHELL_TOOLS
            and strict and snapshot.get("opaque_tools") == "block"
        ):
            # A file's Ask rule must never weaken an explicit Block-all-
            # execution choice merely because its literal path is recognized.
            result.decision = "deny"
            result.reason_code = "execution_policy"
            result.reason = DENIAL_REASONS["execution_policy"]
        return result
    if name not in DIRECT_TOOLS | SEARCH_TOOLS:
        strict = snapshot.get("strict_execution", snapshot.get("opaque_tools") == "block")
        if not isinstance(strict, bool):
            raise ValueError("Invalid strict execution setting")
        if strict:
            result.decision = "deny" if snapshot.get("opaque_tools") == "block" else "ask"
            result.reason_code = "execution_policy"
            result.reason = (
                DENIAL_REASONS["execution_policy"] if result.decision == "deny"
                else "Strict execution review is enabled. Review this command or unrecognized tool."
            )
    return result


def hook_output(decision: Decision, harness: str) -> dict:
    if decision.decision == "pass":
        # Do not turn an ordinary tool into "allow": that could bypass the
        # harness's own permission checks.
        return {}
    if decision.phase == "post":
        if harness == "claude":
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PostToolUse",
                    "updatedToolOutput": decision.reason,
                }
            }
        if harness == "codex":
            return {"decision": "block", "reason": decision.reason}
        if harness == "opencode":
            return {"blocked": True, "message": decision.reason}
        return {}  # Copilot does not support withholding post-tool output.
    output = {
        # Unsupported "ask" can fail open in these harnesses. A native ADR
        # approval must resolve it to pass/deny before output is emitted.
        "permissionDecision": "deny"
        if decision.decision == "ask" and harness != "claude"
        else decision.decision,
        "permissionDecisionReason": decision.reason,
    }
    if harness in ("claude", "codex"):
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", **output}}
    return output
