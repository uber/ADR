import json
import os
import subprocess
import sys

import pytest

from adr_desktop.config import atomic_json
from adr_desktop.policy import evaluate, hook_output, validate_rule


def policy(path, action="block", kind="directory", **options):
    return {
        "version": 1,
        "enabled": True,
        "opaque_tools": "ask",
        "rules": [{"id": "test-rule", "path": str(path), "action": action, "kind": kind, "label": "Private"}],
        "control_paths": [],
        **options,
    }


def event(path=None, tool="Read", cwd="/workspace", **arguments):
    return {
        "tool_name": tool,
        "tool_input": {**({"file_path": str(path)} if path else {}), **arguments},
        "cwd": str(cwd),
        "session_id": "synthetic",
    }


def test_direct_access_is_blocked_and_normal_access_remains_native(tmp_path):
    protected = tmp_path / "private"
    protected.mkdir()
    assert evaluate(event(protected / "secret"), "claude", policy(protected)).decision == "deny"
    result = evaluate(event(tmp_path / "public"), "claude", policy(protected))
    assert result.decision == "pass"
    assert hook_output(result, "claude") == {}


def test_ask_is_native_for_both_harnesses(tmp_path):
    snapshot = policy(tmp_path, action="ask")
    claude = evaluate(event(tmp_path / "file"), "claude", snapshot)
    assert hook_output(claude, "claude")["hookSpecificOutput"]["permissionDecision"] == "ask"
    copilot = evaluate(
        {
            "toolName": "view",
            "toolArgs": json.dumps({"path": str(tmp_path / "file")}),
            "cwd": str(tmp_path),
            "sessionId": "synthetic",
        },
        "copilot",
        snapshot,
    )
    # Copilot does not support an "ask" decision. Unresolved approval is denied.
    assert hook_output(copilot, "copilot")["permissionDecision"] == "deny"


def test_block_wins_over_ask(tmp_path):
    snapshot = policy(tmp_path, action="ask")
    snapshot["rules"].append({**snapshot["rules"][0], "id": "block", "action": "block"})
    assert evaluate(event(tmp_path / "file"), "claude", snapshot).decision == "deny"


def test_relative_paths_and_symlink_aliases_cannot_bypass(tmp_path):
    secret = tmp_path / "private"
    secret.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(secret, target_is_directory=True)
    assert evaluate(event("alias/data", cwd=tmp_path), "claude", policy(secret)).decision == "deny"
    assert evaluate(event("other/../private/data", cwd=tmp_path), "claude", policy(secret)).decision == "deny"


def test_hard_link_to_protected_file_is_blocked(tmp_path):
    protected = tmp_path / "secret"
    protected.write_text("synthetic")
    alias = tmp_path / "alias"
    os.link(protected, alias)
    assert evaluate(event(alias), "claude", policy(protected, kind="file")).decision == "deny"


def test_macos_case_variation_is_conservatively_protected(tmp_path, monkeypatch):
    monkeypatch.setattr("adr_desktop.policy.platform.system", lambda: "Darwin")
    assert (
        evaluate(
            event(str(tmp_path / "Private" / "secret").upper()), "claude", policy(tmp_path / "Private")
        ).decision
        == "deny"
    )


@pytest.mark.parametrize("tool", ["Glob", "Grep"])
def test_recursive_search_of_ancestor_is_checked(tmp_path, tool):
    assert (
        evaluate(event(tool=tool, cwd=tmp_path), "claude", policy(tmp_path / ".env", kind="file")).decision
        == "deny"
    )


@pytest.mark.parametrize("tool", ["Bash", "mcp__unknown__read", "Agent", "apply_patch"])
def test_unclassified_execution_review_is_opt_in(tmp_path, tool):
    assert evaluate(event(tool=tool, command="opaque"), "claude", policy(tmp_path)).decision == "pass"
    assert evaluate(
        event(tool=tool, command="opaque"), "claude", policy(tmp_path, strict_execution=True)
    ).decision == "ask"
    assert evaluate(event(tool=tool), "claude", policy(tmp_path, opaque_tools="block")).decision == "deny"

@pytest.mark.parametrize("tool", ["Bash", "exec_command", "mcp__docs__search"])
def test_control_paths_do_not_enable_blanket_approvals(tmp_path, tool):
    snapshot = policy(
        tmp_path / "protected", control_paths=[[str(tmp_path / "control"), "directory"]]
    )
    result = evaluate(event(tool=tool, cwd=tmp_path / "workspace", command="pwd"), "codex", snapshot)
    assert result.decision == "pass"
    assert result.rule_id is None
    assert result.paths == []


@pytest.mark.parametrize("tool", ["collaborationsend_message", "collaboration.list_agents"])
def test_known_non_file_coordination_does_not_prompt_even_in_strict_mode(tmp_path, tool):
    result = evaluate(event(tool=tool), "codex", policy(tmp_path, strict_execution=True))
    assert result.decision == "pass"


def test_explicit_strict_setting_overrides_legacy_mode_without_weakening_paths(tmp_path):
    snapshot = policy(tmp_path / "private", opaque_tools="block", strict_execution=False)
    assert evaluate(event(tool="Bash"), "codex", snapshot).decision == "pass"
    assert evaluate(event(tmp_path / "private" / "file"), "codex", snapshot).decision == "deny"


@pytest.mark.parametrize("legacy", ["ask", "block"])
def test_saved_policy_migration_preserves_rules_and_explicit_block(runtime, legacy):
    runtime.change_policy(add={"path": "/example/private", "action": "block", "kind": "directory"})
    snapshot = {**runtime.policy, "opaque_tools": legacy}
    snapshot.pop("strict_execution")
    atomic_json(runtime.state_dir / "policy.json", snapshot)
    migrated = runtime._load_policy()
    assert migrated["strict_execution"] is (legacy == "block")
    assert migrated["opaque_tools"] == legacy
    assert migrated["rules"] == snapshot["rules"]
    assert migrated["revision"] != snapshot["revision"]


def test_strict_review_is_off_for_new_profiles_and_remains_an_owner_choice(client, owner, runtime):
    assert runtime.policy["strict_execution"] is False
    assert client.patch("/api/protection", json={"strict_execution": True}).status_code == 401
    assert client.patch(
        "/api/protection", headers=owner, json={"strict_execution": "false"}
    ).status_code == 422
    assert client.patch(
        "/api/protection", headers=owner, json={"strict_execution": True}
    ).status_code == 200
    assert runtime._load_policy()["strict_execution"] is True
    assert client.patch(
        "/api/protection", headers=owner, json={"strict_execution": False}
    ).status_code == 200
    assert runtime._load_policy()["strict_execution"] is False


def test_pausing_custom_rules_does_not_weaken_control_files(tmp_path):
    snapshot = policy(
        tmp_path / "private", enabled=False, control_paths=[[str(tmp_path / "state"), "directory"]]
    )
    assert evaluate(event(tmp_path / "private" / "file"), "claude", snapshot).decision == "pass"
    assert evaluate(event(tmp_path / "state" / "policy.json"), "claude", snapshot).decision == "deny"


def test_project_settings_cannot_disable_hooks(tmp_path):
    snapshot = policy(tmp_path / "private", control_paths=[[str(tmp_path / "state"), "directory"]])
    assert evaluate(event(".claude/settings.local.json", cwd=tmp_path), "claude", snapshot).decision == "deny"


@pytest.mark.parametrize("path", ["relative/path", "/", ""])
def test_rule_requires_specific_absolute_path(path):
    with pytest.raises(ValueError):
        validate_rule(path, "block", "directory", "")


def test_missing_file_argument_does_not_pass(tmp_path):
    assert evaluate(event(), "claude", policy(tmp_path)).decision == "deny"


@pytest.mark.parametrize("harness", ["claude", "copilot"])
def test_hook_runs_offline_and_fails_closed_on_missing_cache(runtime, harness):
    sample = (
        event(runtime.state_dir / "private.json")
        if harness == "claude"
        else {
            "toolName": "view",
            "toolArgs": json.dumps({"path": str(runtime.state_dir / "private.json")}),
            "cwd": str(runtime.state_dir),
        }
    )
    command = [
        sys.executable,
        "-m",
        "adr_desktop",
        "hook",
        "--harness",
        harness,
        "--state-dir",
        str(runtime.state_dir),
    ]
    result = subprocess.run(command, input=json.dumps(sample), capture_output=True, text=True, timeout=6)
    assert result.returncode == 0
    output = json.loads(result.stdout)
    decision = output.get("hookSpecificOutput", output)
    assert decision["permissionDecision"] == "deny"
    (runtime.state_dir / "policy.json").unlink()
    result = subprocess.run(command, input=json.dumps(sample), capture_output=True, text=True, timeout=6)
    assert result.returncode == 0
    output = json.loads(result.stdout)
    assert output.get("hookSpecificOutput", output)["permissionDecision"] == "deny"


def test_policy_writes_are_acknowledged_only_after_cache_is_saved(runtime, monkeypatch):
    old = dict(runtime.policy)

    def fail(*_args, **_kwargs):
        raise OSError("synthetic disk failure")

    monkeypatch.setattr("adr_desktop.runtime.atomic_json", fail)
    with pytest.raises(OSError):
        runtime.change_policy(add={"path": "/private/example", "action": "block", "kind": "directory"})
    assert runtime.policy == old


def test_private_cache_permissions_are_required(runtime):
    if os.name == "nt":
        pytest.skip("POSIX mode-bit check")
    atomic_json(runtime.state_dir / "policy.json", runtime.policy)
    (runtime.state_dir / "policy.json").chmod(0o644)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "adr_desktop",
            "hook",
            "--harness",
            "claude",
            "--state-dir",
            str(runtime.state_dir),
        ],
        input=json.dumps(event("/public/file")),
        capture_output=True,
        text=True,
        timeout=6,
    )
    assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
