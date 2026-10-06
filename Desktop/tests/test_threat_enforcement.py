import hashlib
import io
import json
import os
import shlex
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from adr_desktop.config import atomic_json
from adr_desktop.guard import install_guard
from adr_desktop.hooks import run_hook
from adr_desktop.policy import Decision
from adr_desktop.protection import evaluate_operation
from adr_desktop.threat_feed import BUNDLED_FEED_ID, compose_generation, load_bundled_feed


def generation(*targets):
    indicators = [{
        "id": f"fixture-{index}", "status": "active", "kind": kind, "target": target,
        "summary": "Inert test fixture", "references": ["https://example.invalid/disclosure"],
    } for index, (kind, target) in enumerate(targets)]
    return compose_generation({
        "schema_version": 1, "feed_id": BUNDLED_FEED_ID, "revision": 1,
        "published_at": "2026-10-05T00:00:00Z", "indicators": indicators,
    })


def package_generation():
    return generation(("package", {
        "ecosystem": "npm", "name": "fixture-package", "registry": "https://registry.npmjs.org",
        "versions": ["1.2.3"],
    }))


def protected(snapshot, feed=None):
    return {**snapshot, "threats": {"enabled": True, "generation": feed or package_generation()}}


def command_event(tmp_path, command="npm install fixture-package@1.2.3", harness="codex"):
    if harness == "copilot":
        return {"toolName": "bash", "toolArgs": {"command": command}, "cwd": str(tmp_path)}
    return {"tool_name": "Bash", "tool_input": {"command": command}, "cwd": str(tmp_path)}


@pytest.fixture(autouse=True)
def isolate_registries(monkeypatch, runtime):
    monkeypatch.setenv("HOME", str(Path.home()))
    for key in tuple(os.environ):
        if key.lower().startswith(("pip_", "npm_config_", "uv_")) or key == "VIRTUAL_ENV":
            monkeypatch.delenv(key)


@pytest.mark.parametrize("harness", ["codex", "claude", "copilot", "opencode"])
def test_known_match_denies_without_blanket_command_review(runtime, tmp_path, harness):
    snapshot = protected(runtime.policy)
    decision = evaluate_operation(command_event(tmp_path, harness=harness), harness, snapshot,
                                  state_dir=runtime.state_dir)
    assert decision.decision == "deny" and decision.reason_code == "known_malicious_artifact"
    assert set(decision.artifact) == {"indicator_id", "source_id", "kind", "generation", "target_display"}
    assert "npm install" not in json.dumps(decision.as_dict())
    clean = evaluate_operation(command_event(tmp_path, "npm install fixture-package@1.2.4", harness),
                               harness, snapshot, state_dir=runtime.state_dir)
    assert clean.decision == "pass" and "artifact" not in clean.as_dict()


def test_existing_file_deny_short_circuits_inspection(runtime, tmp_path, monkeypatch):
    event = {"tool_name": "Read", "tool_input": {"file_path": str(runtime.state_dir / "policy.json")},
             "cwd": str(tmp_path)}

    def forbidden(*_args, **_kwargs):
        raise AssertionError("A file already blocked by policy must not be hashed")

    monkeypatch.setattr("adr_desktop.protection.identify_event", forbidden)
    decision = evaluate_operation(event, "codex", protected(runtime.policy), state_dir=runtime.state_dir)
    assert decision.reason_code == "protected_path"


def test_trusted_adr_pass_still_receives_artifact_check(runtime, tmp_path, monkeypatch):
    monkeypatch.setattr("adr_desktop.protection.trusted_tool", lambda *_: True)
    decision = evaluate_operation(command_event(tmp_path), "codex", protected(runtime.policy),
                                  state_dir=runtime.state_dir)
    assert decision.reason_code == "known_malicious_artifact"


def test_unknown_keeps_ask_and_disabled_feature_keeps_file_policy(runtime, tmp_path):
    snapshot = protected({**runtime.policy, "strict_execution": True, "opaque_tools": "ask"})
    event = command_event(tmp_path, "echo routine")
    assert evaluate_operation(event, "codex", snapshot, state_dir=runtime.state_dir).decision == "ask"
    snapshot["threats"]["enabled"] = False
    assert evaluate_operation(command_event(tmp_path), "codex", snapshot,
                              state_dir=runtime.state_dir).decision == "ask"
    assert "artifact" not in Decision().as_dict()


def test_feed_corruption_is_not_an_empty_list(runtime, tmp_path):
    snapshot = protected(runtime.policy)
    snapshot["threats"]["generation"]["digest"] = "0" * 64
    with pytest.raises(ValueError):
        evaluate_operation(command_event(tmp_path), "codex", snapshot, state_dir=runtime.state_dir)


def test_exact_skill_and_file_hash_blocks_but_remediation_passes(runtime, tmp_path):
    skill = tmp_path / "SKILL.md"
    skill.write_bytes(b"Inert known fixture\n")
    snapshot = protected(runtime.policy, generation(
        ("skill_sha256", {"sha256": hashlib.sha256(skill.read_bytes()).hexdigest()}),
    ))
    for tool in ("Read", "read_file"):
        event = {"tool_name": tool, "tool_input": {"file_path": str(skill)}, "cwd": str(tmp_path)}
        assert evaluate_operation(event, "codex", snapshot, state_dir=runtime.state_dir).artifact
    event["tool_name"] = "Write"
    assert evaluate_operation(event, "codex", snapshot, state_dir=runtime.state_dir).decision == "pass"
    skill.write_bytes(b"Different inert fixture\n")
    event["tool_name"] = "Read"
    assert evaluate_operation(event, "codex", snapshot, state_dir=runtime.state_dir).decision == "pass"


def test_named_skill_invocation_blocks_using_manifest_bytes(runtime, tmp_path):
    path = tmp_path / ".claude/skills/renamed-directory/SKILL.md"
    path.parent.mkdir(parents=True)
    path.write_text("---\nname: fixture\n---\nInert test fixture\n")
    snapshot = protected(runtime.policy, generation(
        ("skill_sha256", {"sha256": hashlib.sha256(path.read_bytes()).hexdigest()}),
    ))
    event = {"tool_name": "Skill", "tool_input": {"skill": "fixture"}, "cwd": str(tmp_path)}
    decision = evaluate_operation(event, "claude", snapshot, state_dir=runtime.state_dir)
    assert decision.reason_code == "known_malicious_artifact"
    assert decision.artifact["kind"] == "skill_sha256"


def test_numeric_sed_skill_read_blocks_full_known_hash_not_printed_prefix(runtime, tmp_path):
    path = tmp_path / "SKILL.md"
    path.write_text("---\nname: fixture\n---\n" + "inert tail\n" * 400)
    snapshot = protected(runtime.policy, generation(
        ("skill_sha256", {"sha256": hashlib.sha256(path.read_bytes()).hexdigest()}),
    ))
    command = f"sed -n '1,3p' {shlex.quote(str(path))}"
    decision = evaluate_operation(command_event(tmp_path, command), "codex", snapshot,
                                  state_dir=runtime.state_dir)
    assert decision.reason_code == "known_malicious_artifact"
    clean = tmp_path / "clean.md"
    clean.write_text("Clean fixture")
    for command in (f"sed -n '1,3p' {clean}", f"echo {shlex.quote(command)}",
                    f"sed -i '' 's/fixture/clean/' {path}"):
        decision = evaluate_operation(command_event(tmp_path, command), "codex", snapshot,
                                      state_dir=runtime.state_dir)
        assert decision.decision == "pass"

def test_mcp_endpoint_requires_current_exact_definition(runtime, tmp_path):
    config = tmp_path / ".mcp.json"
    config.write_text('{"mcpServers":{"fixture":{"url":"https://fixture.example.invalid/mcp"}}}')
    snapshot = protected(runtime.policy, generation(
        ("mcp_endpoint", {"url": "https://fixture.example.invalid/mcp"}),
    ))
    event = {"tool_name": "mcp__fixture__lookup", "tool_input": {}, "cwd": str(tmp_path)}
    assert evaluate_operation(event, "claude", snapshot, state_dir=runtime.state_dir).artifact
    config.write_text('{"mcpServers":{"fixture":{"url":"https://clean.example.invalid/mcp"}}}')
    assert evaluate_operation(event, "claude", snapshot, state_dir=runtime.state_dir).decision == "pass"


def test_offline_real_guardian_stops_inert_installer_before_marker(runtime, tmp_path):
    marker = tmp_path / "marker"
    program = tmp_path / "npm"
    program.write_text("#!/bin/sh\nprintf invoked > " + shlex.quote(str(marker)) + "\n")
    program.chmod(0o700)
    atomic_json(runtime.state_dir / "policy.json", protected(runtime.policy))
    guard = install_guard(runtime.state_dir)
    command = shlex.join([str(program), "install", "fixture-package@1.2.3"])
    result = subprocess.run([str(guard), "codex", str(runtime.state_dir)],
                            input=json.dumps(command_event(tmp_path, command)), capture_output=True,
                            text=True, timeout=6, env={**os.environ, "HOME": str(Path.home())})
    assert result.returncode == 0
    response = json.loads(result.stdout)
    assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "known malicious artifact" in response["hookSpecificOutput"]["permissionDecisionReason"]
    assert not marker.exists()
    # An adjacent harmless version is allowed by the same real guardian.
    control = subprocess.run([str(guard), "codex", str(runtime.state_dir)],
                             input=json.dumps(command_event(tmp_path, command.replace("1.2.3", "1.2.4"))),
                             capture_output=True, text=True, timeout=6,
                             env={**os.environ, "HOME": str(Path.home())})
    assert json.loads(control.stdout) == {}


@pytest.mark.parametrize("explicit", [False, True])
def test_real_guardian_blocks_public_pin_with_symlinked_npm_config(runtime, tmp_path, explicit):
    target = tmp_path / "npm-config"
    target.write_text("registry=https://registry.npmjs.org\n")
    (Path.home() / ".npmrc").symlink_to(target)
    atomic_json(runtime.state_dir / "policy.json", protected(
        runtime.policy, compose_generation(load_bundled_feed()),
    ))
    guard = install_guard(runtime.state_dir)
    result = subprocess.run(
        [str(guard), "codex", str(runtime.state_dir)],
        input=json.dumps(command_event(
            tmp_path, "npm install "
            + ("--registry=https://registry.npmjs.org " if explicit else "") + "postmark-mcp@1.0.16",
        )),
        capture_output=True, text=True, timeout=6, env={**os.environ, "HOME": str(Path.home())},
    )
    assert result.returncode == 0
    decision = json.loads(result.stdout)["hookSpecificOutput"]
    assert decision["permissionDecision"] == "deny"
    assert "known malicious artifact" in decision["permissionDecisionReason"]

def test_vault_runner_denies_before_native_execution(runtime, tmp_path):
    saved = runtime.environment_vault.create("Fixture", "FIXTURE_TOKEN")
    grant = runtime.create_grant(
        "Fixture command", str(tmp_path), [saved["id"]], kind="execution", confirm_execution=True,
        approval_mode="automatic", confirm_automatic=True,
    )
    principal = runtime.store.one("SELECT * FROM grants WHERE id=?", (grant["id"],))
    runtime.policy = protected(runtime.policy)
    with pytest.raises(PermissionError, match="known_malicious_artifact"):
        runtime.environment_vault.execute(principal, "npm install fixture-package@1.2.3", str(tmp_path))
    assert not any(operation == "environment_execute" for operation, _ in runtime.native.calls)


def test_vault_registry_identity_uses_actual_clean_native_environment(runtime, tmp_path, monkeypatch):
    saved = runtime.environment_vault.create("Fixture", "FIXTURE_TOKEN")
    grant = runtime.create_grant(
        "Fixture command", str(tmp_path), [saved["id"]], kind="execution", confirm_execution=True,
        approval_mode="automatic", confirm_automatic=True,
    )
    principal = runtime.store.one("SELECT * FROM grants WHERE id=?", (grant["id"],))
    runtime.policy = protected(runtime.policy)
    monkeypatch.setenv("NPM_CONFIG_REGISTRY", "https://private.example.invalid")
    with pytest.raises(PermissionError, match="known_malicious_artifact"):
        runtime.environment_vault.execute(principal, "npm install fixture-package@1.2.3", str(tmp_path))
    assert not any(operation == "environment_execute" for operation, _ in runtime.native.calls)

def test_vault_rechecks_feed_after_owner_approval(runtime, tmp_path, monkeypatch):
    saved = runtime.environment_vault.create("Fixture", "FIXTURE_TOKEN")
    grant = runtime.create_grant(
        "Fixture command", str(tmp_path), [saved["id"]], kind="execution", confirm_execution=True,
        approval_mode="ask",
    )
    principal = runtime.store.one("SELECT * FROM grants WHERE id=?", (grant["id"],))
    original = runtime.native.call

    def approve(operation, arguments=None, timeout=30):
        if operation == "approve_tool":
            runtime.policy = protected(runtime.policy)
            return {"allowed": True}
        return original(operation, arguments, timeout=timeout)

    monkeypatch.setattr(runtime.native, "call", approve)
    with pytest.raises(PermissionError, match="known_malicious_artifact"):
        runtime.environment_vault.execute(principal, "npm install fixture-package@1.2.3", str(tmp_path))
    assert not any(operation == "environment_execute" for operation, _ in runtime.native.calls)


def pending_hook(runtime, event, snapshot, approve, monkeypatch, capsys):
    """Exercise the real hook function with an inert local approval transport."""
    atomic_json(runtime.state_dir / "policy.json", snapshot)
    monkeypatch.setattr("adr_desktop.hooks.sys.stdin", SimpleNamespace(
        buffer=io.BytesIO(json.dumps(event).encode()),
    ))
    receipts = []

    def request(_state, _method, path, *, payload=None, **_kwargs):
        if path == "/api/hooks/approve":
            return approve(payload)
        assert path == "/api/hooks/events"
        receipts.append(payload)
        return {"recorded": True}

    monkeypatch.setattr("adr_desktop.hooks.request", request)
    assert run_hook(runtime.state_dir, "codex") == 0
    return json.loads(capsys.readouterr().out), receipts


@pytest.mark.parametrize("tool,arguments", [
    ("Bash", {"command": "npm install fixture-package@1.2.3"}),
    ("Skill", {"skill": "fixture"}),
    ("mcp__fixture__lookup", {}),
    ("Read", {"file_path": "SKILL.md"}),
    ("Read", {"file_path": "~/SKILL.md"}),
    ("Read", {"file_path": "file:///synthetic/SKILL.md"}),
    ("Write", {"file_path": "/synthetic/SKILL.md"}),
])
def test_daemon_scope_never_resolves_missing_harness_context(runtime, tmp_path, monkeypatch, tool, arguments):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Missing process context must not be inferred by the daemon")

    monkeypatch.setattr("adr_desktop.protection.identify_event", forbidden)
    event = {"tool_name": tool, "tool_input": arguments, "cwd": str(tmp_path)}
    decision = evaluate_operation(event, "codex", protected(runtime.policy), state_dir=runtime.state_dir,
                                  allow_adr_trust=False, artifact_scope="direct_files")
    assert decision.artifact is None


def test_daemon_scope_retains_absolute_file_hash_enforcement(runtime, tmp_path):
    path = tmp_path / "fixture.txt"
    path.write_text("Inert fixture")
    snapshot = protected(runtime.policy, generation(
        ("file_sha256", {"sha256": hashlib.sha256(path.read_bytes()).hexdigest()}),
    ))
    event = {"tool_name": "Read", "tool_input": {"file_path": str(path)}, "cwd": str(tmp_path)}
    decision = evaluate_operation(event, "codex", snapshot, state_dir=runtime.state_dir,
                                  allow_adr_trust=False, artifact_scope="direct_files")
    assert decision.reason_code == "known_malicious_artifact"


@pytest.mark.parametrize("ecosystem,variable,command,registry", [
    ("npm", "NPM_CONFIG_REGISTRY", "npm install fixture-package@1.2.3", "https://registry.npmjs.org"),
    ("pypi", "PIP_INDEX_URL", "pip install fixture-package==1.2.3", "https://pypi.org"),
])
@pytest.mark.parametrize("private_harness", [False, True])
@pytest.mark.parametrize("receipt_code", ["approved", "no_match"])
def test_final_hook_rechecks_original_environment_and_latest_feed(
    runtime, tmp_path, monkeypatch, capsys, ecosystem, variable, command, registry,
    private_harness, receipt_code,
):
    current = protected(
        {**runtime.policy, "strict_execution": receipt_code == "approved"},
        generation(("package", {
            "ecosystem": ecosystem, "registry": registry, "name": "fixture-package", "versions": ["1.2.3"],
        })),
    )
    initial = {**(current if private_harness else protected(current, generation())), "strict_execution": True}
    event = command_event(tmp_path, command)
    if private_harness:
        monkeypatch.setenv(variable, "https://private.example.invalid")
    else:
        monkeypatch.delenv(variable, raising=False)

    def approve(_payload):
        with monkeypatch.context() as daemon:
            if private_harness:
                daemon.delenv(variable, raising=False)
            else:
                daemon.setenv(variable, "https://private.example.invalid")
            checked = evaluate_operation(
                event, "codex", current, state_dir=runtime.state_dir, allow_adr_trust=False,
                artifact_scope="direct_files",
            )
            assert checked.decision == ("ask" if receipt_code == "approved" else "pass")
            assert checked.artifact is None
        # Simulate publication between the daemon's final check and its reply.
        atomic_json(runtime.state_dir / "policy.json", current)
        return {"allowed": True, "reason_code": receipt_code}

    output, receipts = pending_hook(runtime, event, initial, approve, monkeypatch, capsys)
    if private_harness:
        assert output == {}
        assert receipts[-1]["decision"] == "pass" and "artifact" not in receipts[-1]
    else:
        assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "known malicious artifact" in output["hookSpecificOutput"]["permissionDecisionReason"]
        artifact = receipts[-1]["artifact"]
        assert set(artifact) == {"indicator_id", "source_id", "kind", "generation", "target_display"}
        assert artifact["generation"] == current["threats"]["generation"]["digest"]
        assert artifact["indicator_id"] == BUNDLED_FEED_ID + "/fixture-0"
        assert artifact["source_id"] == BUNDLED_FEED_ID and artifact["kind"] == "package"
        assert receipts[-1].get("approval_requested", False) is (receipt_code == "approved")


def test_automatic_daemon_pass_cannot_approve_new_ask_rule(runtime, tmp_path, monkeypatch, capsys):
    snapshot = protected({**runtime.policy, "strict_execution": True}, generation())
    event = command_event(tmp_path, "echo inert")

    def approve(_payload):
        automatic = evaluate_operation(
            event, "codex", {**snapshot, "strict_execution": False},
            state_dir=runtime.state_dir, allow_adr_trust=False, artifact_scope="direct_files",
        )
        assert automatic.decision == "pass"
        # Before the positive automatic response reaches the hook, Ask returns.
        atomic_json(runtime.state_dir / "policy.json", snapshot)
        return {"allowed": True, "reason_code": "no_match"}

    output, receipts = pending_hook(runtime, event, snapshot, approve, monkeypatch, capsys)
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "no approval was granted" in output["hookSpecificOutput"]["permissionDecisionReason"]
    assert "approval_requested" not in receipts[-1]


@pytest.mark.parametrize("corruption", ["version", "generation"])
def test_positive_approval_cannot_pass_corrupt_refreshed_policy(
    runtime, tmp_path, monkeypatch, capsys, corruption,
):
    snapshot = protected({**runtime.policy, "strict_execution": True}, generation())

    def approve(_payload):
        changed = json.loads(json.dumps(snapshot))
        if corruption == "version":
            changed["version"] = 999
        else:
            changed["threats"]["generation"]["digest"] = "0" * 64
        atomic_json(runtime.state_dir / "policy.json", changed)
        return {"allowed": True, "reason_code": "approved"}

    output, receipts = pending_hook(
        runtime, command_event(tmp_path, "echo inert"), snapshot, approve, monkeypatch, capsys,
    )
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "local protection policy" in output["hookSpecificOutput"]["permissionDecisionReason"]
    assert receipts[-1]["decision"] == "deny"


def test_final_hook_refreshes_plugin_control_path(runtime, tmp_path, monkeypatch, capsys):
    root = tmp_path / "plugin"
    root.mkdir()
    path = root / "manifest.json"
    path.write_text("{}")
    snapshot = protected(runtime.policy, generation())
    snapshot["rules"] = [*snapshot["rules"], {
        "id": "fixture", "path": str(path), "kind": "file", "action": "ask", "label": "fixture",
    }]
    changed = False
    monkeypatch.setattr("adr_desktop.agent_plugins.plugin_root", lambda *_: root if changed else None)

    def approve(_payload):
        nonlocal changed
        changed = True
        return {"allowed": True, "reason_code": "approved"}

    event = {"tool_name": "Read", "tool_input": {"file_path": str(path)}, "cwd": str(tmp_path)}
    output, receipts = pending_hook(runtime, event, snapshot, approve, monkeypatch, capsys)
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert receipts[-1]["rule_id"] == "adr-control-plane"


def test_final_hook_keeps_file_credential_checks_after_approval(runtime, tmp_path, monkeypatch, capsys):
    path = tmp_path / "fixture.txt"
    path.write_text("Ordinary initial bytes")
    snapshot = protected(runtime.policy, generation())
    snapshot["rules"] = [*snapshot["rules"], {
        "id": "fixture", "path": str(path), "kind": "file", "action": "ask", "label": "fixture",
    }]

    def approve(_payload):
        path.write_text("-----BEGIN PRIVATE KEY-----\nInert test fixture, not a key\n")
        return {"allowed": True, "reason_code": "approved"}

    event = {"tool_name": "Read", "tool_input": {"file_path": str(path)}, "cwd": str(tmp_path)}
    output, receipts = pending_hook(runtime, event, snapshot, approve, monkeypatch, capsys)
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert receipts[-1]["credential_kinds"] == ["Private key"]
