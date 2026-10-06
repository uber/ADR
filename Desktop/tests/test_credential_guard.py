import io
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from adr_desktop.guard import install_guard
from adr_desktop.hooks import configuration_path, install, installed, run_hook, uninstall
from adr_desktop.policy import DENIAL_REASONS
from adr_desktop.secret_guard import detect_credentials

SYNTHETIC = {
    "GitHub token": "ghp_" + "a" * 36,
    "AWS access key": "AKIA" + "A" * 16,
    "AWS secret key": 'aws_secret_access_key="' + "a" * 40 + '"',
    "Google API key": "AIza" + "a" * 35,
    "Google OAuth token": "ya29." + "a" * 30,
    "Private key": "-----BEGIN PRIVATE KEY-----\nsynthetic\n-----END PRIVATE KEY-----",
}


@pytest.mark.parametrize(
    "reply",
    [
        {"blocked": True, "unavailable": True, "reason_code": "local_vault_busy"},
        {"blocked": 1},
    ],
)
def test_unavailable_output_check_is_not_a_credential_detection(runtime, monkeypatch, capsys, reply):
    from adr_desktop import hooks

    runtime.environment_vault.create("Synthetic", "MY_TOKEN")
    monkeypatch.setattr(
        sys,
        "stdin",
        SimpleNamespace(
            buffer=io.BytesIO(
                json.dumps(
                    {
                        "tool_name": "Read",
                        "tool_input": {},
                        "tool_response": "ordinary output",
                        "cwd": str(Path.home()),
                        "session_id": "synthetic",
                    }
                ).encode()
            )
        ),
    )
    events = []

    def request(_state, _method, path, **kwargs):
        if path == "/api/hooks/output-check":
            return reply
        if path == "/api/hooks/events":
            events.append(kwargs["payload"])
        return {}

    monkeypatch.setattr(hooks, "request", request)
    hooks.run_hook(runtime.state_dir, "codex", phase="post")
    output = json.loads(capsys.readouterr().out)
    assert output["decision"] == "block"
    assert "could not check" in output["reason"]
    assert events[0]["credential_kinds"] == []
    assert events[0]["decision"] == "deny"


@pytest.mark.parametrize("kind,value", list(SYNTHETIC.items()))
def test_detection_returns_only_types_not_secret_values(kind, value):
    assert kind in detect_credentials(value)
    assert value not in json.dumps(detect_credentials(value))


@pytest.mark.parametrize(
    "value", ["", "api_key=example", "a normal source file", "https://api.github.com/user"]
)
def test_ordinary_text_and_placeholders_do_not_trigger(value):
    assert detect_credentials(value) == []


def event(path=None, *, response=None):
    return {
        "tool_name": "Read",
        "tool_input": {"file_path": str(path)} if path else {},
        "cwd": str(Path.home()),
        "session_id": "synthetic",
        **({"tool_response": response} if response is not None else {}),
    }


@pytest.mark.parametrize("harness", ["claude", "codex", "opencode", "copilot"])
def test_pre_read_blocks_credential_without_returning_its_value(runtime, tmp_path, harness):
    path = tmp_path / "project" / "config.txt"
    path.parent.mkdir()
    value = SYNTHETIC["GitHub token"]
    path.write_text("test_fixture=" + value)
    payload = event(path)
    if harness == "copilot":
        payload = {"toolName": "view", "toolArgs": {"path": str(path)}, "cwd": str(path.parent)}
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "adr_desktop",
            "hook",
            "--harness",
            harness,
            "--state-dir",
            str(runtime.state_dir),
        ],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=6,
    )
    assert result.returncode == 0
    output = json.loads(result.stdout)
    assert output.get("hookSpecificOutput", output)["permissionDecision"] == "deny"
    assert "vault" in result.stdout.lower()
    assert value not in result.stdout + result.stderr


@pytest.mark.parametrize("harness", ["claude", "codex", "opencode"])
def test_guardian_withholds_post_tool_credential_output(runtime, harness):
    guardian = install_guard(runtime.state_dir)
    value = SYNTHETIC["Google OAuth token"]
    result = subprocess.run(
        [str(guardian), harness, str(runtime.state_dir), "post"],
        input=json.dumps(event(response={"body": value})),
        capture_output=True,
        text=True,
        timeout=6,
    )
    assert result.returncode == 0
    output = json.loads(result.stdout)
    if harness == "claude":
        assert output["hookSpecificOutput"]["hookEventName"] == "PostToolUse"
        assert "updatedToolOutput" in output["hookSpecificOutput"]
    elif harness == "codex":
        assert output["decision"] == "block"
    else:
        assert output["blocked"] is True
    assert "vault" in result.stdout.lower()
    assert value not in result.stdout + result.stderr


@pytest.mark.parametrize("harness", ["claude", "codex", "opencode"])
def test_post_tool_does_not_replace_ordinary_output(runtime, harness):
    guardian = install_guard(runtime.state_dir)
    result = subprocess.run(
        [str(guardian), harness, str(runtime.state_dir), "post"],
        input=json.dumps(event(response={"body": "ordinary result"})),
        capture_output=True,
        text=True,
        timeout=6,
    )
    assert json.loads(result.stdout) == {}


def test_starter_cannot_be_added_without_a_hook_for_this_profile(client, owner, runtime):
    before = (runtime.state_dir / "policy.json").read_bytes()
    assert client.get("/api/protection/starter", headers=owner).json()["connected"] is False
    response = client.post("/api/protection/starter", headers=owner, json={})
    assert response.status_code == 400
    assert (runtime.state_dir / "policy.json").read_bytes() == before


def test_hook_bound_to_another_profile_does_not_make_this_profile_connected(runtime, tmp_path):
    other = tmp_path / "other-profile"
    other.mkdir()
    install("codex", other, prefix=[sys.executable, "-m", "adr_desktop"])
    assert installed("codex")
    assert not installed("codex", state_dir=runtime.state_dir)
    assert runtime.starter_protection()["connected"] is False


def test_codex_install_preserves_other_hooks_and_removes_only_adr(runtime):
    target = configuration_path("codex")
    target.parent.mkdir(parents=True, exist_ok=True)
    original = {
        "hooks": {
            "PreToolUse": [{"matcher": "Read", "hooks": [{"type": "command", "command": "echo keep"}]}],
            "PostToolUse": [{"hooks": [{"type": "command", "command": "echo keep-post"}]}],
        },
    }
    target.write_text(json.dumps(original))
    install("codex", runtime.state_dir)
    install("codex", runtime.state_dir)
    current = json.loads(target.read_text())
    assert len(current["hooks"]["PreToolUse"]) == len(current["hooks"]["PostToolUse"]) == 2
    assert installed("codex", state_dir=runtime.state_dir)
    assert installed("codex", phase="post", state_dir=runtime.state_dir)
    uninstall("codex", runtime.state_dir)
    assert json.loads(target.read_text()) == original


def test_opencode_plugin_has_both_apis_and_is_profile_bound(runtime):
    install("opencode", runtime.state_dir)
    target = configuration_path("opencode")
    text = target.read_text()
    assert "__ADR_BRIDGE_ARGUMENTS__" not in text
    assert "async server" in text and "async setup" in text
    assert installed("opencode", state_dir=runtime.state_dir)
    install("opencode", runtime.state_dir)
    assert target.read_text() == text
    uninstall("opencode", runtime.state_dir)
    assert not target.exists()


def test_modified_opencode_plugin_is_not_overwritten_or_deleted(runtime):
    install("opencode", runtime.state_dir)
    target = configuration_path("opencode")
    changed = target.read_text() + "\n// user's change\n"
    target.write_text(changed)
    assert not installed("opencode", state_dir=runtime.state_dir)
    with pytest.raises(ValueError):
        install("opencode", runtime.state_dir)
    with pytest.raises(ValueError):
        uninstall("opencode", runtime.state_dir)
    assert target.read_text() == changed


def test_only_hook_capability_can_request_a_native_file_approval(client, owner, runtime):
    runtime.change_policy(strict_execution=True)
    body = {
        "harness": "codex",
        "event": {
            "tool_name": "exec_command",
            "tool_input": {"cmd": "git status"},
            "cwd": str(Path.home()),
        },
    }
    assert client.post("/api/hooks/approve", json=body, headers=owner).status_code == 401
    response = client.post(
        "/api/hooks/approve",
        json=body,
        headers={"Authorization": "Bearer " + runtime.hook_token},
    )
    assert response.json() == {"allowed": False, "reason_code": "approval_denied"}
    assert runtime.native.calls[-1][0] == "approve_tool"


def test_native_approval_cannot_override_a_new_block_policy(client, runtime, monkeypatch):
    runtime.change_policy(strict_execution=True)

    def change_policy(_operation, _arguments, timeout=30):
        runtime.change_policy(opaque_tools="block")
        return {"allowed": True}

    monkeypatch.setattr(runtime.native, "call", change_policy)
    response = client.post(
        "/api/hooks/approve",
        headers={"Authorization": "Bearer " + runtime.hook_token},
        json={
            "harness": "opencode",
            "event": {
                "tool_name": "bash",
                "tool_input": {"command": "git status"},
                "cwd": str(Path.home()),
            },
        },
    )
    assert response.json() == {"allowed": False, "reason_code": "execution_policy"}


def test_credential_in_approval_arguments_never_reaches_native_dialog(client, runtime):
    response = client.post(
        "/api/hooks/approve",
        headers={"Authorization": "Bearer " + runtime.hook_token},
        json={
            "harness": "codex",
            "event": {
                "tool_name": "exec_command",
                "tool_input": {"cmd": "echo " + SYNTHETIC["GitHub token"]},
                "cwd": str(Path.home()),
            },
        },
    )
    assert response.json() == {"allowed": False, "reason_code": "invalid_request"}
    assert runtime.native.calls == []


@pytest.mark.parametrize(
    "code", ["approval_denied", "approval_expired", "approval_queue_full", "app_unavailable"]
)
def test_hook_forwards_approval_failure_code_without_sensitive_content(runtime, monkeypatch, capfd, code):
    runtime.change_policy(add={"path": "/example/private", "action": "ask", "kind": "directory"})
    payload = event("/example/private/file")
    stream = io.TextIOWrapper(io.BytesIO(json.dumps(payload).encode()), encoding="utf-8")
    monkeypatch.setattr(sys, "stdin", stream)

    def respond(_state, _method, path, **_kwargs):
        if path == "/api/hooks/approve":
            return {"allowed": False, "reason_code": code}
        return {"recorded": True}

    monkeypatch.setattr("adr_desktop.hooks.request", respond)
    assert run_hook(runtime.state_dir, "codex", guard_protocol=True) == 0
    assert capfd.readouterr().out.splitlines() == ["waiting", f"deny:{code}"]
    assert code in DENIAL_REASONS


def test_opencode_v1_and_v2_interfaces_execute_the_real_guardian(runtime, tmp_path):
    import playwright

    install(
        "opencode",
        runtime.state_dir,
        context_server={
            "command": "/synthetic/ADRCore",
            "args": ["mcp", "--access-file", "/synthetic/access"],
        },
    )
    plugin = tmp_path / "plugin.mjs"
    plugin.write_bytes(configuration_path("opencode").read_bytes())
    directory = tmp_path / "project"
    directory.mkdir()
    secret = SYNTHETIC["GitHub token"]
    (directory / "secret.txt").write_text(secret)
    node = Path(playwright.__file__).parent / "driver" / "node"
    driver = Path(__file__).parent / "opencode_adapter_check.mjs"
    result = subprocess.run(
        [str(node), str(driver), str(plugin), str(directory), secret],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
    assert "contracts passed" in result.stdout
