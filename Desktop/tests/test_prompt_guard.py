import io
import json
import subprocess
import sys
from types import SimpleNamespace

import pytest

from adr_desktop import agent_plugins, hooks, prompt_guard
from adr_desktop.config import atomic_json
from adr_desktop.environment_vault import PROMPT_MESSAGE
from adr_desktop.guard import install_guard, publish_target


@pytest.mark.parametrize("harness", ["claude", "codex"])
def test_prompt_guard_returns_native_block_without_echoing_input(runtime, monkeypatch, capsys, harness):
    secret = "synthetic-password-only-in-input"
    monkeypatch.setattr(
        sys,
        "stdin",
        SimpleNamespace(
            buffer=io.BytesIO(
                json.dumps({"prompt": "My password is " + secret}).encode(),
            )
        ),
    )
    observed = []

    def check(*args, **kwargs):
        observed.append(kwargs["payload"])
        return {"blocked": True, "message": PROMPT_MESSAGE}

    monkeypatch.setattr(prompt_guard, "request", check)
    prompt_guard.run_prompt_hook(runtime.state_dir, harness)
    output = capsys.readouterr().out
    assert json.loads(output)["decision"] == "block"
    assert secret not in output
    assert observed[0]["harness"] == harness


def test_prompt_guard_allows_checked_alias_prompt_without_changing_it(runtime, monkeypatch, capsys):
    monkeypatch.setattr(
        sys,
        "stdin",
        SimpleNamespace(
            buffer=io.BytesIO(
                b'{"prompt":"Run my code with $MY_PASSWORD"}',
            )
        ),
    )
    monkeypatch.setattr(prompt_guard, "request", lambda *_args, **_kwargs: {"blocked": False})
    prompt_guard.run_prompt_hook(runtime.state_dir, "codex")
    assert json.loads(capsys.readouterr().out) == {}


def test_prompt_guard_unavailable_service_blocks_instead_of_silent_send(runtime, monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(b'{"prompt":"hello"}')))

    def unavailable(*_args, **_kwargs):
        raise RuntimeError("synthetic error text that must not be returned")

    monkeypatch.setattr(prompt_guard, "request", unavailable)
    prompt_guard.run_prompt_hook(runtime.state_dir, "codex")
    output = capsys.readouterr().out
    assert json.loads(output)["decision"] == "block"
    assert "synthetic error text" not in output


@pytest.mark.parametrize(("decision", "blocked"), [("pass", False), ("secret", True), ("deny", True)])
def test_compiled_guardian_emits_prompt_decisions(runtime, decision, blocked):
    guardian = install_guard(runtime.state_dir)
    publish_target(runtime.state_dir, [sys.executable, "-c", f"print({decision!r})"])
    result = subprocess.run(
        [str(guardian), "codex", str(runtime.state_dir), "prompt"],
        input='{"prompt":"synthetic"}',
        capture_output=True,
        text=True,
        timeout=6,
    )
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload.get("decision") == ("block" if blocked else None)
    assert "hookSpecificOutput" not in payload


def test_compiled_prompt_guard_fails_closed_if_the_core_is_missing(runtime):
    guardian = install_guard(runtime.state_dir)
    publish_target(runtime.state_dir, ["/this/synthetic/core/does/not/exist"])
    result = subprocess.run(
        [str(guardian), "claude", str(runtime.state_dir), "prompt"],
        input="{}",
        capture_output=True,
        text=True,
        timeout=6,
    )
    assert json.loads(result.stdout)["decision"] == "block"


@pytest.mark.parametrize("harness", ["claude", "codex"])
def test_prompt_install_and_remove_preserve_other_hooks(runtime, tmp_path, harness):
    home = tmp_path / "synthetic-home"
    target = hooks.configuration_path(harness, home)
    foreign = {"hooks": [{"type": "command", "command": "foreign-prompt-check"}]}
    atomic_json(target, {"hooks": {"UserPromptSubmit": [foreign]}})
    hooks.install(harness, runtime.state_dir, home)
    assert hooks.installed(harness, home, phase="prompt", state_dir=runtime.state_dir)
    hooks.uninstall(harness, runtime.state_dir, home)
    assert json.loads(target.read_text())["hooks"]["UserPromptSubmit"] == [foreign]


def test_uninstall_preserves_explicit_empty_prompt_setting(runtime):
    target = hooks.configuration_path("codex")
    atomic_json(target, {"hooks": {"UserPromptSubmit": []}})
    hooks.install("codex", runtime.state_dir)
    hooks.uninstall("codex", runtime.state_dir)
    assert json.loads(target.read_text())["hooks"]["UserPromptSubmit"] == []


def test_native_bundle_advertises_prompt_guard_without_expanding_context_permission(runtime):
    grant = runtime.create_grant("Synthetic context", kind="context", confirm_device_history=True)
    root, _ = agent_plugins.build_bundle(runtime, "codex", grant["id"], "adr-local-codex-0123456789ab")
    hook_config = json.loads((root / "hooks/hooks.json").read_text())
    prompt = hook_config["hooks"]["UserPromptSubmit"][0]["hooks"][0]
    assert " prompt " in prompt["command"]
    assert prompt["timeout"] == 5
    server = json.loads((root / ".mcp.json").read_text())["mcpServers"]
    assert set(server) == {"adr_context"}


def test_normal_shell_using_a_vault_alias_is_redirected_to_credential_runner(runtime):
    runtime.environment_vault.create("Synthetic", "MY_PASSWORD")
    guardian = install_guard(runtime.state_dir)
    result = subprocess.run(
        [str(guardian), "codex", str(runtime.state_dir)],
        input=json.dumps(
            {
                "tool_name": "Bash",
                "tool_input": {"command": 'printf "%s" "$MY_PASSWORD"'},
                "cwd": str(runtime.state_dir.parent),
            }
        ),
        capture_output=True,
        text=True,
        timeout=6,
    )
    output = json.loads(result.stdout)["hookSpecificOutput"]
    assert output["permissionDecision"] == "deny"
    assert "adr_run_command" in output["permissionDecisionReason"]
    assert "synthetic-private-password" not in result.stdout
