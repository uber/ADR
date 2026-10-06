import json
import subprocess
import sys
import time

import pytest

from adr_desktop.config import atomic_json, read_private_json
from adr_desktop.guard import GUARD_VERSION, install_guard, publish_target, upgrade_guard
from adr_desktop.policy import DENIAL_REASONS


@pytest.fixture
def guardian(runtime):
    return install_guard(runtime.state_dir)


@pytest.mark.parametrize("harness", ["claude", "copilot"])
def test_guard_is_fail_closed_when_core_is_missing(runtime, guardian, harness):
    publish_target(runtime.state_dir, ["/this/core/does/not/exist"])
    result = subprocess.run(
        [str(guardian), harness, str(runtime.state_dir)],
        input="{}",
        capture_output=True,
        text=True,
        timeout=6,
    )
    assert result.returncode == 0
    value = json.loads(result.stdout)
    assert value.get("hookSpecificOutput", value)["permissionDecision"] == "deny"


@pytest.mark.parametrize("output", ["garbage", "", "pass\\x00deny", "pass" * 100])
def test_guard_rejects_malformed_output(runtime, guardian, output):
    publish_target(runtime.state_dir, [sys.executable, "-c", f"print({output!r})"])
    result = subprocess.run(
        [str(guardian), "copilot", str(runtime.state_dir)],
        input="{}",
        capture_output=True,
        text=True,
        timeout=6,
    )
    assert json.loads(result.stdout)["permissionDecision"] == "deny"


def test_guard_returns_pass_without_overriding_native_permissions(runtime, guardian):
    publish_target(runtime.state_dir, [sys.executable, "-c", "print('pass')"])
    result = subprocess.run(
        [str(guardian), "claude", str(runtime.state_dir)],
        input="{}",
        capture_output=True,
        text=True,
        timeout=6,
    )
    assert json.loads(result.stdout) == {}


def test_guard_deadline_stops_a_stalled_core(runtime, guardian):
    publish_target(runtime.state_dir, [sys.executable, "-c", "import time; time.sleep(30)"])
    started = time.monotonic()
    result = subprocess.run(
        [str(guardian), "claude", str(runtime.state_dir)],
        input="{}",
        capture_output=True,
        text=True,
        timeout=6,
    )
    assert time.monotonic() - started < 5
    assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_guard_executes_real_cached_policy_offline(runtime, guardian):
    result = subprocess.run(
        [str(guardian), "claude", str(runtime.state_dir)],
        input=json.dumps(
            {
                "tool_name": "Read",
                "tool_input": {"file_path": str(runtime.state_dir / "policy.json")},
                "cwd": str(runtime.state_dir),
            }
        ),
        capture_output=True,
        text=True,
        timeout=6,
    )
    assert result.returncode == 0
    assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "protected file" in result.stdout


@pytest.mark.parametrize("code", list(DENIAL_REASONS))
def test_guard_preserves_closed_reason_codes(runtime, guardian, code):
    publish_target(runtime.state_dir, [sys.executable, "-c", f"print('deny:{code}')"])
    result = subprocess.run(
        [str(guardian), "codex", str(runtime.state_dir)],
        input="{}", capture_output=True, text=True, timeout=6,
    )
    output = json.loads(result.stdout)["hookSpecificOutput"]
    assert output["permissionDecision"] == "deny"
    assert output["permissionDecisionReason"] == DENIAL_REASONS[code]


def test_unknown_reason_code_cannot_inject_a_harness_response(runtime, guardian):
    publish_target(runtime.state_dir, [sys.executable, "-c", "print('deny:arbitrary-untrusted-text')"])
    result = subprocess.run(
        [str(guardian), "codex", str(runtime.state_dir)],
        input="{}", capture_output=True, text=True, timeout=6,
    )
    assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "arbitrary-untrusted-text" not in result.stdout


@pytest.mark.parametrize("tool", ["Bash", "exec_command", "collaborationsend_message"])
def test_real_guardian_does_not_request_approval_for_unrelated_tools(runtime, guardian, tool):
    result = subprocess.run(
        [str(guardian), "codex", str(runtime.state_dir)],
        input=json.dumps({
            "tool_name": tool,
            "tool_input": {"command": "pwd"},
            "cwd": "/example/workspace",
        }),
        capture_output=True, text=True, timeout=6,
    )
    assert json.loads(result.stdout) == {}


def test_existing_guard_is_upgraded_without_changing_plugin_registration(runtime, guardian):
    before = (runtime.state_dir / "policy.json").read_bytes()
    atomic_json(runtime.state_dir / "guard-version.json", {"version": 2})
    assert upgrade_guard(runtime.state_dir) is True
    assert read_private_json(runtime.state_dir / "guard-version.json") == {"version": GUARD_VERSION}
    assert (runtime.state_dir / "policy.json").read_bytes() == before
    assert upgrade_guard(runtime.state_dir) is False


def test_upgrade_does_not_install_a_missing_guard(runtime):
    assert upgrade_guard(runtime.state_dir) is False
    assert not (runtime.state_dir / "bin" / "adr-hook").exists()
