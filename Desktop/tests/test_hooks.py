import json

import pytest

from adr_desktop import hooks
from adr_desktop.config import atomic_json


def test_claude_install_preserves_settings_and_other_hooks(runtime, tmp_path):
    home = tmp_path / "fixture-home"
    target = hooks.configuration_path("claude", home)
    original = {
        "permissions": {"deny": ["Read(example)"]},
        "hooks": {
            "PreToolUse": [{"matcher": "Read", "hooks": [{"type": "command", "command": "echo keep"}]}]
        },
    }
    atomic_json(target, original)
    result = hooks.install("claude", runtime.state_dir, home, prefix=["/path with spaces/ADRCore"])
    config = json.loads(target.read_text())
    assert config["permissions"] == original["permissions"]
    assert config["hooks"]["PreToolUse"][0] == original["hooks"]["PreToolUse"][0]
    assert result["backup"]
    assert hooks.installed("claude", home)
    # A user later adds their own hook to ADR's matcher group.
    config["hooks"]["PreToolUse"][-1]["hooks"].append({"type": "command", "command": "echo user-added"})
    atomic_json(target, config)
    hooks.install("claude", runtime.state_dir, home, prefix=["/path with spaces/ADRCore"])
    hooks.uninstall("claude", runtime.state_dir, home)
    remaining = json.loads(target.read_text())
    commands = [hook["command"] for group in remaining["hooks"]["PreToolUse"] for hook in group["hooks"]]
    assert commands == ["echo keep", "echo user-added"]
    assert not hooks.installed("claude", home)


def test_copilot_uses_user_hook_schema_and_installs_idempotently(runtime, tmp_path):
    home = tmp_path / "fixture-home"
    hooks.install("copilot", runtime.state_dir, home, prefix=["/example/ADRCore"])
    hooks.install("copilot", runtime.state_dir, home, prefix=["/example/ADRCore"])
    content = json.loads(hooks.configuration_path("copilot", home).read_text())
    assert content["version"] == 1
    assert len(content["hooks"]["preToolUse"]) == 1
    assert set(content["hooks"]["preToolUse"][0]) == {"type", "bash", "timeoutSec"}
    assert hooks.installed("copilot", home)
    hooks.uninstall("copilot", runtime.state_dir, home)
    assert not hooks.installed("copilot", home)


def test_invalid_config_is_not_replaced(runtime, tmp_path):
    home = tmp_path / "fixture-home"
    target = hooks.configuration_path("claude", home)
    target.parent.mkdir(parents=True)
    target.write_text("not json")
    with pytest.raises(ValueError):
        hooks.install("claude", runtime.state_dir, home)
    assert target.read_text() == "not json"


def test_symlinked_config_is_not_overwritten(runtime, tmp_path):
    home = tmp_path / "fixture-home"
    target = hooks.configuration_path("claude", home)
    target.parent.mkdir(parents=True)
    outside = tmp_path / "outside.json"
    outside.write_text("{}")
    target.symlink_to(outside)
    with pytest.raises(ValueError):
        hooks.install("claude", runtime.state_dir, home)
    assert outside.read_text() == "{}"
