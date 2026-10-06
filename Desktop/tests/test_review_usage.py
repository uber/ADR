import json
from unittest.mock import patch

import pytest

from adr_desktop.config import atomic_json
from adr_desktop.review_usage import connect, connection_status, report_usage


def test_connect_and_restore_preserve_existing_status_and_other_settings(runtime, monkeypatch, tmp_path):
    directory = tmp_path / "claude"
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(directory))
    path = directory / "settings.json"
    before = {
        "statusLine": {"type": "command", "command": "printf existing", "padding": 2},
        "theme": "dark",
        "hooks": {"Stop": []},
    }
    atomic_json(path, before)
    connect(runtime.state_dir, enabled=True)
    installed = json.loads(path.read_text())
    assert connection_status(runtime.state_dir)
    assert installed["theme"] == before["theme"] and installed["hooks"] == before["hooks"]
    assert installed["statusLine"]["padding"] == 2
    connect(runtime.state_dir, enabled=True)
    connect(runtime.state_dir, enabled=False)
    assert json.loads(path.read_text()) == before
    assert not connection_status(runtime.state_dir)


def test_external_status_line_edits_are_not_overwritten(runtime, monkeypatch, tmp_path):
    directory = tmp_path / "claude"
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(directory))
    connect(runtime.state_dir, enabled=True)
    path = directory / "settings.json"
    changed = {**json.loads(path.read_text()), "statusLine": {"type": "command", "command": "printf new"}}
    atomic_json(path, changed)
    with pytest.raises(ValueError, match="untouched"):
        connect(runtime.state_dir, enabled=False)
    assert json.loads(path.read_text()) == changed


def test_bridge_forwards_only_quota_metadata(runtime):
    payload = {
        "session_id": "do-not-forward",
        "workspace": {"private": "do-not-forward"},
        "rate_limits": {
            "five_hour": {"used_percentage": 42, "resets_at": 1800000000},
            "spend_limit": {"used_usd": 900},
        },
    }
    with patch("adr_desktop.local_client.request") as request:
        report_usage(runtime.state_dir, json.dumps(payload).encode())
    assert request.call_args.kwargs["payload"] == {
        "rate_limits": {"five_hour": {"used_percentage": 42, "resets_at": 1800000000}},
    }


def test_reject_symlink_without_changes(runtime, monkeypatch, tmp_path):
    directory = tmp_path / "claude"
    directory.mkdir()
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(directory))
    other = tmp_path / "other.json"
    other.write_text('{"unrelated": true}')
    (directory / "settings.json").symlink_to(other)
    with pytest.raises(ValueError, match="symlink"):
        connect(runtime.state_dir, enabled=True)
    assert other.read_text() == '{"unrelated": true}'
