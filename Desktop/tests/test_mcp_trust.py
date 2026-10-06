import json
import sys
from pathlib import Path

import pytest

from adr_desktop.config import atomic_json
from adr_desktop.mcp_trust import trusted_tool


@pytest.fixture
def packaged(runtime, monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", "/synthetic/ADR.app/Contents/Resources/core/ADRCore")
    grant = runtime.create_grant("History", kind="history", confirm_device_history=True)
    monkeypatch.setattr(
        "adr_desktop.mcp_trust.request", lambda *_args, **_kwargs: {"kind": "history", "id": grant["id"]},
    )
    configuration = grant["configuration"]
    atomic_json(Path.home() / ".claude.json", configuration)
    project = Path.home() / "project"
    project.mkdir()
    event = {"tool_name": "mcp__adr_history__adr_search_history", "cwd": str(project)}
    return runtime, event, configuration


def test_packaged_adr_history_can_use_its_explicit_permission_without_an_extra_prompt(packaged):
    runtime, event, _ = packaged
    assert trusted_tool(event, "claude", runtime.state_dir)


def test_name_alone_does_not_make_an_mcp_server_trusted(packaged):
    runtime, event, configuration = packaged
    configuration["mcpServers"]["adr_history"]["command"] = "/bin/sh"
    atomic_json(Path.home() / ".claude.json", configuration)
    assert not trusted_tool(event, "claude", runtime.state_dir)


@pytest.mark.parametrize(
    "change",
    [
        {"env": {"PYTHONPATH": "/untrusted"}},
        {"url": "https://untrusted.example"},
        {"type": "http"},
        {"cwd": "/untrusted"},
        {"enabled": False},
    ],
)
def test_wrappers_environment_and_remote_overrides_are_not_exempt(packaged, change):
    runtime, event, configuration = packaged
    configuration["mcpServers"]["adr_history"].update(change)
    atomic_json(Path.home() / ".claude.json", configuration)
    assert not trusted_tool(event, "claude", runtime.state_dir)


def test_conflicting_project_mcp_server_is_not_exempt(packaged):
    runtime, event, _ = packaged
    atomic_json(
        Path(event["cwd"]) / ".mcp.json",
        {
            "mcpServers": {"adr_history": {"command": "/other/program", "args": []}},
        },
    )
    assert not trusted_tool(event, "claude", runtime.state_dir)


def test_revoked_or_wrong_kind_grant_is_not_exempt(packaged, monkeypatch):
    runtime, event, _ = packaged
    monkeypatch.setattr("adr_desktop.mcp_trust.request", lambda *_args, **_kwargs: {"kind": "vault"})
    assert not trusted_tool(event, "claude", runtime.state_dir)


def test_development_python_launchers_are_not_exempt(packaged, monkeypatch):
    runtime, event, _ = packaged
    monkeypatch.setattr(sys, "frozen", False)
    assert not trusted_tool(event, "claude", runtime.state_dir)


def test_codex_toml_configuration_is_checked(packaged):
    runtime, event, configuration = packaged
    server = configuration["mcpServers"]["adr_history"]
    directory = Path.home() / ".codex"
    directory.mkdir()
    (directory / "config.toml").write_text(
        "[mcp_servers.adr_history]\n"
        f"command = {json.dumps(server['command'])}\nargs = {json.dumps(server['args'])}\n"
    )
    assert trusted_tool(event, "codex", runtime.state_dir)


def test_status_must_confirm_the_same_grant_not_only_its_kind(packaged, monkeypatch):
    runtime, event, _ = packaged
    monkeypatch.setattr(
        "adr_desktop.mcp_trust.request", lambda *_args, **_kwargs: {"kind": "history", "id": "0" * 32},
    )
    assert not trusted_tool(event, "claude", runtime.state_dir)
