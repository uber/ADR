"""Tests for the SystemConfiguration schema."""

from datetime import datetime, timezone

from adr_sensor import host_identity
from adr_sensor.schemas.system_config_schema import (
    DockerInfo,
    HomebrewInfo,
    MCPConfigs,
    NpmInfo,
    OpenCursorWorkspaces,
    PackageManagers,
    PipInfo,
    PythonEnvironments,
    SystemConfiguration,
    SystemInfo,
)


def _configuration(**kwargs):
    return SystemConfiguration(
        timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
        system_info=SystemInfo("platform", "Linux", "6.0", "#1", "x86_64", "x86_64", "3.11.0", "CPython"),
        mcp_configs=MCPConfigs(),
        package_managers=PackageManagers(pip=PipInfo(), npm=NpmInfo(), homebrew=HomebrewInfo()),
        docker=DockerInfo(),
        python_environments=PythonEnvironments(),
        open_cursor_workspaces=OpenCursorWorkspaces(),
        hostname="test-host",
        username="test-user",
        **kwargs,
    )


def test_system_configuration_host_os_defaults_to_host_identity(monkeypatch):
    monkeypatch.setattr(host_identity, "host_os", lambda: "Darwin")
    assert _configuration().host_os == "Darwin"


def test_system_configuration_keeps_explicit_host_os_out_of_the_uuid():
    assert _configuration(host_os="Linux").host_os == "Linux"
    assert _configuration(host_os="Linux").uuid == _configuration(host_os="Windows").uuid
