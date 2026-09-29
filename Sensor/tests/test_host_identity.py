"""Tests for host identity resolution."""

import os
import sys

import pytest

from adr_sensor import host_identity


@pytest.fixture(autouse=True)
def fresh_identity():
    for resolver in (host_identity.username, host_identity.hostname, host_identity.host_os):
        resolver.cache_clear()
    yield
    for resolver in (host_identity.username, host_identity.hostname, host_identity.host_os):
        resolver.cache_clear()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX account lookup")
def test_username_comes_from_the_process_account_not_environment_variables(monkeypatch):
    import pwd

    for name in ("USER", "USERNAME", "LOGNAME", "SUDO_USER"):
        monkeypatch.setenv(name, "spoofed-user")
    assert host_identity.username() == pwd.getpwuid(os.geteuid()).pw_name
    assert host_identity.username() != "spoofed-user"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX account lookup")
def test_username_falls_back_when_the_account_cannot_be_resolved(monkeypatch):
    import pwd

    def no_account(uid):
        raise KeyError(uid)

    monkeypatch.setattr(pwd, "getpwuid", no_account)
    monkeypatch.setenv("USER", "spoofed-user")
    assert host_identity.username() == "unknown_user"


def test_hostname_falls_back_when_unavailable(monkeypatch):
    def fail():
        raise OSError("synthetic")

    monkeypatch.setattr(host_identity.socket, "gethostname", fail)
    assert host_identity.hostname() == "unknown_hostname"


@pytest.mark.parametrize(("system", "expected"), [("Linux", "Linux"), ("", None)])
def test_host_os_uses_platform_system(monkeypatch, system, expected):
    monkeypatch.setattr(host_identity.platform, "system", lambda: system)
    assert host_identity.host_os() == expected


def test_host_os_is_none_when_platform_fails(monkeypatch):
    def fail():
        raise OSError("synthetic")

    monkeypatch.setattr(host_identity.platform, "system", fail)
    assert host_identity.host_os() is None


def test_identity_is_resolved_once_per_process(monkeypatch):
    calls = []

    def gethostname():
        calls.append(1)
        return "host-a"

    monkeypatch.setattr(host_identity.socket, "gethostname", gethostname)
    assert host_identity.hostname() == host_identity.hostname() == "host-a"
    assert len(calls) == 1
