"""The degraded "unreadable launch shape" probe fires only for unreadable shapes."""

from __future__ import annotations

import pytest

from adr_discovery.contracts.records import Asset, Declaration, Kind
from adr_discovery.judge import Policy, judge
from adr_discovery.judge.risk import launch_shape, pinning


@pytest.mark.parametrize(
    ("command", "args", "shape", "pinned"),
    [
        ("npx", ("-y", "pkg@1.2.3"), "package_runner", True),
        ("npx", ("-y", "@scope/pkg"), "package_runner", False),
        ("uvx", ("pkg",), "package_runner", False),
        ("uvx", ("pkg==1.0",), "package_runner", True),
        ("pipx", ("run", "pkg==2.0"), "package_runner", True),
        ("bunx", ("pkg@3.0.0",), "package_runner", True),
        ("pnpm", ("dlx", "pkg@1.0.0"), "package_runner", True),
        ("pnpm", ("dlx", "pkg"), "package_runner", False),
        ("yarn", ("dlx", "pkg"), "package_runner", False),
        ("bun", ("x", "pkg@1"), "package_runner", True),
        ("uv", ("tool", "run", "pkg"), "package_runner", False),
        ("docker", ("run", "-i", "--rm", "img:1.2"), "container", False),
        ("docker", ("run", "img@sha256:" + "a" * 64), "container", True),
        ("/opt/server/bin/mcp", (), "local", None),
        ("./bin/server", ("--stdio",), "local", None),
        ("python", ("-m", "my_server"), "local", None),
        ("node", ("server.js",), "local", None),
        ("my-server", (), "local", None),
        ("npx -y pkg@1.2.3", (), "package_runner", True),
    ],
)
def test_common_shapes_are_readable(command, args, shape, pinned):
    assert launch_shape(command, args) == shape
    assert pinning(command, args)[0] is pinned


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("npx", ()),
        ("npx", ("-y",)),
        ("uvx", ("--from",)),
        ("docker", ("run",)),
        ("pnpm dlx", ()),
        ("npx 'unterminated", ()),
        ("--weird", ()),
    ],
)
def test_only_unparseable_launches_are_unknown(command, args):
    assert launch_shape(command, args) == "unknown"


def _probes(kind, command, args=(), url=None):
    from adr_discovery.coverage.ledger import Ledger

    ledger = Ledger()
    subject = Asset(asset_id="id", kind=kind, name="n", identity="n")
    declaration = Declaration(kind=kind, name="n", path="/cfg", command=command, args=args, url=url)
    judge((subject,), {"id": declaration}, Policy(), ledger)
    return [p for p in ledger.freeze().probes if p.status == "degraded"]


def test_normal_mcp_launches_do_not_degrade():
    for command, args in [
        ("npx", ("-y", "pkg@1")),
        ("uvx", ("pkg",)),
        ("/usr/local/bin/srv", ()),
        ("python", ("-m", "mod")),
    ]:
        assert _probes(Kind.MCP_SERVER, command, args) == []


def test_hooks_never_degrade():
    assert _probes(Kind.HOOK, "audit --event pre") == []
    assert _probes(Kind.HOOK, "npx") == []


def test_an_unreadable_mcp_launch_degrades_once():
    (probe,) = _probes(Kind.MCP_SERVER, "npx", ("-y",))
    assert probe.name == "judge"
    assert "unreadable launch shape" in probe.detail


def test_url_servers_do_not_degrade():
    assert _probes(Kind.MCP_SERVER, None, url="https://x.example/mcp") == []
