"""opencode's MCP shape: argv-list commands, `environment`, local/remote types."""

from __future__ import annotations

from adr_discovery.contracts.records import Candidate, Kind
from adr_discovery.extractor import extract
from adr_discovery.pipeline import discover

OPENCODE = {
    "mcp": {
        "files": {
            "type": "local",
            "command": ["npx", "-y", "@mcp/server-filesystem", "--token", "SECRET-VALUE"],
            "environment": {"API_TOKEN": "SECRET-ENV"},
        },
        "docs": {
            "type": "remote",
            "url": "https://u:pw@docs.example/mcp?k=SECRET",
            "headers": {"Authorization": "Bearer SECRET-HDR"},
        },
        "off": {"type": "local", "command": ["uvx", "thing"], "enabled": False},
    }
}
PATH = "/Users/a/.config/opencode/opencode.json"


def _read(world):
    world.json(PATH, OPENCODE)
    return extract(world.gate(), Candidate("marker_file", PATH, "sweep"))


def test_every_opencode_server_is_read(world):
    result = _read(world)

    assert result.errors == ()
    assert result.declared == 3
    by_name = {d.name: d for d in result.declarations}
    files = by_name["files"]
    assert (files.command, files.args[:2]) == ("npx", ("-y", "@mcp/server-filesystem"))
    assert files.env_names == ("API_TOKEN",)
    assert files.raw["transport"] == "stdio"
    assert by_name["docs"].raw["transport"] == "http"
    assert by_name["docs"].url == "https://docs.example/mcp"


def test_no_secret_value_survives(world):
    blob = repr(_read(world).declarations)

    assert "SECRET" not in blob


def test_a_disabled_server_is_emitted_and_flagged(world):
    by_name = {d.name: d for d in _read(world).declarations}

    assert by_name["off"].raw["flags"] == ("disabled",)
    assert "flags" not in by_name["files"].raw


def test_the_disabled_flag_reaches_the_asset(world, catalog):
    world.dir("/Users/a")
    world.json(PATH, OPENCODE)

    snapshot = discover(world.gate(), catalog)

    servers = {a.name: a for a in snapshot.assets if a.kind is Kind.MCP_SERVER}
    assert "disabled" in servers["off"].flags
    assert "disabled" not in servers["files"].flags
