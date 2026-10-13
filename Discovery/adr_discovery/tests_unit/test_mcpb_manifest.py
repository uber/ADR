"""A valid MCP bundle manifest is inventory; before, it produced nothing."""

from __future__ import annotations

from adr_discovery.contracts.records import Candidate, Kind
from adr_discovery.extractor import extract
from adr_discovery.pipeline import discover

PATH = "/Users/a/ext/notes/.mcpb/manifest.json"
MANIFEST = {
    "manifest_version": "0.2",
    "name": "notes-server",
    "version": "1.2.3",
    "description": "Summarise the EMEA ledger",
    "server": {
        "type": "node",
        "entry_point": "server/index.js",
        "mcp_config": {
            "command": "node",
            "args": ["${__dirname}/server/index.js", "--api-key=SECRET-ARG"],
            "env": {"NOTES_TOKEN": "SECRET-ENV"},
        },
    },
}


def _read(world, document=MANIFEST):
    world.json(PATH, document)
    return extract(world.gate(), Candidate("marker_file", PATH, "sweep"))


def test_a_valid_manifest_becomes_a_bundle(world):
    result = _read(world)

    assert result.errors == () and result.declared == 1
    (bundle,) = result.declarations
    assert bundle.kind is Kind.MCP_BUNDLE
    assert bundle.name == "notes-server"
    assert bundle.command == "node"
    assert bundle.args[0] == "${__dirname}/server/index.js"
    assert bundle.env_names == ("NOTES_TOKEN",)
    assert bundle.raw["version"] == "1.2.3"
    assert bundle.raw["bundle_runtime"] == "node"


def test_secrets_and_prose_are_not_collected(world):
    blob = repr(_read(world).declarations)

    assert "SECRET" not in blob and "EMEA" not in blob


def test_a_manifest_without_a_server_is_flagged_malformed(world):
    result = _read(world, {"name": "x", "version": "1"})

    (bundle,) = result.declarations
    assert bundle.raw["flags"] == ("malformed",)
    assert len(result.errors) == 1


def test_the_bundle_reaches_the_snapshot_with_its_version(world, catalog):
    world.dir("/Users/a")
    world.json(PATH, MANIFEST)

    snapshot = discover(world.gate(), catalog)

    (asset,) = [a for a in snapshot.assets if a.kind is Kind.MCP_BUNDLE]
    assert asset.name == "notes-server"
    assert asset.version == "1.2.3"
