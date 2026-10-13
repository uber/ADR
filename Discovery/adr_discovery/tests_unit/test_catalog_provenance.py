"""Catalog `proofs.provenance` entries are matchable as package identities."""

from __future__ import annotations

import json

import pytest

from adr_discovery.catalog.load import CatalogError, loads
from adr_discovery.contracts.evidence import Rung
from adr_discovery.contracts.records import Candidate
from adr_discovery.identifier import identify


def test_a_brew_package_record_identifies_claude_code(world, catalog):
    path = "/opt/homebrew/bin/claude"
    world.exe(path, "2.1.234")
    candidate = Candidate(
        kind="binary",
        path=path,
        source="package:brew",
        detail={"name": "claude", "version": "2.1.234"},
    )

    verdict = identify(world.gate(), candidate, catalog)

    assert verdict.catalog_id == "claude-code"
    assert verdict.rung is Rung.PROVENANCE


def test_every_provenance_entry_in_the_shipped_catalog_matches(catalog):
    entries = [(e.id, p) for e in catalog.entries for p in e.provenance]

    assert entries
    for entry_id, provenance in entries:
        assert catalog.match("packages", provenance).id == entry_id


def _catalog(*entries):
    return loads(json.dumps({"version": "t", "entries": list(entries)}))


def _entry(entry_id, packages=(), provenance=()):
    return {
        "id": entry_id,
        "name": entry_id,
        "vendor": "v",
        "kind": "cli_agent",
        "fingerprints": {"packages": list(packages)},
        "proofs": {"provenance": list(provenance)},
    }


def test_the_same_package_in_fingerprints_and_provenance_of_one_entry_is_fine():
    loaded = _catalog(_entry("a", packages=["npm:x"], provenance=["npm:x", "brew:a"]))

    assert loaded.match("packages", "brew:a").id == "a"


def test_provenance_claimed_by_two_entries_is_ambiguous():
    with pytest.raises(CatalogError, match="ambiguous"):
        _catalog(_entry("a", provenance=["brew:tool"]), _entry("b", packages=["brew:tool"]))
