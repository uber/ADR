"""Content identity -- M4 rung 2, and M5's strongest merge key.

These two live together because they are the same read: the hash that
identifies a self-compiled build is the hash that merges a copy of it
found somewhere else.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from adr_discovery.catalog.load import CatalogError
from adr_discovery.catalog.load import loads as load_catalog
from adr_discovery.contracts.evidence import Rung
from adr_discovery.contracts.records import Candidate, Priority
from adr_discovery.identifier import content_hash, identify
from adr_discovery.pipeline import discover

BODY = "#!/bin/sh\necho 2.1.234\n"
DIGEST = hashlib.sha256(BODY.encode()).hexdigest()


def catalog_with_hash(digest=DIGEST):
    return load_catalog(json.dumps({"version": "test", "entries": [{
        "id": "claude-code", "name": "Claude Code", "vendor": "Anthropic", "kind": "cli_agent",
        "fingerprints": {"binaries": ["claude"]},
        "proofs": {"content_hashes": [digest]},
    }]}))


def test_the_loader_indexes_content_hashes():
    """Without this index, rung 2 is dead code that silently never fires."""
    catalog = catalog_with_hash()

    assert catalog.match("content_hashes", DIGEST).id == "claude-code"


def test_a_hash_claimed_by_two_entries_fails_the_load():
    document = {"entries": [
        {"id": "a", "name": "A", "vendor": "V", "kind": "cli_agent",
         "proofs": {"content_hashes": [DIGEST]}},
        {"id": "b", "name": "B", "vendor": "V", "kind": "cli_agent",
         "proofs": {"content_hashes": [DIGEST]}},
    ]}

    with pytest.raises(CatalogError, match="ambiguous"):
        load_catalog(json.dumps(document))


def test_content_identifies_a_build_with_no_package_record(world):
    """A self-compiled binary under a name nobody recognises."""
    world.binary("/opt/built/mystery-tool", BODY)
    gate = world.gate()

    verdict = identify(gate, Candidate("binary", "/opt/built/mystery-tool", "sweep",
                                       Priority.HOME), catalog_with_hash())

    assert verdict.catalog_id == "claude-code"
    assert verdict.rung is Rung.CONTENT
    assert verdict.is_concluded


def test_a_partial_read_never_produces_a_hash(world):
    """A hash of truncated bytes is worse than no hash: it is a confident
    wrong answer that would merge two unrelated things."""
    from adr_discovery.world.budget import Budget

    world.file("/big", "x" * 5000)
    gate = world.gate(budget=Budget(max_read_bytes=1000))

    assert content_hash(gate, "/big") is None


def test_two_copies_of_one_binary_are_one_asset(world):
    """Same bytes, two paths, no package record and no shared inode --
    content is the only key that can merge them."""
    world.binary("/opt/a/claude", BODY)
    world.binary("/opt/b/claude", BODY)
    gate = world.gate()

    snapshot = discover(gate, catalog_with_hash())

    agents = [a for a in snapshot.assets if a.catalog_id == "claude-code"]
    assert len(agents) == 1, "a copy is not a second install"
    assert "merged_2" in agents[0].flags
