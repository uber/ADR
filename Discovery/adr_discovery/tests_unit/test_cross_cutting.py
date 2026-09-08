"""C1 catalog · C2 redaction · C3 coverage.

The three concerns that are not stages. Their cases are shaped differently:
C1 is almost entirely about rejection at load, C2 measures both directions
of a filter, and C3 can only be tested by planting something real and
making it unreachable.
"""

from __future__ import annotations

import json

import pytest

from adr_discovery.catalog.load import CatalogError
from adr_discovery.catalog.load import loads as load_catalog
from adr_discovery.contracts.snapshot import OUT_OF_SCOPE
from adr_discovery.pipeline import discover
from adr_discovery.redact import rules as redact
from adr_discovery.reporter import to_json


def entry(**kwargs):
    base = {"id": "a", "name": "A", "vendor": "V", "kind": "cli_agent"}
    base.update(kwargs)
    return base


# ---------------------------------------------------------------- C1 catalog


def test_uc1_01_an_ambiguous_fingerprint_fails_the_load():
    document = {"entries": [
        entry(id="a", fingerprints={"binaries": ["codex"]}),
        entry(id="b", fingerprints={"binaries": ["codex"]}),
    ]}

    with pytest.raises(CatalogError, match="ambiguous"):
        load_catalog(json.dumps(document))


def test_uc1_02_a_probe_without_a_shape_is_rejected():
    document = {"entries": [entry(proofs={"version_probe": ["--version"]})]}

    with pytest.raises(CatalogError, match="version_shape"):
        load_catalog(json.dumps(document))


def test_uc1_03_a_bad_shape_is_rejected_at_load_not_at_match():
    document = {"entries": [entry(proofs={"version_probe": ["-v"], "version_shape": "[unclosed"})]}

    with pytest.raises(CatalogError, match="regex"):
        load_catalog(json.dumps(document))


def test_uc1_04_the_shipped_catalog_obeys_its_own_rules(catalog):
    assert len(catalog) > 0
    assert catalog.version != "unknown"


# -------------------------------------------------------------- C2 redaction


def test_uc2_01_no_canary_survives_a_full_run(world, catalog):
    world.file("/Users/alice/proj/.mcp.json", json.dumps({"mcpServers": {
        "r": {"url": "https://user:PW-CANARY@h.example:8443/sse?tok=TOK-CANARY",
              "env": {"ANTHROPIC_API_KEY": "sk-ant-KEY-CANARY"}},
    }}))
    gate = world.gate()

    blob = to_json(discover(gate, catalog))

    for canary in ("PW-CANARY", "TOK-CANARY", "sk-ant-KEY-CANARY"):
        assert canary not in blob, f"{canary} escaped"


def test_uc2_02_a_flag_name_survives_redaction():
    """Dropping it is a permission bypass nobody detects, and no leak test
    would notice."""
    scrubbed = redact.scrub_argv(("claude", "-p", "SECRET", "--dangerously-skip-permissions"))

    assert "--dangerously-skip-permissions" in scrubbed
    assert "SECRET" not in scrubbed


def test_uc2_02a_joined_short_credential_operands_are_redacted():
    assert redact.scrub_argv(("mysql", "-uroot", "-pSuperSecret123", "mydb")) == (
        "mysql", "-uroot", f"-p{redact.REDACTED}", "mydb",
    )
    assert redact.scrub_argv(("curl", "-HAuthorization: Bearer secret")) == (
        "curl", f"-H{redact.REDACTED}",
    )


def test_uc2_02b_credential_assignments_without_flags_are_redacted():
    assert redact.scrub_argv(("agent", "password=hunter2")) == (
        "agent", f"password={redact.REDACTED}",
    )
    assert redact.scrub_argv(("agent", "OPENAI_API_KEY=sk-secret")) == (
        "agent", f"OPENAI_API_KEY={redact.REDACTED}",
    )


def test_uc2_02c_noncredential_assignments_are_preserved():
    assert redact.scrub_argv(("server", "--port=8080")) == ("server", "--port=8080")
    assert redact.scrub_argv(("agent", "profile=production")) == ("agent", "profile=production")


def test_uc2_04_explain_names_every_rule_it_enforces():
    lines = redact.explain()

    assert any(str(len(redact.CREDENTIAL_FLAGS)) in line for line in lines)
    assert any(str(len(redact.PERSONAL_PATH_SEGMENTS)) in line for line in lines)


def test_uc2_05_personal_path_denial_is_inherited_from_m1(world):
    """A stage added tomorrow inherits this without containing a rule."""
    world.file("/Users/alice/Documents/notes.json", "{}")
    gate = world.gate()

    assert not gate.read_text("/Users/alice/Documents/notes.json").ok
    assert redact.is_personal("/Users/alice/Documents/notes.json")


# --------------------------------------------------------------- C3 coverage


def test_uc3_01_an_unreachable_asset_is_explained(world, catalog):
    """Plant something real, make it unreachable, require an explanation."""
    world.exe("/opt/hidden/claude", "2.1.234")
    world.unreadable("/opt/hidden")
    gate = world.gate()

    snapshot = discover(gate, catalog)

    assert not snapshot.coverage.is_complete
    assert snapshot.coverage.denied or snapshot.coverage.unavailable


def test_uc3_02_out_of_scope_is_named_on_a_machine_that_has_none(world, catalog):
    snapshot = discover(world.gate(), catalog)

    assert snapshot.coverage.out_of_scope == OUT_OF_SCOPE
    assert "instruction_files" in snapshot.coverage.out_of_scope


def test_uc3_03_every_boundary_kind_is_reachable(world):
    """A boundary type no case can produce is a code path no run exercised."""
    from adr_discovery.coverage.ledger import Ledger

    ledger = Ledger()
    ledger.boundary("/a", "depth")
    ledger.boundary("/b", "entry_cap")
    ledger.boundary("/c", "budget_exhausted")
    ledger.deny("/d", "eacces")
    ledger.unavailable("dpkg", "absent")
    ledger.truncate("/e", 10, 100)

    coverage = ledger.freeze()

    assert {b.boundary for b in coverage.boundaries_hit} == {"depth", "entry_cap", "budget_exhausted"}
    assert coverage.denied and coverage.unavailable and coverage.truncated
    assert not coverage.is_complete


def test_uc2_03_a_stage_that_never_calls_a_redactor_still_cannot_leak():
    """Redaction is carried by the type, not applied by whoever constructs it.

    This is the case that decides whether C2 is a rule or a habit: a final
    pass is something a stage added tomorrow can be placed behind, and a
    constructor is not. The declaration below is built the way a brand-new
    extractor would build one -- raw values, no redactor in sight.
    """
    from adr_discovery.contracts.records import Declaration, Kind

    naive = Declaration(
        kind=Kind.MCP_SERVER,
        name="new-surface",
        path="/cfg",
        command="server",
        args=("--token", "TOK-CANARY", "--api-key=KEY-CANARY", "--model", "opus"),
        url="https://user:PW-CANARY@h.example:8443/sse?tok=Q-CANARY",
        raw={"env": {"ANTHROPIC_API_KEY": "sk-ant-KEY-CANARY"}},
    )

    blob = repr(naive)
    for canary in ("TOK-CANARY", "KEY-CANARY", "PW-CANARY", "Q-CANARY", "sk-ant-KEY-CANARY"):
        assert canary not in blob, f"{canary} survived construction"

    # The other direction: names and shapes are kept, or the record is useless.
    assert "--token" in naive.args and "--model" in naive.args and "opus" in naive.args
    assert naive.url == "https://h.example:8443/sse"
    assert naive.raw["env"] == ("ANTHROPIC_API_KEY",)
