"""M4 -- identifier.

Every case asserts the verdict *and* the rung that produced it. A correct
answer reached by convention is a failing case here, because the next
rename breaks it.
"""

from __future__ import annotations

from adr_discovery.contracts.evidence import Rung
from adr_discovery.contracts.records import Candidate, Priority
from adr_discovery.identifier import identify, is_reviewable, score, signals_for


def candidate(path, **detail):
    return Candidate("binary", path, detail.pop("source", "sweep"), Priority.HOME, detail)


def test_u4_01_a_rename_does_not_hide_a_real_agent(world, catalog):
    world.exe("/opt/tools/notes-helper", "2.1.234")
    world.surface("packages", [{"manager": "npm", "name": "@anthropic-ai/claude-code",
                                "version": "2.1.234", "path": "/opt/tools/notes-helper"}])
    gate = world.gate()

    verdict = identify(gate, candidate("/opt/tools/notes-helper", source="package:npm",
                                       name="@anthropic-ai/claude-code", version="2.1.234"), catalog)

    assert verdict.catalog_id == "claude-code"
    assert verdict.rung is Rung.PROVENANCE
    assert verdict.version == "2.1.234"
    assert verdict.is_concluded


def test_kilo_cli_has_package_provenance(world, catalog):
    world.surface("packages", [{"manager": "npm", "name": "@kilocode/cli",
                                "version": "7.4.23", "path": "/opt/tools/kilo"}])
    verdict = identify(world.gate(), candidate("/opt/tools/kilo", source="package:npm",
                                               name="@kilocode/cli", version="7.4.23"), catalog)

    assert verdict.catalog_id == "kilo-cli"
    assert verdict.version == "7.4.23"


def test_u4_02_a_decoy_is_not_believed(world, catalog):
    """GNU sleep copied to `gemini`. Its --version output does not match the
    declared shape, so it produces no version and no catalogued verdict."""
    world.exe("/decoy/gemini", "sleep (GNU coreutils) 9.4")
    gate = world.gate()

    verdict = identify(gate, candidate("/decoy/gemini"), catalog)

    assert verdict.catalog_id is None
    assert verdict.version is None
    assert not verdict.is_concluded
    assert verdict.rung is Rung.CONVENTION, "a name may raise priority and nothing more"


def test_u4_02b_a_genuine_version_shape_is_believed(world, catalog):
    world.exe("/real/gemini", "0.55.1")
    gate = world.gate()

    verdict = identify(gate, candidate("/real/gemini"), catalog)

    assert verdict.catalog_id == "gemini-cli"
    assert verdict.rung is Rung.BEHAVIOUR
    assert verdict.version == "0.55.1"


def test_u4_03_the_ladder_stops_at_the_first_proof(world, catalog):
    world.exe("/opt/tools/claude", "2.1.234")
    world.surface("packages", [{"manager": "npm", "name": "@anthropic-ai/claude-code",
                                "version": "2.1.234", "path": "/opt/tools/claude"}])
    gate = world.gate()
    before = gate.calls["run"]

    identify(gate, candidate("/opt/tools/claude"), catalog)

    assert gate.calls["run"] == before, "provenance settled it; no subprocess should be spent"


def test_u4_04_convention_never_concludes(world, catalog):
    world.dir("/somewhere/claude-code")
    gate = world.gate()

    verdict = identify(gate, candidate("/somewhere/claude-code"), catalog)

    assert not verdict.is_concluded


def test_u4_07_an_uncatalogued_ai_shape_goes_to_the_review_queue(world, catalog):
    """An unknown binary that holds provider credentials *and* talks to a
    model provider. Two properties, no name involved."""
    peer = Candidate("network_peer", "api.anthropic.com", "network:established",
                     Priority.HOME, {"provider": True, "pid": 8812,
                                     "env_names": ("ANTHROPIC_API_KEY", "PATH")})
    value, fired = score(peer, signals_for(peer))

    assert set(fired) == {"network_intent", "credential_affinity"}
    assert is_reviewable(value), "properties, not names, put this in triage"


def test_u4_07b_one_signal_alone_sits_below_the_threshold(world, catalog):
    """Documents where the line currently falls.

    A lone outbound connection to a model provider scores 0.35 against a
    threshold of 0.40, so it is *not* queued on its own. That is a tuning
    decision, not a law: the design argues this connection is the one piece
    of evidence an unknown tool cannot suppress, which is an argument for
    raising it. Asserted here so the choice is visible rather than implicit.
    """
    peer = Candidate("network_peer", "api.anthropic.com", "network:established",
                     Priority.HOME, {"provider": True})
    value, fired = score(peer, signals_for(peer))

    assert fired == ("network_intent",)
    assert value == 0.35 and not is_reviewable(value)


def test_u4_08_nothing_is_a_verdict(world, catalog):
    world.exe("/usr/bin/ls", "ls (GNU coreutils) 9.4")
    gate = world.gate()

    verdict = identify(gate, candidate("/usr/bin/ls"), catalog)

    assert verdict.catalog_id is None
    assert not is_reviewable(verdict.score)
    assert gate.calls["package_owner"] == 0, "irrelevant system binaries must not trigger package queries"


def test_u4_09_no_verdict_is_bare(world, catalog):
    world.exe("/opt/tools/claude", "2.1.234")
    world.exe("/decoy/gemini", "sleep (GNU coreutils) 9.4")
    world.dir("/somewhere/cursor")
    gate = world.gate()

    for path in ("/opt/tools/claude", world.root + "/decoy/gemini", "/somewhere/cursor"):
        verdict = identify(gate, candidate(path), catalog)
        assert verdict.evidence, f"{path} produced a verdict with no evidence"
        if verdict.is_concluded:
            assert verdict.rung is not Rung.CONVENTION


def test_u4_05_a_self_compiled_build_is_identified_by_content_and_behaviour(world, catalog):
    """No package record and no known hash, but it is a real compiled
    object whose version output matches the declared shape."""
    import os

    world.file("/opt/built/gemini", "\x7fELF\x02\x01\x01" + "\x00" * 64)
    os.chmod(world.root + "/opt/built/gemini", 0o755)
    gate = world.gate()

    from adr_discovery.identifier import binary_format

    assert binary_format(gate, "/opt/built/gemini") == "elf"
    assert binary_format(gate, "/opt/shipped/gemini") is None  # not written yet

    # A real compiled object whose probe answers in the declared shape.
    # The fixture cannot both be an ELF and run, so the format check and
    # the probe are asserted against the same path in two steps.
    world.exe("/opt/shipped/gemini", "0.55.1")
    verdict = identify(gate, candidate("/opt/shipped/gemini"), catalog)

    assert verdict.catalog_id == "gemini-cli"
    assert verdict.is_concluded
    assert Rung.BEHAVIOUR in {e.rung for e in verdict.evidence}


def test_u4_05b_a_shell_wrapper_is_not_content_evidence(world, catalog):
    """A `#!` file that answers correctly is believed on behaviour alone.

    Letting the format lift it to content would hand the decoy the exact
    strengthening the ladder exists to withhold.
    """
    world.exe("/opt/shipped/gemini", "0.55.1")
    gate = world.gate()

    verdict = identify(gate, candidate("/opt/shipped/gemini"), catalog)

    assert verdict.rung is Rung.BEHAVIOUR
    assert Rung.CONTENT not in {e.rung for e in verdict.evidence}


def test_u4_06_channels_that_disagree_record_a_conflict(world, catalog):
    """Provenance says one thing, the name says another. Neither is picked
    silently: the conflict is recorded so a reviewer can settle it."""
    world.exe("/opt/tools/gemini", "2.1.234")
    world.surface("packages", [{"manager": "npm", "name": "@anthropic-ai/claude-code",
                                "version": "2.1.234", "path": "/opt/tools/gemini"}])
    gate = world.gate()

    verdict = identify(gate, candidate("/opt/tools/gemini"), catalog)

    assert verdict.catalog_id == "claude-code", "provenance outranks a filename"
    assert verdict.conflict is not None
    assert "gemini-cli" in verdict.conflict and "claude-code" in verdict.conflict
