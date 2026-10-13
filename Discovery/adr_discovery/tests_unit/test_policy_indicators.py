"""Sanction for assets that have no catalog id."""

from __future__ import annotations

import hashlib

import pytest

from adr_discovery.contracts.records import Asset, Declaration, Kind
from adr_discovery.judge import Policy, judge
from adr_discovery.judge.risk import package_of
from adr_discovery.judge.sanction import state_for
from adr_discovery.pipeline import discover

SHA_A = "a" * 64
SHA_B = "b" * 64


def asset(kind=Kind.MCP_SERVER, name="srv", **kwargs):
    return Asset(asset_id="id-" + name, kind=kind, name=name, identity=name, **kwargs)


def mcp(command=None, args=(), url=None):
    return Declaration(kind=Kind.MCP_SERVER, name="srv", path="/cfg", command=command, args=args, url=url)


def policy(**sections):
    return Policy.from_dict(sections)


def forbid(*indicators):
    return policy(forbidden_indicators=list(indicators))


def approve(*indicators):
    return policy(approved_indicators=list(indicators))


# --------------------------------------------------------------- each kind


def test_skill_sha256_matches_the_skill():
    skill = asset(Kind.SKILL, "s", skill_sha256=SHA_A)

    assert state_for(skill, forbid({"kind": "skill_sha256", "sha256": SHA_A.upper()})) == "forbidden"
    assert state_for(skill, forbid({"kind": "skill_sha256", "sha256": SHA_B})) == "unknown"


def test_file_sha256_matches_content_hash():
    hook = asset(Kind.HOOK, "h", content_hash=SHA_A)

    assert state_for(hook, forbid({"kind": "file_sha256", "sha256": SHA_A})) == "forbidden"
    assert state_for(hook, forbid({"kind": "file_sha256", "sha256": SHA_B})) == "unknown"
    assert state_for(asset(), forbid({"kind": "file_sha256", "sha256": SHA_A})) == "unknown"


def test_mcp_endpoint_is_an_exact_normalized_match():
    declared = mcp(url="https://MCP.example.com/api/")
    indicator = {"kind": "mcp_endpoint", "url": "https://mcp.example.com/api"}

    assert state_for(asset(), forbid(indicator), declared) == "forbidden"
    other = mcp(url="https://mcp.example.com/api/v2")
    assert state_for(asset(), forbid(indicator), other) == "unknown"
    assert state_for(asset(), forbid(indicator), None) == "unknown"


def test_package_matches_launcher_operand_and_version():
    ind = {"kind": "package", "ecosystem": "npm", "name": "evil-mcp", "versions": ["1.0.16"]}

    assert state_for(asset(), forbid(ind), mcp("npx", ("-y", "evil-mcp@1.0.16"))) == "forbidden"
    assert state_for(asset(), forbid(ind), mcp("npx", ("-y", "evil-mcp@1.0.17"))) == "unknown"
    # an unpinned launch cannot be shown to be the listed version
    assert state_for(asset(), forbid(ind), mcp("npx", ("-y", "evil-mcp"))) == "unknown"


def test_package_all_versions_and_pypi_normalization():
    ind = {"kind": "package", "ecosystem": "pypi", "name": "Bad_Pkg", "all_versions": True}

    assert state_for(asset(), forbid(ind), mcp("uvx", ("bad-pkg",))) == "forbidden"
    assert state_for(asset(), forbid(ind), mcp("pipx", ("run", "bad.pkg==2.0"))) == "forbidden"
    assert state_for(asset(), forbid(ind), mcp("uvx", ("--from", "bad-pkg", "cmd"))) == "forbidden"
    assert state_for(asset(), forbid(ind), mcp("npx", ("bad-pkg",))) == "unknown"


def test_package_matches_package_manager_assets():
    ind = {"kind": "package", "ecosystem": "npm", "name": "@scope/tool", "versions": ["2.0.0"]}
    installed = asset(Kind.CLI_AGENT, "tool", package_id="npm:@scope/tool", version="2.0.0")

    assert state_for(installed, forbid(ind)) == "forbidden"
    assert (
        state_for(asset(Kind.CLI_AGENT, "t", package_id="npm:@scope/tool", version="2.0.1"), forbid(ind))
        == "unknown"
    )
    assert (
        state_for(asset(Kind.CLI_AGENT, "t", package_id="pipx:tool", version="2.0.0"), forbid(ind))
        == "unknown"
    )


def test_name_indicator_is_kind_scoped():
    ind = {"kind": "name", "asset_kind": "mcp_server", "name": "srv"}

    assert state_for(asset(), forbid(ind)) == "forbidden"
    assert state_for(asset(Kind.SKILL, "srv"), forbid(ind)) == "unknown"


@pytest.mark.parametrize(
    ("command", "args", "expected"),
    [
        ("npx", ("-y", "@a/b@1.2.3"), ("npm", "@a/b", "1.2.3")),
        ("npx", ("-y", "@a/b"), ("npm", "@a/b", None)),
        ("pnpm", ("dlx", "p@2"), ("npm", "p", "2")),
        ("uvx", ("pkg[extra]==1.0",), ("pypi", "pkg", "1.0")),
        ("uvx", ("pkg>=1.0",), ("pypi", "pkg", None)),
        ("uvx", ("pkg@1.1",), ("pypi", "pkg", "1.1")),
        ("/usr/bin/server", (), None),
        ("docker", ("run", "img:1"), None),
    ],
)
def test_package_of(command, args, expected):
    assert package_of(command, args) == expected


# -------------------------------------------------------------- precedence


def test_forbidden_beats_approved_in_both_forms():
    skill = asset(Kind.SKILL, "s", skill_sha256=SHA_A)
    both = policy(
        approved_indicators=[{"kind": "skill_sha256", "sha256": SHA_A}],
        forbidden_indicators=[{"kind": "skill_sha256", "sha256": SHA_A}],
    )
    assert state_for(skill, both) == "forbidden"

    catalogued = asset(Kind.CLI_AGENT, "c", catalog_id="claude-code")
    mixed = policy(
        approved=["claude-code"],
        forbidden_indicators=[{"kind": "name", "asset_kind": "cli_agent", "name": "c"}],
    )
    assert state_for(catalogued, mixed) == "forbidden"


def test_catalog_sets_behave_as_before():
    catalogued = asset(Kind.CLI_AGENT, "c", catalog_id="claude-code")

    assert state_for(catalogued, policy(approved=["claude-code"])) == "approved"
    assert state_for(catalogued, policy(forbidden=["claude-code"])) == "forbidden"
    assert state_for(catalogued, policy(approved=["other"])) == "unsanctioned"
    assert state_for(catalogued, Policy()) == "unknown"
    assert state_for(asset(), policy(approved=["claude-code"])) == "unknown"


def test_unsanctioned_only_for_kinds_the_policy_addresses():
    allow_skill = approve({"kind": "skill_sha256", "sha256": SHA_A})

    assert state_for(asset(Kind.SKILL, "s", skill_sha256=SHA_A), allow_skill) == "approved"
    assert state_for(asset(Kind.SKILL, "s", skill_sha256=SHA_B), allow_skill) == "unsanctioned"
    assert state_for(asset(Kind.MCP_SERVER), allow_skill) == "unknown"
    assert state_for(asset(Kind.INSTRUCTIONS, "i"), allow_skill) == "unknown"

    allow_pkg = approve({"kind": "package", "ecosystem": "npm", "name": "ok", "all_versions": True})
    assert state_for(asset(), allow_pkg, mcp("npx", ("ok",))) == "approved"
    assert state_for(asset(), allow_pkg, mcp("npx", ("other",))) == "unsanctioned"
    assert state_for(asset(Kind.SKILL, "s"), allow_pkg) == "unknown"

    allow_hash = approve({"kind": "file_sha256", "sha256": SHA_A})
    assert state_for(asset(), allow_hash) == "unknown"


# -------------------------------------------------------------- validation


@pytest.mark.parametrize(
    "bad",
    [
        {"approved_indicators": "x"},
        {"approved_indicators": {"kind": "name"}},
        {"forbidden_indicators": ["x"]},
        {"forbidden_indicators": [{"kind": "bogus"}]},
        {"forbidden_indicators": [{"kind": "skill_sha256"}]},
        {"forbidden_indicators": [{"kind": "skill_sha256", "sha256": "abc"}]},
        {"forbidden_indicators": [{"kind": "skill_sha256", "sha256": SHA_A, "extra": 1}]},
        {"forbidden_indicators": [{"kind": "mcp_endpoint", "url": "ftp://x"}]},
        {"forbidden_indicators": [{"kind": "mcp_endpoint", "url": "not a url"}]},
        {
            "forbidden_indicators": [
                {"kind": "package", "ecosystem": "gem", "name": "x", "all_versions": True}
            ]
        },
        {"forbidden_indicators": [{"kind": "package", "ecosystem": "npm", "name": "x"}]},
        {
            "forbidden_indicators": [
                {"kind": "package", "ecosystem": "npm", "name": "x", "versions": ["1"], "all_versions": True}
            ]
        },
        {"forbidden_indicators": [{"kind": "package", "ecosystem": "npm", "name": "x", "versions": []}]},
        {"forbidden_indicators": [{"kind": "package", "ecosystem": "npm", "name": "x", "versions": [1]}]},
        {"forbidden_indicators": [{"kind": "name", "asset_kind": "nope", "name": "x"}]},
        {"forbidden_indicators": [{"kind": "name", "asset_kind": "skill", "name": ""}]},
    ],
)
def test_invalid_indicators_are_rejected_with_a_clear_message(bad):
    with pytest.raises(ValueError, match=r"policy '?(approved|forbidden)_indicators"):
        Policy.from_dict(bad)


def test_the_example_policy_loads():
    import json
    import os

    here = os.path.dirname(__file__)
    path = os.path.join(here, "..", "..", "examples", "policy.example.json")
    with open(path, encoding="utf-8") as fh:
        loaded = Policy.from_dict(json.load(fh))

    assert loaded.forbidden_indicators and loaded.approved_indicators


# ----------------------------------------------------------------- finding


def test_forbidden_asset_finding_is_raised_for_any_kind():
    skill = asset(Kind.SKILL, "s", skill_sha256=SHA_A)
    clean = asset(Kind.SKILL, "t", skill_sha256=SHA_B)
    pol = forbid({"kind": "skill_sha256", "sha256": SHA_A})

    judged, findings = judge((skill, clean), {}, pol)

    assert [a.sanction for a in judged] == ["forbidden", "unknown"]
    (finding,) = [f for f in findings if f.rule == "forbidden_asset"]
    assert finding.severity == "high"
    assert finding.asset_id == skill.asset_id


def test_judge_uses_the_declaration_for_endpoint_sanction():
    server = asset()
    pol = forbid({"kind": "mcp_endpoint", "url": "https://bad.example/mcp"})

    judged, findings = judge((server,), {server.asset_id: mcp(url="https://bad.example/mcp")}, pol)

    assert judged[0].sanction == "forbidden"
    assert "forbidden_asset" in [f.rule for f in findings]


# -------------------------------------------------------------- end to end


def test_a_skill_is_forbidden_by_the_sha256_of_its_raw_skill_md(world, catalog):
    body = "---\nname: shady\n---\nraw bytes \r\n kept exactly\n"
    digest = hashlib.sha256(body.encode()).hexdigest()
    world.dir("/Users/a")
    world.file("/Users/a/.claude/skills/shady/SKILL.md", body)
    world.file("/Users/a/.claude/skills/fine/SKILL.md", "---\nname: fine\n---\nx\n")
    pol = forbid({"kind": "skill_sha256", "sha256": digest})

    snapshot = discover(world.gate(), catalog, pol)

    by_name = {a.name: a for a in snapshot.assets if a.kind is Kind.SKILL}
    assert by_name["shady"].skill_sha256 == digest
    assert by_name["shady"].sanction == "forbidden"
    assert by_name["fine"].sanction == "unknown"
    assert any(
        f.rule == "forbidden_asset" and f.asset_id == by_name["shady"].asset_id for f in snapshot.findings
    )


def test_an_mcp_server_is_forbidden_by_endpoint_and_by_name_end_to_end(world, catalog):
    world.dir("/Users/a")
    world.json(
        "/Users/a/.claude.json",
        {
            "mcpServers": {
                "remote": {"url": "https://bad.example/mcp"},
                "named": {"command": "/opt/x/server"},
                "ok": {"command": "/opt/y/server"},
            }
        },
    )
    pol = forbid(
        {"kind": "mcp_endpoint", "url": "https://bad.example/mcp"},
        {"kind": "name", "asset_kind": "mcp_server", "name": "named"},
    )

    snapshot = discover(world.gate(), catalog, pol)

    states = {a.name: a.sanction for a in snapshot.assets if a.kind is Kind.MCP_SERVER}
    assert states == {"remote": "forbidden", "named": "forbidden", "ok": "unknown"}


def test_new_asset_fields_round_trip(world, catalog):
    import json

    from adr_discovery.reporter import to_json
    from adr_discovery.reporter.snapshot import from_dict

    world.dir("/Users/a")
    world.file("/Users/a/.claude/skills/s/SKILL.md", "---\nname: s\n---\nx\n")

    snapshot = discover(world.gate(), catalog)
    again = from_dict(json.loads(to_json(snapshot)))

    (skill,) = [a for a in again.assets if a.kind is Kind.SKILL]
    assert skill.skill_sha256 == hashlib.sha256(b"---\nname: s\n---\nx\n").hexdigest()
