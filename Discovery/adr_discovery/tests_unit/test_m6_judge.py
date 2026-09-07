"""M6 -- judge.

Precision is asserted, not just recall, so the negative cases are the
load-bearing half. U6-09 in particular is two false positives caught on
real machines and by no fixture.
"""

from __future__ import annotations

import pytest

from adr_discovery.contracts.evidence import Band, Channel
from adr_discovery.contracts.records import Asset, Declaration, Kind, Liveness
from adr_discovery.judge import Policy, judge
from adr_discovery.judge.risk import credential_reach, operand_of, pinning, unattended


def declaration(command, args=(), **kwargs):
    return Declaration(kind=Kind.MCP_SERVER, name=kwargs.pop("name", "srv"), path="/cfg",
                       command=command, args=tuple(args), **kwargs)


def asset(name="srv", kind=Kind.MCP_SERVER, **kwargs):
    return Asset(asset_id="id-" + name, kind=kind, name=name, identity=name,
                 catalog_id=kwargs.pop("catalog_id", "srv"),
                 confidence=Band("medium", (Channel.CONFIG,)), **kwargs)


# ------------------------------------------------------------------ pinning


def test_u6_01_unpinned_then_pinned():
    assert pinning("npx", ("-y", "server-github"))[0] is False
    assert pinning("npx", ("-y", "@modelcontextprotocol/server-github@1.4.2"))[0] is True


def test_u6_02_a_volume_mount_is_not_an_image():
    operand, _ = operand_of("docker", ("run", "-v", "/data:/srv", "img:tag"))

    assert operand == "img:tag"


def test_u6_03_a_registry_url_is_not_a_package():
    operand, _ = operand_of("pip", ("install", "--index-url", "https://r/simple", "pkg"))

    assert operand == "pkg"


def test_u6_04_a_digest_is_pinned():
    assert pinning("docker", ("run", "ghcr.io/x/y@sha256:ab34cd56"))[0] is True


# -------------------------------------------------------------- credentials


def test_u6_05_an_absent_env_block_means_all_not_none():
    names, kinds = credential_reach((), env_declared=False)

    assert kinds == ("inherited",)
    assert names == ("<inherits parent environment>",)


def test_u6_06_names_never_values():
    names, kinds = credential_reach(("ANTHROPIC_API_KEY", "PATH"), env_declared=True)

    assert names == ("ANTHROPIC_API_KEY", "PATH")
    assert kinds == ("anthropic",)


# ------------------------------------------------------------------- policy


def test_u6_07_tenant_values_come_from_configuration():
    """One world, two policies, two verdicts. A value reachable from code
    alone cannot pass this."""
    from dataclasses import replace

    from adr_discovery.contracts.records import Risk

    subject = replace(asset(), risk=Risk(destinations=("api.vendor.example",)))

    ours = Policy.from_dict({"tenant_domains": ["vendor.example"]})
    theirs = Policy.from_dict({"tenant_domains": ["corp.internal"]})

    _, none_raised = judge((subject,), {}, ours)
    _, raised = judge((subject,), {}, theirs)

    assert [f.rule for f in none_raised] == []
    assert [f.rule for f in raised] == ["third_party_destination"]


@pytest.mark.parametrize("value", ["claude-code", ["claude-code", 7], {"id": True}])
def test_u6_07b_policy_sets_require_arrays_of_strings(value):
    with pytest.raises(ValueError):
        Policy.from_dict({"approved": value})


def test_u6_07c_tenant_domains_are_normalized():
    policy = Policy.from_dict({"tenant_domains": ["EXAMPLE.COM."]})

    assert policy.tenant_domains == frozenset({"example.com"})


def test_u6_08_unattended_comes_from_the_agents_own_launch():
    """cron, a timer or a person -- the same argv is the same finding."""
    argv = ("-p", "--dangerously-skip-permissions")

    assert unattended(argv)
    assert unattended(("--dangerously-skip-permissions",))
    assert not unattended(("-p",)), "headless alone is not a bypass"


# ---------------------------------------------------------------- precision


def test_u6_09_the_two_false_positives_stay_silent():
    from dataclasses import replace

    from adr_discovery.contracts.records import Risk

    # `npx eslint .` -- a shell's argv is arbitrary user text.
    eslint = replace(
        asset(name="eslint", kind=Kind.CLI_AGENT, catalog_id=None),
        risk=Risk(pinned=False),
    )
    # A command that merely mentions a path containing "mcp".
    mentions = replace(
        asset(name="build", kind=Kind.CLI_AGENT, catalog_id=None),
        risk=Risk(pinned=False),
    )

    _, findings = judge((eslint, mentions), {}, Policy())

    assert findings == (), "neither was caught by the suite the first time"


def test_u6_10_declared_is_silent_and_undeclared_is_not():
    from dataclasses import replace

    declared = asset(name="github", liveness=Liveness.RUNNING)
    undeclared = replace(declared, asset_id="id-undeclared", flags=("undeclared",))

    _, quiet = judge((declared,), {}, Policy())
    _, loud = judge((undeclared,), {}, Policy())

    assert [f.rule for f in quiet] == []
    assert "undeclared_mcp_server" in [f.rule for f in loud]


def test_u6_11_an_unreadable_shape_raises_nothing(world):
    """Ambiguity resolves toward the safe verdict, and is recorded."""
    gate = world.gate()
    subject = asset(name="odd")
    declarations = {subject.asset_id: declaration("some-unknown-runner", ("--weird",), name="odd")}

    judged, findings = judge((subject,), declarations, Policy(), gate.ledger)

    assert judged[0].risk.pinned is None
    assert [f.rule for f in findings if f.rule == "unpinned_mcp_server"] == []
    assert any(p.name == "judge" and p.status == "degraded" for p in gate.ledger.freeze().probes)
