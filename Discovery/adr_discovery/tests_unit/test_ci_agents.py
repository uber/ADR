"""CI agents -- an agent arranged to run with no person present.

Invisible to every other source: nothing about it exists on the endpoint
except a YAML file in a directory no binary scan reads.
"""

from __future__ import annotations

from adr_discovery.contracts.records import Candidate, Kind
from adr_discovery.extractor import extract
from adr_discovery.pipeline import discover

WORKFLOW = """name: review
on:
  pull_request:
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: anthropics/claude-code-action@v1
        env:
          ANTHROPIC_API_KEY: secret-value-here
        with:
          mode: agent
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@v4
      - uses: actions/cache@v4
"""


def read(world, path="/proj/.github/workflows/review.yml", body=WORKFLOW):
    world.file(path, body)
    return extract(world.gate(), Candidate(kind="marker_file", path=path, source="sweep"))


def test_an_agent_step_becomes_a_declaration(world):
    result = read(world)

    (declaration,) = result.declarations
    assert declaration.kind is Kind.CI_AGENT
    assert declaration.raw["catalog_id"] == "claude-code"
    assert declaration.raw["job"] == "review"
    assert declaration.raw["unattended"] is True


def test_build_steps_are_not_agents(world):
    """`uses: actions/checkout@v4` is not an AI agent however many agents
    run after it -- the precision half of this source."""
    result = read(world)

    assert len(result.declarations) == 1, "only the agent step counts"


def test_env_names_survive_and_values_do_not(world):
    (declaration,) = read(world).declarations

    assert "ANTHROPIC_API_KEY" in declaration.env_names
    assert "with.mode" in declaration.env_names
    assert "secret-value-here" not in repr(declaration)


def test_a_workflow_with_no_agent_yields_nothing(world):
    result = read(world, body="""name: ci
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
""")

    assert result.declarations == () and result.declared == 0


def test_a_ci_agent_reaches_the_snapshot(world, catalog):
    world.file("/Users/a/proj/.github/workflows/review.yml", WORKFLOW)

    snapshot = discover(world.gate(), catalog)

    agents = [a for a in snapshot.assets if a.kind is Kind.CI_AGENT]
    assert len(agents) == 1
    assert "claude-code-action" in agents[0].name


def test_a_ci_agent_carries_its_catalog_id_and_is_sanctioned(world, catalog):
    from adr_discovery.judge import Policy

    world.file("/Users/a/proj/.github/workflows/review.yml", WORKFLOW)

    open_snapshot = discover(world.gate(), catalog)
    (agent,) = [a for a in open_snapshot.assets if a.kind is Kind.CI_AGENT]
    assert agent.catalog_id == "claude-code"
    assert agent.sanction == "unknown"
    # unattended by construction is not a permission-bypass finding
    assert [f.rule for f in open_snapshot.findings if f.asset_id == agent.asset_id] == []

    forbidden = discover(world.gate(), catalog, Policy.from_dict({"forbidden": ["claude-code"]}))
    (agent,) = [a for a in forbidden.assets if a.kind is Kind.CI_AGENT]
    assert agent.sanction == "forbidden"
    assert [f.rule for f in forbidden.findings if f.asset_id == agent.asset_id] == ["forbidden_asset"]

    approved = discover(world.gate(), catalog, Policy.from_dict({"approved": ["codex-cli"]}))
    (agent,) = [a for a in approved.assets if a.kind is Kind.CI_AGENT]
    assert agent.sanction == "unsanctioned"


def test_catalogued_ci_steps_stay_separate_assets_and_take_no_local_telemetry(world, catalog):
    world.file("/Users/a/proj/.github/workflows/a.yml", WORKFLOW)
    world.file("/Users/a/proj/.github/workflows/b.yml", WORKFLOW)

    snapshot = discover(
        world.gate(), catalog, telemetry={"claude-code": "2026-08-21T09:12:00+00:00"}
    )

    agents = [a for a in snapshot.assets if a.kind is Kind.CI_AGENT]
    assert len(agents) == 2
    assert {a.catalog_id for a in agents} == {"claude-code"}
    assert all(a.last_used is None for a in agents)
