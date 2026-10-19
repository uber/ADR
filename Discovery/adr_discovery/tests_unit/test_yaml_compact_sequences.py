"""A block sequence may sit at its parent key's own column.

`steps:` followed by `- uses: ...` at the same indentation is ordinary
YAML and the layout GitHub's own starter workflows use.
"""

from __future__ import annotations

import pytest

from adr_discovery.contracts.records import Candidate, Kind
from adr_discovery.extractor import extract
from adr_discovery.extractor.formats.yaml import Unrepresentable, loads

COMPACT = """jobs:
  review:
    steps:
    - uses: actions/checkout@v4
    - uses: anthropics/claude-code-action@v1
      with:
        mode: agent
"""


def test_a_compact_sequence_is_the_value_of_its_key():
    steps = loads(COMPACT)["jobs"]["review"]["steps"]

    assert steps == [
        {"uses": "actions/checkout@v4"},
        {"uses": "anthropics/claude-code-action@v1", "with": {"mode": "agent"}},
    ]


def test_a_compact_sequence_of_scalars():
    assert loads("on:\n  push:\n    branches:\n    - main\n    - dev\n") == {
        "on": {"push": {"branches": ["main", "dev"]}}
    }


def test_a_stray_dash_line_is_refused_not_read_as_a_key():
    with pytest.raises(Unrepresentable):
        loads("a: 1\n- b: 2\n")


def test_a_compact_workflow_yields_its_agent_step(world):
    path = "/proj/.github/workflows/review.yml"
    world.file(path, COMPACT)

    result = extract(world.gate(), Candidate(kind="marker_file", path=path, source="sweep"))

    (declaration,) = result.declarations
    assert declaration.kind is Kind.CI_AGENT
    assert declaration.raw["catalog_id"] == "claude-code"
