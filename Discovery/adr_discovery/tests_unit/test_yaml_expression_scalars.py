"""Braces inside a plain scalar are text, not a flow collection.

Nearly every real workflow passes secrets as `${{ secrets.NAME }}`; the
subset parser must read those lines and still refuse true flow values.
"""

from __future__ import annotations

import pytest

from adr_discovery.contracts.records import Candidate, Kind
from adr_discovery.extractor import extract
from adr_discovery.extractor.formats.yaml import Unrepresentable, loads

WORKFLOW = """name: review
on:
  pull_request:
jobs:
  review:
    if: ${{ github.event.pull_request.draft == false }}
    steps:
      - uses: anthropics/claude-code-action@v1
        env:
          GH_TOKEN: ${{ github.token }}
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
"""


def test_expressions_are_read_as_plain_text():
    doc = loads("a: ${{ secrets.K }}\nb: x[0]\nc:\n  - ${{ matrix.os }}\n")

    assert doc == {"a": "${{ secrets.K }}", "b": "x[0]", "c": ["${{ matrix.os }}"]}


@pytest.mark.parametrize("text", ["a: {b: 1}\n", "a: [1, 2]\n", "a:\n  - [1]\n", "a:\n  - {b: 1}\n"])
def test_flow_collections_are_still_refused(text):
    with pytest.raises(Unrepresentable):
        loads(text)


def test_a_workflow_using_expressions_yields_its_agent_step(world):
    path = "/proj/.github/workflows/review.yml"
    world.file(path, WORKFLOW)

    result = extract(world.gate(), Candidate(kind="marker_file", path=path, source="sweep"))

    assert result.errors == ()
    (declaration,) = result.declarations
    assert declaration.kind is Kind.CI_AGENT
    assert "with.anthropic_api_key" in declaration.env_names
    assert "secrets.ANTHROPIC_API_KEY" not in repr(declaration)
