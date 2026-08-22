"""Pytest wrapper for the discovery fidelity suite.

The suite itself is a scorecard runner: it reports per-group agreement rather
than a pass count, because "180 of 192" hides which kind of wrong it is. This
wrapper makes it fail the build when anything regresses.
"""

import pytest

from .framework import run_cases
from .run_suite import load


@pytest.mark.parametrize("case_id", sorted(load()))
def test_case(case_id):
    cases = load()
    results, failures = run_cases({case_id: cases[case_id]})
    assert results, "case %s produced no checks" % case_id
    assert not failures, "\n".join("%s: %s -> %s" % (c, label, detail)
                                   for c, label, _, detail in failures)
