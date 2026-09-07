"""The scorer, and proof that it moves when something is actually wrong.

A scorer that has only ever seen a perfect run is a scorer nobody has tested.
Each fault below is one of the conditions the gate exists to catch, injected
deliberately, with the score asserted to respond.
"""

import json
import os
import tempfile
import unittest

from . import manifest as manifest_module
from .scoring import schema, snapshot
from .scoring.score import score
from .tools import synthesize

RECORDED = os.path.join(os.path.dirname(os.path.abspath(__file__)), "recorded", "synthetic-linux")


def run_and_score(*faults, platform="linux", **plan):
    """Both halves, because some properties are about what the runner skipped."""
    directory = tempfile.mkdtemp()
    synthesize.build(directory, plan=synthesize.Plan(platform=platform, faults=tuple(faults), **plan))
    run = snapshot.load(directory)
    return run, score(run, manifest_module.load(), platform=platform)


def scored(*faults, platform="linux", **plan):
    return run_and_score(*faults, platform=platform, **plan)[1]


class RecordedRun(unittest.TestCase):
    """The checked-in run is the baseline every scoring change is replayed against."""

    @classmethod
    def setUpClass(cls):
        cls.score = score(snapshot.load(RECORDED), manifest_module.load())

    def test_a_correct_collector_scores_perfectly(self):
        self.assertEqual(self.score.totals.recall, 1.0)
        self.assertEqual(self.score.totals.precision, 1.0)
        self.assertEqual(self.score.totals.dup, 0)

    def test_the_gate_passes(self):
        self.assertTrue(schema.gate(self.score).passed)

    def test_recall_is_reported_per_category(self):
        """Never pooled: the denominators differ, and an average hides which one moved."""
        self.assertGreater(len(self.score.by_category), 1)

    def test_every_verdict_is_keyed_by_manifest_id(self):
        ids = {entry.id for entry in manifest_module.load()}
        for verdict in self.score.verdicts:
            if verdict.outcome != "fp":
                self.assertIn(verdict.entry_id, ids)


class Faults(unittest.TestCase):
    def test_a_missing_asset_is_a_false_negative(self):
        result = scored("miss")
        self.assertGreaterEqual(result.totals.fn, 1)
        self.assertLess(result.totals.recall, 1.0)

    def test_an_invented_asset_is_a_false_positive(self):
        result = scored("invent")
        self.assertGreaterEqual(result.totals.fp, 1)
        self.assertLess(result.totals.precision, 1.0)

    def test_a_second_asset_for_one_install_is_a_duplicate(self):
        result = scored("duplicate")
        self.assertGreaterEqual(result.totals.dup, 1)
        self.assertFalse(schema.gate(result).passed)

    def test_a_leaked_canary_fails_the_run_outright(self):
        result = scored("leak")
        self.assertGreaterEqual(result.canaries.leaked, 1)
        gate = schema.gate(result)
        self.assertFalse(gate.passed)
        self.assertTrue(any("canary" in reason for reason in gate.reasons))

    def test_a_dirty_baseline_fails_before_the_score_matters(self):
        result = scored("dirty-baseline")
        self.assertFalse(result.baseline_clean)
        self.assertFalse(schema.gate(result).passed)

    def test_a_wrong_field_lowers_that_field_and_not_recall(self):
        """A tool found with the wrong facts is still found."""
        result = scored("wrong-field")
        self.assertEqual(result.totals.recall, 1.0)
        self.assertLess(result.fields["version"], 1.0)


class Denominators(unittest.TestCase):
    def test_an_unavailable_entry_is_not_a_miss(self):
        """The vendor's choice is not the collector's blind spot."""
        clean = scored()
        result = scored(unavailable=("T-CLI-01",))
        self.assertEqual(result.totals.fn, 0)
        self.assertEqual(clean.totals.tp - result.totals.tp,
                         result.manifest_counts["unavailable"])

    def test_a_variant_leaves_with_the_tool_it_duplicates(self):
        """A second channel of a tool nobody installed was not installed either."""
        run, _ = run_and_score(unavailable=("T-CLI-01",))
        dropped = {o.id for o in run.outcomes if o.status == "unavailable"}
        self.assertIn("T-CLI-01", dropped)
        self.assertGreater(len(dropped), 1, "its variants and assertions must leave with it")

    def test_a_failed_entry_leaves_the_denominator_but_is_reported(self):
        result = scored(failed=("T-CLI-02",))
        self.assertEqual(result.totals.fn, 0)
        self.assertEqual(result.manifest_counts["failed"], 1)


class Gate(unittest.TestCase):
    def test_recall_below_the_previous_accepted_run_fails(self):
        previous = schema.to_dict(score(snapshot.load(RECORDED), manifest_module.load()))
        regressed = scored("miss")
        gate = schema.gate(regressed, previous)
        self.assertFalse(gate.passed)
        self.assertTrue(any("recall fell" in reason for reason in gate.reasons))

    def test_a_run_is_not_compared_against_another_os(self):
        """Denominators differ per OS, so a cross-OS comparison is meaningless."""
        previous = schema.to_dict(scored(platform="mac"))
        previous["run"]["os"] = "mac"
        gate = schema.gate(scored("miss"), previous)
        self.assertFalse(any("recall fell" in reason for reason in gate.reasons))

    def test_score_json_round_trips(self):
        document = json.loads(schema.to_json(score(snapshot.load(RECORDED), manifest_module.load())))
        self.assertEqual(document["schema_version"], schema.SCHEMA_VERSION)
        self.assertIn("totals", document)
        self.assertIn("canaries", document)


if __name__ == "__main__":
    unittest.main()
