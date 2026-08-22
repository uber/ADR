"""The scorer, replayed over a recorded run.

The recorded directory is the load-bearing fixture: a run captured once and
checked in, so a change to the scorer can be replayed against it and show
exactly which verdicts moved. These assertions are deliberately exact - a
scorer whose totals drift by one has a bug, and a test that only checked
"recall is high" would not notice.
"""

import copy
import json
import os
import unittest

from . import manifest as manifest_module
from .scoring import canary, score, score_run
from .scoring.snapshot import Snapshot

RECORDED = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "recorded", "synthetic-linux")


def _load(name):
    with open(os.path.join(RECORDED, name + ".json"), encoding="utf-8") as handle:
        return json.load(handle)


class RecordedRun(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = manifest_module.load()
        cls.score = score_run(RECORDED, cls.manifest)

    def test_the_recorded_run_is_labelled_synthetic(self):
        """A generated run proves the scorer computes what we think it computes.
        Only a captured one says anything about the collector, so the difference
        must never be inferable only from a directory name."""
        self.assertTrue(_load("manifest.actual")["synthetic"])

    def test_totals(self):
        totals = self.score["totals"]
        self.assertEqual((totals["tp"], totals["fp"], totals["fn"], totals["dup"]),
                         (73, 2, 2, 5))
        self.assertAlmostEqual(totals["recall"], 73 / 75, places=3)
        self.assertAlmostEqual(totals["precision"], 73 / 75, places=3)

    def test_every_injected_miss_is_reported_by_id(self):
        """A regression must read as `M-SITE-08 went from TP to FN`, not as
        `MCP recall dropped`."""
        self.assertEqual([row["id"] for row in self.score["misses"]], ["M-SITE-08", "T-RT-04"])

    def test_the_duplicate_is_reported_against_every_entry_it_touches(self):
        """One binary reachable by two names duplicates the base entry, both
        variants that key on it, and the two states that attach to it."""
        self.assertEqual([row["id"] for row in self.score["duplicates"]],
                         ["AG-01", "AG-08", "T-CHAN-01", "T-CHAN-04", "T-CLI-01"])
        self.assertTrue(all(row["count"] == 2 for row in self.score["duplicates"]))

    def test_an_invention_is_attributed_when_a_control_explains_it(self):
        inventions = {row["name"]: row for row in self.score["inventions"]}
        self.assertEqual(inventions["mcp-backup.sh"]["attributed_to"], "N-07")
        self.assertIn("mcp", inventions["mcp-backup.sh"]["why_wrong"])

    def test_an_invention_nothing_explains_is_still_reported(self):
        ghost = next(row for row in self.score["inventions"] if row["name"] == "ghost-agent")
        self.assertIsNone(ghost["attributed_to"])
        self.assertTrue(ghost["evidence"])

    def test_duplicates_are_not_also_counted_as_true_positives(self):
        """A duplicate is not a partial success: folding it into the good column
        is what let it recur."""
        by_category = self.score["by_category"]
        self.assertEqual(by_category["cli_agent"]["dup"], 1)      # T-CLI-01
        self.assertEqual(by_category["channel_variant"]["dup"], 2)  # T-CHAN-01, T-CHAN-04
        self.assertEqual(by_category["agent"]["dup"], 2)          # AG-01, AG-08
        # None of the five appear in the good column of their own category.
        self.assertEqual(sum(values["tp"] for values in by_category.values()),
                         self.score["totals"]["tp"])

    def test_the_denominator_reports_what_left_it(self):
        manifest = self.score["manifest"]
        self.assertEqual(manifest["applicable"], 105)
        self.assertEqual(manifest["failed"], 1)
        self.assertGreater(manifest["unimplemented"], 0)
        self.assertEqual(manifest["installed"] + manifest["failed"] + manifest["unimplemented"]
                         + manifest["unavailable"], 105)

    def test_field_accuracy_is_per_field(self):
        fields = self.score["fields"]
        self.assertIn("version", fields)
        self.assertIn("config_scope", fields)
        for name, tally in fields.items():
            self.assertEqual(tally["checked"], tally["correct"] + len(tally["wrong"]), name)

    def test_the_baseline_is_clean(self):
        self.assertTrue(self.score["baseline"]["clean"])
        self.assertEqual(self.score["baseline"]["asset_count"], 0)

    def test_a_deliberate_error_is_explained(self):
        """N-09's dangling symlink is expected to produce one error. Anything
        else is the collector tripping over the real world."""
        self.assertEqual(self.score["errors"]["count"], 1)
        self.assertEqual(self.score["errors"]["unexplained"], 0)

    def test_the_open_world_entry_reaches_the_review_queue(self):
        self.assertTrue(self.score["review_queue"]["passed"])
        self.assertEqual(self.score["review_queue"]["expected"], 1)

    def test_the_gate_fails_on_the_duplicates(self):
        self.assertFalse(self.score["gate"]["passed"])
        self.assertEqual(self.score["gate"]["reasons"], ["duplicates"])


class Gate(unittest.TestCase):
    """Everything the gate refuses, one refusal at a time."""

    @classmethod
    def setUpClass(cls):
        cls.manifest = manifest_module.load()
        cls.actual = _load("manifest.actual")
        cls.planted = _load("canaries")

    def _score(self, before=None, after=None, planted=None, previous=None):
        return score(Snapshot(before or _load("before")), Snapshot(after or _load("after")),
                     self.actual, self.manifest, planted=planted or self.planted,
                     previous=previous)

    def test_a_leaked_canary_fails_the_run(self):
        """Regardless of every other score: a collector that finds every tool
        and leaks one token has not had a good run."""
        after = copy.deepcopy(_load("after"))
        after["assets"][0]["risk"]["args"] = [self.planted["hook_token"]]
        result = self._score(after=after)
        self.assertIn("canary_leaked", result["gate"]["reasons"])
        self.assertEqual(result["canaries"]["leaked"], 1)
        self.assertNotIn(self.planted["hook_token"], json.dumps(result["canaries"]))

    def test_an_unplanted_canary_is_not_reported_clean(self):
        """A check that never ran is not a check that passed."""
        result = self._score(planted=dict(self.planted, hook_token=""))
        self.assertFalse(result["canaries"]["clean"])

    def test_a_dirty_baseline_fails_the_run(self):
        """Anything on a clean machine is a false positive with no manifest to
        blame, and it invalidates every number computed after it."""
        before = copy.deepcopy(_load("before"))
        before["assets"] = [copy.deepcopy(_load("after")["assets"][0])]
        result = self._score(before=before)
        self.assertIn("baseline_dirty", result["gate"]["reasons"])

    def test_an_unexplained_error_fails_the_run(self):
        after = copy.deepcopy(_load("after"))
        after["errors"].append({"probe": "app", "path": "/opt/mystery", "message": "denied"})
        result = self._score(after=after)
        self.assertIn("unexplained_errors", result["gate"]["reasons"])

    def test_recall_is_compared_against_the_last_accepted_run(self):
        """A real endpoint is not perfectly reproducible, so the gate compares
        against history rather than an absolute threshold."""
        previous = {"run": {"id": "yesterday"}, "totals": {"recall": 1.0}}
        result = self._score(previous=previous)
        self.assertIn("recall_regressed", result["gate"]["reasons"])
        self.assertEqual(result["gate"]["compared_to"], "yesterday")

    def test_a_repeated_asset_id_is_refused_rather_than_scored(self):
        """Any score computed from a halved delta would be wrong in a direction
        that flatters the collector."""
        after = copy.deepcopy(_load("after"))
        after["assets"].append(copy.deepcopy(after["assets"][0]))
        with self.assertRaises(ValueError):
            self._score(after=after)


class CanarySearch(unittest.TestCase):
    def test_the_search_covers_the_whole_document_not_the_modelled_fields(self):
        snapshot = Snapshot({"hostname": "h", "assets": [],
                             "stats": {"note": "leaked-value-here"}})
        result = canary.check_canaries(snapshot, {"c": "leaked-value-here"})
        self.assertEqual(result["leaked"], 1)

    def test_the_context_line_masks_the_value_it_reports(self):
        """Printing the value into a report that then gets shared would repeat
        exactly the mistake being reported."""
        snapshot = Snapshot({"hostname": "h", "assets": [], "stats": {"n": "sk-xyz"}})
        result = canary.check_canaries(snapshot, {"c": "sk-xyz"})
        self.assertIn("<CANARY>", result["hits"][0]["detail"])
        self.assertNotIn("sk-xyz", result["hits"][0]["detail"])

    def test_extra_documents_are_searched_too(self):
        """A value redacted out of the snapshot and copied into the scorecard
        has still left the machine."""
        snapshot = Snapshot({"hostname": "h", "assets": []})
        result = canary.check_canaries(snapshot, {"c": "tok"}, also=[{"report": "tok"}])
        self.assertEqual(result["leaked"], 1)


if __name__ == "__main__":
    unittest.main()
