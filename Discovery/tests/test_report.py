"""The scorecard. Tested for the two things a report can get wrong: leaving out
the row somebody needs, and rendering something it was handed as markup."""

import json
import os
import unittest

from . import manifest as manifest_module
from .report import html
from .scoring import score_run

RECORDED = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "recorded", "synthetic-linux")


class Scorecard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.score = score_run(RECORDED, manifest_module.load())
        cls.page = html.render(cls.score)

    def test_every_miss_is_listed_by_id(self):
        """The aggregate number is for tracking; the individual rows are what
        somebody fixes."""
        for row in self.score["misses"]:
            self.assertIn(row["id"], self.page)

    def test_every_invention_carries_the_evidence_that_produced_it(self):
        """A miss can be localized to a probe from the output alone, and the
        report should surface that rather than making a reader open two JSON
        files side by side."""
        self.assertIn("filesystem", self.page)
        self.assertIn("path-contains:mcp", self.page)

    def test_the_gate_verdict_is_visible_without_reading_a_table(self):
        self.assertIn("gate failed", self.page)
        self.assertIn("duplicates", self.page)

    def test_the_page_is_self_contained(self):
        """A scorecard that needed a CDN would be unreadable on the isolated
        host that produced it."""
        for external in ("http://", "https://", "<script"):
            self.assertNotIn(external, self.page)

    def test_content_is_escaped(self):
        page = html.render({"run": {"id": "<img src=x onerror=alert(1)>"},
                            "totals": {"tp": 0, "fp": 0, "fn": 0, "dup": 0},
                            "gate": {"passed": True, "reasons": []}})
        self.assertNotIn("<img", page)
        self.assertIn("&lt;img", page)

    def test_it_renders_a_perfect_run_without_empty_tables(self):
        page = html.render({"run": {}, "totals": {"tp": 10, "fp": 0, "fn": 0, "dup": 0,
                                                  "recall": 1.0, "precision": 1.0},
                            "gate": {"passed": True, "reasons": []},
                            "misses": [], "inventions": [], "duplicates": []})
        self.assertIn("gate passed", page)
        self.assertEqual(page.count("class=\"empty\">none"), 4)

    def test_writing_leaves_a_file_next_to_the_run(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            path = html.write(self.score, directory)
            self.assertTrue(os.path.exists(path))
            with open(path, encoding="utf-8") as handle:
                self.assertIn("ADR Discovery", handle.read())

    def test_no_canary_value_reaches_the_page(self):
        """The report is a document that gets shared. A value redacted out of
        the snapshot and copied into the scorecard has still left the machine."""
        with open(os.path.join(RECORDED, "canaries.json"), encoding="utf-8") as handle:
            planted = json.load(handle)
        for name, value in planted.items():
            self.assertNotIn(value, self.page, name)


if __name__ == "__main__":
    unittest.main()
