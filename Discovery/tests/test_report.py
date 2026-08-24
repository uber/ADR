"""The scorecard exists to be read, so what it must contain is asserted."""

import os
import unittest

from . import manifest as manifest_module
from .report import html
from .scoring import schema, snapshot
from .scoring.score import score

RECORDED = os.path.join(os.path.dirname(os.path.abspath(__file__)), "recorded", "synthetic-linux")


class Scorecard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.score = score(snapshot.load(RECORDED), manifest_module.load())
        cls.page = html.render(cls.score, schema.gate(cls.score))

    def test_it_is_one_self_contained_page(self):
        """No external assets: a scorecard travels as a file."""
        self.assertTrue(self.page.startswith("<!doctype html>"))
        self.assertNotIn("http://", self.page)
        self.assertNotIn("<script", self.page)

    def test_it_names_the_run_the_image_and_the_collector(self):
        """A scoring shift must be attributable to the image or the collector."""
        for expected in (self.score.run_id, self.score.image, self.score.collector):
            self.assertIn(html.esc(expected), self.page)

    def test_it_reports_the_gate(self):
        self.assertIn("PASS", self.page)

    def test_categories_are_listed_separately(self):
        for category in self.score.by_category:
            self.assertIn(html.esc(category), self.page)


class Failures(unittest.TestCase):
    def test_every_miss_and_invention_is_listed_by_id(self):
        """The aggregate is for tracking; the rows are what somebody fixes."""
        import tempfile

        from .tools import synthesize

        directory = tempfile.mkdtemp()
        synthesize.build(directory, plan=synthesize.Plan(platform="linux",
                                                        faults=("miss", "invent")))
        result = score(snapshot.load(directory), manifest_module.load())
        page = html.render(result, schema.gate(result))

        self.assertTrue(result.misses and result.inventions)
        for verdict in result.misses:
            self.assertIn(html.esc(verdict.entry_id), page)
        for verdict in result.inventions:
            self.assertIn(html.esc(verdict.entry_id), page)

    def test_a_failing_gate_says_why(self):
        import tempfile

        from .tools import synthesize

        directory = tempfile.mkdtemp()
        synthesize.build(directory, plan=synthesize.Plan(platform="linux", faults=("leak",)))
        result = score(snapshot.load(directory), manifest_module.load())
        gate = schema.gate(result)
        page = html.render(result, gate)

        self.assertIn("FAIL", page)
        for reason in gate.reasons:
            self.assertIn(html.esc(reason), page)

    def test_content_is_escaped(self):
        """Asset names come from the machine under test, not from us."""
        self.assertNotIn("<script>", html.esc("<script>alert(1)</script>"))


if __name__ == "__main__":
    unittest.main()
