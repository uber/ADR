"""A run is read from files, so the file boundary is asserted like a contract."""

import json
import os
import tempfile
import unittest

from .scoring import snapshot
from .tools import synthesize


class RunLoading(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.mkdtemp()
        synthesize.build(cls.directory, plan=synthesize.Plan(platform="linux"))

    def test_a_run_round_trips_from_disk(self):
        run = snapshot.load(self.directory)
        self.assertEqual(run.os, "linux")
        self.assertEqual(len(run.outcomes), 105)
        self.assertEqual(len(run.canaries), 6)

    def test_a_missing_file_is_an_error_rather_than_an_empty_run(self):
        """Scoring nothing and scoring a run that found nothing are different claims."""
        empty = tempfile.mkdtemp()
        with self.assertRaises(snapshot.RunError):
            snapshot.load(empty)

    def test_malformed_json_names_the_file(self):
        broken = tempfile.mkdtemp()
        for name in (snapshot.BEFORE, snapshot.AFTER, snapshot.ACTUAL):
            with open(os.path.join(broken, name), "w", encoding="utf-8") as handle:
                handle.write("{not json")
        with self.assertRaises(snapshot.RunError) as raised:
            snapshot.load(broken)
        self.assertIn(snapshot.BEFORE, str(raised.exception))

    def test_an_unknown_status_is_refused(self):
        """Three statuses, three meanings. A fourth would be scored as nothing."""
        directory = tempfile.mkdtemp()
        synthesize.build(directory, plan=synthesize.Plan(platform="linux"))
        path = os.path.join(directory, snapshot.ACTUAL)
        with open(path, encoding="utf-8") as handle:
            document = json.load(handle)
        document["entries"][0]["status"] = "probably"
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(document, handle)
        with self.assertRaises(snapshot.RunError):
            snapshot.load(directory)


class Delta(unittest.TestCase):
    def test_only_what_installation_caused_is_scored(self):
        """Baseline noise present in both scans is not the manifest's invention."""
        directory = tempfile.mkdtemp()
        synthesize.build(directory, plan=synthesize.Plan(platform="linux", faults=("dirty-baseline",)))
        run = snapshot.load(directory)

        self.assertFalse(snapshot.baseline_is_clean(run.before))
        carried = {a.asset_id for a in run.before.assets}
        self.assertTrue(carried)
        self.assertFalse(carried & {a.asset_id for a in snapshot.added(run)})

    def test_a_clean_baseline_has_no_assets(self):
        run = snapshot.load(_fixture())
        self.assertTrue(snapshot.baseline_is_clean(run.before))


class Outcomes(unittest.TestCase):
    def test_only_installed_is_scoreable(self):
        """A vendor that does not ship here is not a collector blind spot."""
        self.assertTrue(snapshot.Outcome("X", "installed").is_scoreable)
        self.assertFalse(snapshot.Outcome("X", "unavailable").is_scoreable)
        self.assertFalse(snapshot.Outcome("X", "failed").is_scoreable)


def _fixture():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "recorded", "synthetic-linux")


if __name__ == "__main__":
    unittest.main()
