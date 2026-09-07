"""A leaked credential fails the run, so the leak check is asserted first."""

import unittest

from .scoring import canary


class Leaks(unittest.TestCase):
    def test_a_planted_value_in_the_output_is_a_leak(self):
        report = canary.check(
            {"hook_token": "adr-e2e-canary-hook-000000000000"},
            {"after.json": '{"proof": "adr-e2e-canary-hook-000000000000"}'},
        )
        self.assertFalse(report.clean)
        self.assertEqual(report.leaked, 1)
        self.assertEqual(report.leaks[0].name, "hook_token")
        self.assertEqual(report.leaks[0].where, "after.json")

    def test_a_redacted_output_is_clean(self):
        report = canary.check(
            {"hook_token": "adr-e2e-canary-hook-000000000000"},
            {"after.json": '{"proof": "[redacted]"}'},
        )
        self.assertTrue(report.clean)
        self.assertEqual(report.planted, 1)

    def test_a_short_canary_is_refused_rather_than_reported(self):
        """A value short enough to collide would report a leak that is not one."""
        with self.assertRaises(canary.CanaryError):
            canary.check({"tiny": "abc"}, {"after.json": "abc"})

    def test_declared_but_never_planted_is_reported(self):
        """A canary nobody planted is a hole in the check, not a pass."""
        report = canary.check(
            {"hook_token": "adr-e2e-canary-hook-000000000000"},
            {"after.json": "{}"},
            declared=["hook_token", "env_key"],
        )
        self.assertTrue(report.clean)
        self.assertEqual(report.unplanted, ("env_key",))

    def test_every_document_is_searched(self):
        report = canary.check(
            {"a": "adr-e2e-canary-aaaaaaaaaaaa"},
            {"before.json": "{}", "after.json": "adr-e2e-canary-aaaaaaaaaaaa"},
        )
        self.assertEqual([leak.where for leak in report.leaks], ["after.json"])


if __name__ == "__main__":
    unittest.main()
