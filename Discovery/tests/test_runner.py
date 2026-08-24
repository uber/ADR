"""Execution order is the runner's whole job, so it is asserted directly."""

import unittest

from . import manifest as manifest_module
from .install import runner
from .install.recipes import BUILT, PENDING, REGISTRY
from .provision.driver import DryDriver


class Order(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = manifest_module.load()

    def test_every_family_has_an_execution_slot(self):
        families = {entry.family for entry in self.manifest}
        self.assertEqual(families - set(runner.ORDER), set())

    def test_a_family_with_no_slot_is_refused(self):
        """Silently appending it would run it in an order nobody chose."""
        entry = self.manifest.by_id("T-CLI-01")
        entry = type(entry)(**{**entry.__dict__, "family": "invented"})
        with self.assertRaises(runner.UnknownFamily):
            runner.ordered([entry])

    def test_extensions_run_after_the_app_that_hosts_them(self):
        self.assertLess(runner.ORDER.index("app-installer"), runner.ORDER.index("vscode-ext"))

    def test_declarations_run_after_their_host_application(self):
        """A config path created before the app exists may be read differently."""
        self.assertLess(runner.ORDER.index("app-installer"), runner.ORDER.index("declare-mcp"))

    def test_variants_run_after_the_first_install(self):
        self.assertLess(runner.ORDER.index("npm-global"), runner.ORDER.index("channel-variant"))

    def test_runtime_state_runs_last(self):
        """The processes must still be alive when the second scan happens."""
        self.assertEqual(runner.ORDER[-1], "runtime-state")

    def test_ordering_is_stable_within_a_family(self):
        entries = runner.ordered(self.manifest.for_platform("linux"))
        npm = [e.id for e in entries if e.family == "npm-global"]
        self.assertEqual(npm, sorted(npm))


class Execution(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = manifest_module.load()

    def test_a_dry_run_touches_no_guest_and_records_everything(self):
        driver = DryDriver()
        actual = runner.run(driver, self.manifest, platform="linux", image="dry", collector="dry")
        self.assertEqual(actual["applicable"], 105)
        self.assertEqual(actual["applicable"],
                         actual["installed"] + actual["unavailable"] + actual["failed"])
        self.assertTrue(driver.commands)

    def test_a_pending_family_is_unavailable_with_a_reason(self):
        """A family that silently no-opped would shrink the denominator."""
        driver = DryDriver()
        actual = runner.run(driver, self.manifest, platform="linux", image="dry", collector="dry")
        rows = {row["id"]: row for row in actual["entries"]}
        pending = [row for row in rows.values()
                   if row["status"] == "unavailable" and "pending" in row.get("reason", "")]
        self.assertTrue(pending)
        self.assertTrue(all(row.get("reason") for row in pending))

    def test_a_broken_recipe_fails_one_entry_rather_than_the_run(self):
        def explode(driver, entry, platform):
            raise RuntimeError("vendor changed the flags again")

        actual = runner.run(DryDriver(), self.manifest, platform="linux",
                            recipes={**REGISTRY, "npm-global": explode},
                            image="dry", collector="dry")
        failed = [row for row in actual["entries"] if row["status"] == "failed"]
        self.assertTrue(failed)
        self.assertIn("vendor changed the flags", failed[0]["reason"])
        self.assertEqual(actual["applicable"], 105)

    def test_an_unpinned_install_is_refused(self):
        """An unpinned version makes the version field unscoreable."""
        entry = self.manifest.by_id("T-CLI-01")
        unpinned = type(entry)(**{**entry.__dict__,
                                  "install": {**entry.install, "version": None}})
        outcome = REGISTRY["npm-global"](DryDriver(), unpinned, "linux")
        self.assertEqual(outcome.status, runner.FAILED)
        self.assertIn("unpinned", outcome.reason)

    def test_a_failing_command_is_a_failed_entry(self):
        driver = DryDriver(failures={"npm": 1})
        outcome = REGISTRY["npm-global"](driver, self.manifest.by_id("T-CLI-01"), "linux")
        self.assertEqual(outcome.status, runner.FAILED)


class Registry(unittest.TestCase):
    def test_built_and_pending_together_cover_the_fourteen_families(self):
        self.assertEqual(set(BUILT) | set(PENDING), set(runner.ORDER))

    def test_nothing_is_both_built_and_pending(self):
        self.assertEqual(set(BUILT) & set(PENDING), set())


if __name__ == "__main__":
    unittest.main()
