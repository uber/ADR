"""The runner is as much of the harness as the scorer, and much harder to test:
it exists to mutate a machine. The dry driver makes the mutation inspectable,
so the ordering rules, the canary substitution and the recorded outcomes can be
asserted with no hypervisor anywhere near them."""

import json
import unittest

from . import manifest as manifest_module
from .install import Context, Runner
from .install.recipes import PENDING, REGISTRY, for_family
from .install.runner import ORDER
from .provision import DryRunDriver

HOME = "/home/tester"


class DryLinuxRun(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = manifest_module.load()
        cls.driver = DryRunDriver("linux", HOME)
        cls.context = Context(cls.driver, cls.manifest, "linux", HOME)
        cls.actual = Runner(cls.context).run()
        cls.rows = {row["id"]: row for row in cls.actual["entries"]}

    def test_every_applicable_entry_gets_an_outcome(self):
        """An entry with no row is an entry nobody can score, in either
        direction."""
        self.assertEqual(len(self.rows), 105)
        self.assertEqual(self.actual["applicable"], 105)

    def test_nothing_fails_on_a_healthy_guest(self):
        failures = [row for row in self.actual["entries"] if row["status"] == "failed"]
        self.assertEqual(failures, [], failures)

    def test_the_three_implemented_families_install(self):
        for entry_id in ("T-CLI-01", "M-SITE-01", "M-PIN-06", "S-01", "S-16", "N-10"):
            self.assertEqual(self.rows[entry_id]["status"], "installed", entry_id)

    def test_a_family_with_no_recipe_is_unimplemented_not_failed(self):
        """A recipe nobody has written must never be reported as a vendor that
        stopped shipping or a collector that missed something."""
        row = self.rows["T-APP-02"]
        self.assertEqual(row["status"], "unimplemented")
        self.assertIn("app-installer", row["reason"])

    def test_an_entry_whose_dependency_never_installed_is_not_attempted(self):
        row = self.rows["M-SITE-03"]
        self.assertEqual(row["status"], "unimplemented")
        self.assertIn("T-APP-02", row["reason"])

    def test_counts_add_up(self):
        total = (self.actual["installed"] + self.actual["unavailable"]
                 + self.actual["failed"] + self.actual["unimplemented"])
        self.assertEqual(total, self.actual["applicable"])

    def test_the_run_records_where_home_was(self):
        """Without it the scorer cannot compare a manifest path against a
        recorded one, and every artifact entry scores as a miss."""
        self.assertEqual(self.actual["home"], HOME)


class Ordering(unittest.TestCase):
    def test_config_sites_are_written_after_their_host_applications(self):
        """Writing M-SITE-08 before JetBrains exists creates a path the
        collector may treat differently from one the application created."""
        families = [family for group in ORDER for family in group]
        self.assertLess(families.index("app-installer"), families.index("declare-mcp"))
        self.assertLess(families.index("app-installer"), families.index("vscode-ext"))

    def test_second_installs_come_after_first_ones(self):
        families = [family for group in ORDER for family in group]
        self.assertLess(families.index("npm-global"), families.index("channel-variant"))

    def test_running_processes_are_left_until_last(self):
        """They must still be alive at the second scan."""
        self.assertEqual(ORDER[-1], ("runtime-state",))

    def test_every_family_is_ordered_exactly_once(self):
        families = [family for group in ORDER for family in group]
        self.assertEqual(sorted(families), sorted(manifest_module.FAMILIES))
        self.assertEqual(len(families), len(set(families)))

    def test_every_family_resolves_to_a_recipe_or_a_stated_gap(self):
        for family in manifest_module.FAMILIES:
            self.assertTrue(family in REGISTRY or family in PENDING, family)
            self.assertIsNotNone(for_family(family))


class Canaries(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = manifest_module.load()
        cls.driver = DryRunDriver("linux", HOME)
        cls.context = Context(cls.driver, cls.manifest, "linux", HOME)
        Runner(cls.context).run()

    def test_a_value_is_generated_for_every_declared_canary(self):
        self.assertEqual(sorted(self.context.canaries), sorted(self.manifest.canary_names()))

    def test_values_are_planted_not_placeholders(self):
        """A recipe that built its own would plant a value the redaction check
        never searches for."""
        config = json.loads(self.driver.files[HOME + "/.claude.json"])
        args = config["mcpServers"]["adr-probe-argv-token"]["args"]
        self.assertIn(self.context.canaries["mcp_token"], args)
        self.assertNotIn("{{canary:mcp_token}}", args)

    def test_two_vendor_shapes_are_planted_in_env(self):
        """Redaction is partly shape-driven, so one shape passing proves only
        that one shape passes."""
        config = json.loads(self.driver.files[HOME + "/.claude.json"])
        env = config["mcpServers"]["adr-probe-env-key"]["env"]
        self.assertTrue(env["ANTHROPIC_API_KEY"].startswith("sk-ant-api03-"))
        self.assertTrue(env["OPENAI_API_KEY"].startswith("sk-proj-"))

    def test_each_canary_carries_a_marker_no_issuer_emits(self):
        for name, value in self.context.canaries.items():
            self.assertIn("ADRE2ECANARY" if value.startswith("sk-") else "adr-e2e-canary",
                          value, name)


class WritingConfigs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = manifest_module.load()
        cls.driver = DryRunDriver("linux", HOME)
        Runner(Context(cls.driver, cls.manifest, "linux", HOME)).run()

    def test_nine_launch_forms_share_one_file_without_overwriting_it(self):
        """A recipe that wrote the file whole would leave one server declared
        and eight missing, and the run would report eight misses that never
        happened."""
        config = json.loads(self.driver.files[HOME + "/.claude.json"])
        for name in ("filesystem", "git", "github", "sqlite", "fetch", "memory",
                     "playwright", "local-script", "remote-sse"):
            self.assertIn(name, config["mcpServers"], name)

    def test_each_site_gets_the_format_that_site_uses(self):
        self.assertIn("[mcp_servers", self.driver.files[HOME + "/.codex/config.toml"])
        self.assertIn("extensions:", self.driver.files[HOME + "/.config/goose/config.yaml"])

    def test_two_hooks_in_one_settings_file_both_survive(self):
        settings = json.loads(self.driver.files[HOME + "/.claude/settings.json"])
        commands = [hook["command"] for group in settings["hooks"]["PreToolUse"]
                    for hook in group["hooks"]]
        self.assertEqual(len(commands), 2)

    def test_the_declared_command_exists_on_disk(self):
        """A declaration whose command is absent is a different test from the
        one the manifest describes."""
        self.assertIn(HOME + "/dev/tools/adr-probe-server.js", self.driver.files)

    def test_the_dangling_symlink_is_left_dangling(self):
        """And created as root: /usr/local/bin is not the user's to write."""
        commands = [" ".join(argv) for argv in self.driver.commands]
        self.assertIn("sudo -n ln -sfn /opt/removed/claude /usr/local/bin/claude-old", commands)

    def test_managed_policy_is_written_as_root(self):
        """A policy file a user could write would not be policy. A transport
        that does not elevate writes it as the user - or not at all - and the
        run then reports the site as missing."""
        self.assertIn("/etc/claude-code/managed-settings.json", self.driver.privileged_writes)
        self.assertIn("/etc/adr/managed-mcp.json", self.driver.privileged_writes)

    def test_an_artifact_that_did_not_land_is_a_failure_not_an_install(self):
        """The worst failure this harness can have is manufacturing a defect in
        the thing it measures: a write that silently did not land, recorded as
        installed, reads as the collector missing a file that was never there."""
        from .install.recipes.artifact import ArtifactRecipe
        from .provision import DryRunDriver

        class Sink(DryRunDriver):
            def write(self, remote, content, privileged=False):
                pass          # a transport that quietly drops the write

        manifest = manifest_module.load()
        driver = Sink("linux", HOME)
        context = Context(driver, manifest, "linux", HOME)
        outcome = ArtifactRecipe().execute(context, manifest.by_id("S-01"))
        self.assertEqual(outcome.status, "failed")
        self.assertIn("not there afterwards", outcome.reason)


class OtherPlatforms(unittest.TestCase):
    def test_windows_and_mac_run_with_their_own_paths(self):
        manifest = manifest_module.load()
        for platform, home, marker in (("mac", "/Users/tester", "/Users/tester/.zshrc"),
                                       ("win", "C:/Users/tester",
                                        "C:/Users/tester/.codex/config.toml")):
            driver = DryRunDriver(platform, home)
            actual = Runner(Context(driver, manifest, platform, home)).run()
            self.assertEqual(actual["applicable"], len(manifest.for_platform(platform)))
            self.assertIn(marker, driver.files)


if __name__ == "__main__":
    unittest.main()
