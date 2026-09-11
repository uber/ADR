"""Provisioning is asserted against a dry guest, because the bugs were in the
translation from manifest row to shell command - not in the guests."""

import json
import unittest

from . import manifest as manifest_module
from .install.bodies import artifact, body_for
from .provision.driver import DryDriver
from .tools import bootstrap


class Bodies(unittest.TestCase):
    """`body` names a template. Writing the name leaves a file that says nothing."""

    @classmethod
    def setUpClass(cls):
        cls.manifest = manifest_module.load()

    def test_a_skill_is_a_skill_and_not_the_word_skill(self):
        text = artifact(self.manifest.by_id("S-01"))
        self.assertNotEqual(text.strip(), "skill")
        self.assertIn("name:", text)

    def test_a_hook_row_produces_the_settings_shape(self):
        document = json.loads(artifact(self.manifest.by_id("S-13")))
        self.assertIn("PreToolUse", document["hooks"])
        commands = [inner["command"]
                    for group in document["hooks"]["PreToolUse"]
                    for inner in group["hooks"]]
        self.assertTrue(any("audit.sh" in c for c in commands))

    def test_a_canary_reaches_the_body(self):
        text = body_for(self.manifest.by_id("S-16"), {"hook_token": "adr-e2e-canary-hook-XYZ"})
        self.assertIn("adr-e2e-canary-hook-XYZ", text)
        self.assertNotIn("{{canary:", text)

    def test_an_unresolved_canary_is_left_visible(self):
        """Blanking it would turn a hole in the check into a passing check."""
        text = body_for(self.manifest.by_id("S-16"), {})
        self.assertIn("{{canary:hook_token}}", text)

    def test_the_malformed_bundle_is_actually_malformed(self):
        with self.assertRaises(json.JSONDecodeError):
            json.loads(artifact(self.manifest.by_id("M-SP-06")))

    def test_every_template_marker_is_known(self):
        """A marker with no template silently becomes a comment."""
        from .install.bodies import TEMPLATES

        unknown = set()
        for entry in self.manifest:
            marker = str(entry.create.get("body") or "")
            if marker and marker not in TEMPLATES and marker not in ("hook", "malformed_bundle",
                                                                     "shell_export"):
                unknown.add(marker)
        self.assertEqual(unknown, set())


class Provisioning(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = manifest_module.load()

    def test_an_unattended_family_is_skipped_with_a_reason(self):
        """Silently succeeding would make the environment look ready when it is not."""
        report = bootstrap.provision(DryDriver(), "linux", manifest=self.manifest, log=lambda m: None)
        skipped = report.of(bootstrap.SKIPPED)
        self.assertTrue(skipped)
        self.assertTrue(all(step.detail for step in skipped))

    def test_a_path_outside_home_is_written_as_root(self):
        """A managed policy site lives under /etc whether or not the row says so."""
        driver = DryDriver()
        bootstrap.provision(driver, "linux", manifest=self.manifest,
                            only=("declare-mcp",), log=lambda m: None)
        etc = [c for c in driver.commands if "/etc/" in " ".join(c)]
        self.assertTrue(etc)
        self.assertTrue(all("sudo" in " ".join(c) for c in etc))

    def test_an_append_row_appends_rather_than_replaces(self):
        driver = DryDriver()
        bootstrap.provision(driver, "linux", manifest=self.manifest,
                            only=("artifact",), log=lambda m: None)
        profile = [" ".join(c) for c in driver.commands if ".bashrc" in " ".join(c)]
        self.assertTrue(profile)
        self.assertTrue(any(">>" in line for line in profile))
        self.assertFalse(any("cat > " in line and ".bashrc" in line for line in profile))

    def test_a_directory_row_makes_a_directory(self):
        driver = DryDriver()
        bootstrap.provision(driver, "linux", manifest=self.manifest,
                            only=("artifact",), log=lambda m: None)
        plugin = [" ".join(c) for c in driver.commands if "acme-tools" in " ".join(c)]
        self.assertTrue(any("mkdir -p" in line for line in plugin))

    def test_a_prerequisite_is_verified_by_binary_not_by_display_name(self):
        """`command -v "Node.js"` fails on a machine that has node."""
        driver = DryDriver()
        bootstrap.provision(driver, "linux", manifest=self.manifest,
                            only=("baseline-prereq",), log=lambda m: None)
        joined = " ".join(" ".join(c) for c in driver.commands)
        self.assertIn("node", joined)
        self.assertNotIn("Node.js", joined)

    def test_ready_is_false_while_anything_failed(self):
        report = bootstrap.Report("linux", [bootstrap.Step("X", "x", "f", bootstrap.FAILED)])
        self.assertFalse(report.ready)

    def test_skipped_alone_does_not_block_ready(self):
        report = bootstrap.Report("linux", [bootstrap.Step("X", "x", "f", bootstrap.SKIPPED, "why")])
        self.assertTrue(report.ready)


class Merging(unittest.TestCase):
    def test_a_nested_list_is_extended_rather_than_replaced(self):
        """Two hook rows land on one event; a shallow update keeps only the last."""
        current = {"hooks": {"PreToolUse": [{"hooks": [{"command": "a"}]}]}}
        incoming = {"hooks": {"PreToolUse": [{"hooks": [{"command": "b"}]}]}}
        merged = bootstrap._deep_merge(current, incoming)
        self.assertEqual(len(merged["hooks"]["PreToolUse"]), 2)

    def test_an_identical_entry_is_not_duplicated(self):
        one = {"hooks": {"PreToolUse": [{"hooks": [{"command": "a"}]}]}}
        merged = bootstrap._deep_merge(one, json.loads(json.dumps(one)))
        self.assertEqual(len(merged["hooks"]["PreToolUse"]), 1)

    def test_unrelated_keys_survive(self):
        merged = bootstrap._deep_merge({"model": "opus", "hooks": {}}, {"hooks": {"X": []}})
        self.assertEqual(merged["model"], "opus")


if __name__ == "__main__":
    unittest.main()
