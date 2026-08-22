"""The guest contract, exercised through the driver that touches no guest.

The dry driver is not a mock: the recipes above it verify what they wrote, so a
driver that recorded commands without simulating their effect would make every
recipe take its failure path. What it simulates is therefore part of the
contract, and worth asserting directly rather than only through the runner.
"""

import unittest

from .provision import DryRunDriver


class DryGuest(unittest.TestCase):
    def setUp(self):
        self.driver = DryRunDriver("linux", "/home/tester")

    def test_written_content_is_readable_back(self):
        self.driver.write("/home/tester/.claude.json", '{"mcpServers": {}}')
        self.assertTrue(self.driver.exists("/home/tester/.claude.json"))
        self.assertIn("mcpServers", self.driver.files["/home/tester/.claude.json"])

    def test_a_directory_exists_once_something_is_in_it(self):
        """The plugin entry creates a directory rather than a file, and the
        recipe verifies it afterwards."""
        self.driver.write("/home/tester/.claude/plugins/acme/plugin.json", "{}")
        self.assertTrue(self.driver.exists("/home/tester/.claude/plugins/acme"))
        self.assertFalse(self.driver.exists("/home/tester/.claude/plugins/other"))

    def test_a_link_exists_even_though_its_target_does_not(self):
        """N-09 is deliberately dangling. A driver that ignored `ln` would make
        the one entry that is supposed to be broken look like a failed install."""
        self.driver.sudo(["ln", "-sfn", "/opt/removed/claude", "/usr/local/bin/claude-old"])
        self.assertTrue(self.driver.exists("/usr/local/bin/claude-old"))

    def test_a_binary_is_locatable_after_install(self):
        """Recipes ask `command -v` and record what comes back; answering
        nothing would fail every install on a healthy guest."""
        self.assertEqual(self.driver.run(["command", "-v", "claude"]).text(),
                         "/usr/local/bin/claude")

    def test_privileged_writes_are_recorded_as_such(self):
        self.driver.write("/etc/adr/managed-mcp.json", "{}", privileged=True)
        self.assertIn("/etc/adr/managed-mcp.json", self.driver.privileged_writes)

    def test_restore_is_counted(self):
        self.driver.restore()
        self.driver.restore()
        self.assertEqual(self.driver.restored, 2)


class Contract(unittest.TestCase):
    def test_the_interface_is_four_verbs(self):
        """A new hypervisor should be a new file, not a change to the runner."""
        for verb in ("restore", "run", "push", "pull"):
            self.assertTrue(hasattr(DryRunDriver, verb), verb)

    def test_elevation_is_non_interactive(self):
        """A run that stops for a password has hung, not failed."""
        driver = DryRunDriver("linux", "/home/tester")
        driver.sudo(["mkdir", "-p", "/etc/adr"])
        self.assertIn(("sudo", "-n", "mkdir", "-p", "/etc/adr"), driver.commands)


if __name__ == "__main__":
    unittest.main()
