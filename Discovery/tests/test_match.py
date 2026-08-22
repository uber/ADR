"""Matching: the join between what was installed and what was reported.

Every rule here has a failure mode in both directions - a missed join reads as
a miss the collector never made, and a loose join hides a real one - so each
gets a test that would fail if the rule were relaxed.
"""

import unittest

from . import manifest as manifest_module
from .scoring import match
from .scoring.snapshot import Asset


def _asset(**payload):
    base = {"asset_id": payload.get("name", "x"), "kind": "cli_agent", "name": "tool",
            "evidence": [], "risk": {"factors": []}, "network": {}}
    base.update(payload)
    return Asset(base)


def _actual(platform="linux", home="/home/tester", entries=None):
    return {"os": platform, "home": home, "entries": entries or []}


class Normalization(unittest.TestCase):
    def test_a_launcher_is_its_name_not_its_location(self):
        self.assertEqual(match.norm_command("C:\\Tools\\NPX.EXE"), "npx")
        self.assertEqual(match.norm_command("/usr/local/bin/npx"), "npx")

    def test_windows_paths_compare_case_insensitively(self):
        self.assertEqual(match.norm_path("C:\\Program Files\\Code\\Code.exe", "win"),
                         match.norm_path("c:/program files/code/code.exe", "win"))

    def test_linux_paths_do_not(self):
        self.assertNotEqual(match.norm_path("/usr/bin/Claude", "linux"),
                            match.norm_path("/usr/bin/claude", "linux"))

    def test_home_is_expanded_from_the_run(self):
        self.assertEqual(match.expand("~/bin/x", "/home/tester"), "/home/tester/bin/x")
        self.assertEqual(match.expand("%USERPROFILE%/bin/x", "C:/Users/t", "win"),
                         "c:/users/t/bin/x")

    def test_a_redacted_argument_is_a_wildcard(self):
        """The manifest holds the plaintext a config was written with and the
        snapshot holds the redaction of it. Requiring equality would score every
        credential-carrying entry as a miss - punishing the collector for doing
        the right thing."""
        declared = match.launch_key("node", ["server.js", "--token", "{{canary:t}}"])
        reported = match.launch_key("node", ["server.js", "--token", "[REDACTED]"])
        self.assertEqual(declared, reported)


class Joining(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = manifest_module.load()

    def _match(self, entry_id, assets, record=None, platform="linux"):
        entry = self.manifest.by_id(entry_id)
        record = record or {"id": entry_id, "status": "installed"}
        actual = _actual(platform=platform, entries=[record])
        outcomes, unclaimed = match.match_all(self.manifest, actual, assets)
        found = next(item for item in outcomes if item.entry.id == entry_id)
        return found, unclaimed

    def test_an_installed_tool_joins_on_catalog_id(self):
        found, _ = self._match("T-CLI-01", [_asset(catalog_id="claude-code", name="Claude Code")])
        self.assertEqual(found.outcome, "matched")

    def test_a_variant_joins_through_its_base(self):
        """T-CHAN-04 has no catalog id of its own. If it matched nothing it
        would score as a miss and hide the duplicate it exists to provoke."""
        assets = [_asset(catalog_id="claude-code", name="Claude Code")]
        records = [{"id": "T-CLI-01", "status": "installed"},
                   {"id": "T-CHAN-04", "status": "installed"}]
        outcomes, _ = match.match_all(self.manifest, _actual(entries=records), assets)
        variant = next(item for item in outcomes if item.entry.id == "T-CHAN-04")
        self.assertEqual(len(variant.assets), 1)

    def test_a_variant_of_an_uninstalled_base_is_excluded(self):
        """A second install of a tool that was never installed once proves
        nothing, and scoring it as a miss would blame the collector."""
        records = [{"id": "T-APP-02", "status": "unimplemented"},
                   {"id": "T-CHAN-07", "status": "installed"}]
        outcomes, _ = match.match_all(self.manifest, _actual(entries=records), [])
        variant = next(item for item in outcomes if item.entry.id == "T-CHAN-07")
        self.assertEqual(variant.outcome, "excluded")
        self.assertIn("T-APP-02", variant.detail)

    def test_identical_declarations_are_separated_by_their_site(self):
        """Fourteen sites declare one server. Keying on the launch line alone
        would make all fourteen match all fourteen and report a duplicate on
        every row."""
        shared = {"kind": "mcp_server", "risk": {"factors": [], "command": "node",
                                                 "args": ["~/dev/tools/adr-probe-server.js"]}}
        at_cc = _asset(asset_id="1", name="adr-probe-cc",
                       install_path="/home/tester/.claude.json", **shared)
        at_cursor = _asset(asset_id="2", name="adr-probe-cursor",
                           install_path="/home/tester/.cursor/mcp.json", **shared)
        records = [{"id": "M-SITE-01", "status": "installed", "path": "/home/tester/.claude.json"},
                   {"id": "M-SITE-03", "status": "installed",
                    "path": "/home/tester/.cursor/mcp.json"}]
        outcomes, _ = match.match_all(self.manifest, _actual(entries=records), [at_cc, at_cursor])
        by_id = {item.entry.id: item for item in outcomes}
        self.assertEqual([a.name for a in by_id["M-SITE-01"].assets], ["adr-probe-cc"])
        self.assertEqual([a.name for a in by_id["M-SITE-03"].assets], ["adr-probe-cursor"])

    def test_a_site_that_produced_nothing_is_a_miss_not_a_match(self):
        shared = {"kind": "mcp_server", "risk": {"factors": [], "command": "node",
                                                 "args": ["~/dev/tools/adr-probe-server.js"]}}
        records = [{"id": "M-SITE-01", "status": "installed", "path": "/home/tester/.claude.json"},
                   {"id": "M-SITE-03", "status": "installed",
                    "path": "/home/tester/.cursor/mcp.json"}]
        assets = [_asset(asset_id="1", name="adr-probe-cc",
                         install_path="/home/tester/.claude.json", **shared),
                  _asset(asset_id="2", name="other", install_path="/home/tester/.zed/settings.json",
                         **shared)]
        outcomes, _ = match.match_all(self.manifest, _actual(entries=records), assets)
        cursor = next(item for item in outcomes if item.entry.id == "M-SITE-03")
        self.assertEqual(cursor.assets, [])

    def test_an_artifact_joins_on_the_path_that_was_written(self):
        asset = _asset(kind="skill", name="SKILL.md",
                       install_path="/home/tester/.claude/skills/pdf-filler/SKILL.md")
        found, _ = self._match("S-01", [asset], record={
            "id": "S-01", "status": "installed",
            "path": "/home/tester/.claude/skills/pdf-filler/SKILL.md"})
        self.assertEqual(found.outcome, "matched")

    def test_a_hook_joins_through_evidence_rather_than_install_path(self):
        """A hook lives inside a settings file, not in a file of its own."""
        asset = _asset(kind="hook", name="PreToolUse:*", install_path=None,
                       evidence=[{"probe": "agent_artifact", "channel": "config",
                                  "path": "/home/tester/.claude/settings.json",
                                  "matched_on": "hook:user"}])
        found, _ = self._match("S-13", [asset], record={
            "id": "S-13", "status": "installed", "path": "/home/tester/.claude/settings.json"})
        self.assertEqual(found.outcome, "matched")

    def test_two_schedulers_running_one_command_are_not_duplicates(self):
        """cron and a systemd unit run the identical command on purpose. Keying
        on the command alone reports two duplicates where there are none."""
        cron = _asset(asset_id="c", kind="scheduled_agent", name="cron:claude",
                      risk={"factors": [], "command": "claude"},
                      evidence=[{"probe": "scheduler", "channel": "config", "path": "",
                                 "matched_on": "scheduler:cron"}])
        unit = _asset(asset_id="s", kind="scheduled_agent", name="adr-agent.service",
                      install_path="/home/tester/.config/systemd/user/adr-agent.service",
                      risk={"factors": [], "command": "claude"},
                      evidence=[{"probe": "scheduler", "channel": "config",
                                 "path": "/home/tester/.config/systemd/user/adr-agent.service",
                                 "matched_on": "scheduler:systemd"}])
        records = [{"id": "AG-05", "status": "installed"}, {"id": "AG-06", "status": "installed"},
                   {"id": "T-CLI-01", "status": "installed"}]
        outcomes, _ = match.match_all(self.manifest, _actual(entries=records), [cron, unit])
        by_id = {item.entry.id: item for item in outcomes}
        self.assertEqual([a.asset_id for a in by_id["AG-05"].assets], ["c"])
        self.assertEqual([a.asset_id for a in by_id["AG-06"].assets], ["s"])

    def test_a_negative_control_does_not_claim_an_asset_by_name_alone(self):
        """An MCP server legitimately called `git` is not the `git` binary N-04
        installed. Attributing it would turn a correct report into a fabricated
        false positive."""
        server = _asset(kind="mcp_server", name="git", install_path="/home/tester/.claude.json")
        outcomes, unclaimed = match.match_all(
            self.manifest, _actual(entries=[{"id": "N-04", "status": "installed"}]), [server])
        control = next(item for item in outcomes if item.entry.id == "N-04")
        self.assertEqual(control.assets, [])
        self.assertEqual(len(unclaimed), 1)

    def test_a_negative_control_claims_an_asset_at_its_own_path(self):
        asset = _asset(kind="mcp_server", name="mcp-backup.sh",
                       install_path="/home/tester/bin/mcp-backup.sh")
        found, _ = self._match("N-07", [asset])
        self.assertEqual(len(found.assets), 1)

    def test_an_entry_that_never_installed_is_excluded_from_scoring(self):
        found, _ = self._match("T-RT-06", [], record={"id": "T-RT-06", "status": "failed",
                                                      "reason": "CUDA absent"})
        self.assertEqual(found.outcome, "excluded")
        self.assertEqual(found.detail, "failed")


if __name__ == "__main__":
    unittest.main()
