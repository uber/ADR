"""The snapshot reader, and the delta the harness derives itself."""

import unittest

from .scoring import snapshot as snapshot_module


def _asset(asset_id, name="tool", kind="cli_agent", **extra):
    payload = {"asset_id": asset_id, "name": name, "kind": kind, "evidence": [],
               "risk": {"factors": []}, "network": {}}
    payload.update(extra)
    return payload


def _snapshot(assets, hostname="adr-disco-linux", **extra):
    payload = {"hostname": hostname, "platform": "linux", "assets": assets}
    payload.update(extra)
    return snapshot_module.Snapshot(payload)


class Delta(unittest.TestCase):
    def test_added_assets_are_those_the_baseline_did_not_have(self):
        before = _snapshot([_asset("a")])
        after = _snapshot([_asset("a"), _asset("b", name="new")])
        self.assertEqual([item.name for item in snapshot_module.added_assets(before, after)],
                         ["new"])

    def test_a_reinstall_counts_as_added(self):
        """A tool that changed channel between scans is demonstrably present;
        dropping it here would score it as a miss."""
        before = _snapshot([_asset("a", identity="claude-code", install_method="npm")])
        after = _snapshot([_asset("z", identity="claude-code", install_method="brew")])
        self.assertEqual(len(snapshot_module.added_assets(before, after)), 1)

    def test_two_machines_are_refused(self):
        with self.assertRaises(ValueError):
            snapshot_module.added_assets(_snapshot([], hostname="one"),
                                         _snapshot([], hostname="two"))

    def test_repeated_ids_are_detectable(self):
        """A repeated id would silently halve the delta."""
        self.assertEqual(snapshot_module.duplicate_ids(_snapshot([_asset("a"), _asset("a")])), ["a"])
        self.assertEqual(snapshot_module.duplicate_ids(_snapshot([_asset("a"), _asset("b")])), [])


class Reading(unittest.TestCase):
    def test_unmodelled_fields_survive_in_raw(self):
        """The canary check searches the original document, so a credential in a
        field the harness does not model must still be searchable."""
        snap = _snapshot([_asset("a", surprise="sk-secret")])
        self.assertIn("sk-secret", snap.serialized())

    def test_risk_accessors(self):
        snap = _snapshot([_asset("a", risk={"factors": [], "pinned": False,
                                            "env_names": ["ANTHROPIC_API_KEY"]})])
        self.assertIs(snap.assets[0].pinned, False)
        self.assertEqual(snap.assets[0].env_names, ["ANTHROPIC_API_KEY"])


if __name__ == "__main__":
    unittest.main()
