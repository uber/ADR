"""Matching is where a harness invents defects, so each rule is asserted alone."""

import unittest

from adr_discovery.contracts.records import Asset, Kind

from . import manifest as manifest_module
from .scoring.match import identity_of, launch_identity, match, normalize_path


def asset(asset_id, **kw):
    kw.setdefault("kind", Kind.CLI_AGENT)
    kw.setdefault("name", asset_id)
    kw.setdefault("identity", asset_id)
    return Asset(asset_id=asset_id, **kw)


class Normalization(unittest.TestCase):
    def test_a_home_reference_becomes_a_path(self):
        self.assertEqual(normalize_path("~/.claude.json", "/root"), "/root/.claude.json")
        self.assertEqual(normalize_path("%USERPROFILE%/x", "/users/a"), "/users/a/x")

    def test_windows_separators_compare_with_posix_ones(self):
        self.assertEqual(normalize_path(r"C:\Users\a\x"), normalize_path("C:/Users/a/x"))

    def test_launch_identity_ignores_formatting(self):
        """`docker run x` declared by two people is one server, not two."""
        self.assertEqual(
            launch_identity("docker", ["run", "mcp/memory:latest"]),
            launch_identity("/usr/bin/docker", ["run", "  mcp/memory:latest "]),
        )

    def test_an_empty_path_stays_empty(self):
        self.assertEqual(normalize_path(None), "")


class Claiming(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = manifest_module.load()

    def test_an_asset_is_claimed_once(self):
        """Two rows at one path must not both report success for one asset."""
        rows = [self.manifest.by_id("S-01"), self.manifest.by_id("S-02")]
        one = asset("only", install_path=rows[0].path_for("linux"))
        result = match(rows, [one], platform="linux")
        claimed = [m for m in result.matches if m.assets]
        self.assertEqual(len(claimed), 1)

    def test_an_asset_indexed_by_two_paths_is_not_its_own_duplicate(self):
        """install_path and install_root are often the same file."""
        row = self.manifest.by_id("S-01")
        path = row.path_for("linux")
        result = match([row], [asset("a", install_path=path, install_root=path)], platform="linux")
        self.assertEqual(result.matches[0].assets, ("a",))

    def test_a_surplus_asset_at_a_shared_key_is_a_duplicate(self):
        row = self.manifest.by_id("S-01")
        path = row.path_for("linux")
        result = match([row], [asset("a", install_path=path), asset("b", install_path=path)],
                       platform="linux")
        self.assertEqual(len(result.matches[0].assets), 2)

    def test_an_unmatched_asset_is_left_over(self):
        row = self.manifest.by_id("S-01")
        result = match([row], [asset("stranger", install_path="/nowhere")], platform="linux")
        self.assertIn("stranger", result.unmatched_assets)


class Shapes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = manifest_module.load()

    def test_a_variant_claims_nothing(self):
        """Two installs of one tool must yield one asset, not two."""
        variants = [e for e in self.manifest if e.variant_of]
        self.assertTrue(variants)
        result = match(variants, [asset("x")], platform="linux")
        self.assertTrue(all(m.assets == () for m in result.matches))

    def test_an_assertion_does_not_consume_the_asset_it_describes(self):
        """AG-08 asserts a property of the tool T-CLI-01 installed."""
        tool = self.manifest.by_id("T-CLI-01")
        claim = self.manifest.by_id("AG-08")
        found = asset("claude", catalog_id="claude-code")
        result = match([tool, claim], [found], platform="linux")
        self.assertEqual(result.for_entry("T-CLI-01").assets, ("claude",))
        self.assertEqual(result.for_entry("AG-08").assets, ("claude",))
        self.assertEqual(result.unmatched_assets, ())

    def test_a_remote_server_is_identified_by_where_it_points(self):
        """M-PIN-09 launches nothing, so a launch identity would be empty."""
        entry = self.manifest.by_id("M-PIN-09")
        self.assertTrue(identity_of(entry, platform="linux"))

    def test_the_same_command_at_two_sites_is_two_assets(self):
        """Fourteen M-SITE rows share one command and differ only by site."""
        sites = [e for e in self.manifest if e.id.startswith("M-SITE-")]
        keys = {identity_of(e, platform="linux") for e in sites}
        self.assertEqual(len(keys), 1, "these rows deliberately share a launch identity")
        result = match(sites, [], platform="linux")
        self.assertEqual(len({m.key for m in result.matches}), len(sites))


if __name__ == "__main__":
    unittest.main()
