"""The manifest is a specification, so its shape is asserted like one."""

import unittest

from . import manifest as manifest_module


class ManifestShape(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = manifest_module.load()

    def test_the_manifest_is_complete(self):
        """120 entries. An entry not listed is an entry not tested."""
        self.assertEqual(len(self.manifest), 120)

    def test_applicable_counts_per_os(self):
        """Denominators differ per OS, which is why recall is never pooled."""
        self.assertEqual(len(self.manifest.for_platform("mac")), 110)
        self.assertEqual(len(self.manifest.for_platform("linux")), 105)
        self.assertEqual(len(self.manifest.for_platform("win")), 103)

    def test_fourteen_families_cover_everything(self):
        counts = {}
        for entry in self.manifest:
            counts[entry.family] = counts.get(entry.family, 0) + 1
        self.assertEqual(sum(counts.values()), 120)
        self.assertLessEqual(set(counts), manifest_module.FAMILIES)
        self.assertEqual(counts["declare-mcp"], 27)
        self.assertEqual(counts["artifact"], 24)
        self.assertEqual(counts["app-installer"], 16)

    def test_half_the_manifest_needs_no_installer(self):
        """The property the build order depends on: 51 entries are file writes."""
        no_installer = [entry for entry in self.manifest
                        if entry.family in ("declare-mcp", "artifact")]
        self.assertEqual(len(no_installer), 51)

    def test_every_catalogued_tool_appears_once(self):
        seen = {}
        for entry in self.manifest:
            if entry.catalog_id:
                seen[entry.catalog_id] = seen.get(entry.catalog_id, 0) + 1
        self.assertEqual([k for k, v in seen.items() if v > 1], [])
        self.assertEqual(len(seen), 42)

    def test_installed_packages_are_pinned(self):
        """An unpinned install makes `version` unscoreable."""
        for entry in self.manifest:
            if entry.family in ("npm-global", "pipx", "vscode-ext"):
                self.assertTrue(entry.install.get("version"), entry.id)

    def test_variants_name_a_base_that_applies_there(self):
        for entry in self.manifest:
            if not entry.variant_of:
                continue
            base = self.manifest.by_id(entry.variant_of)
            for platform in entry.platforms:
                self.assertTrue(base.applies_to(platform), "%s on %s" % (entry.id, platform))

    def test_shapes_are_derived_not_declared(self):
        shapes = {entry.shape for entry in self.manifest}
        self.assertEqual(shapes, {"install", "declare", "create", "state"})


class ManifestValidation(unittest.TestCase):
    def test_a_bad_family_is_refused_at_load(self):
        with self.assertRaises(manifest_module.ManifestError):
            manifest_module._family({"id": "X-01", "install": {"method": "telepathy"}})


if __name__ == "__main__":
    unittest.main()
