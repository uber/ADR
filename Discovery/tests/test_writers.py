"""Emitting the three config formats, and the content that goes in them.

Pure functions with no guest anywhere near them, which makes them the part of
the installer that can be checked exactly. A site whose shape is wrong produces
a file the collector reads as empty - that would score as a missed site and
blame the collector for the harness's own mistake - so the emitters are worth
asserting on their own rather than only through a run.
"""

import json
import unittest

from .install import bodies, writers


class Merging(unittest.TestCase):
    def test_lists_concatenate_rather_than_replace(self):
        """Two hook entries write one settings file; replacing would delete the
        first and report it as a miss."""
        merged = writers.merge({"hooks": {"PreToolUse": [{"a": 1}]}},
                               {"hooks": {"PreToolUse": [{"b": 2}]}})
        self.assertEqual(len(merged["hooks"]["PreToolUse"]), 2)

    def test_nested_maps_merge_recursively(self):
        merged = writers.merge({"mcpServers": {"one": {}}}, {"mcpServers": {"two": {}}})
        self.assertEqual(sorted(merged["mcpServers"]), ["one", "two"])


class Toml(unittest.TestCase):
    def test_nested_tables_round_trip(self):
        import tomllib
        document = {"mcp_servers": {"probe": {"command": "node", "args": ["server.js"]}}}
        self.assertEqual(tomllib.loads(writers.as_toml(document)), document)

    def test_keys_that_need_quoting_get_it(self):
        import tomllib
        document = {"mcp_servers": {"has.a.dot": {"command": "node"}}}
        self.assertEqual(tomllib.loads(writers.as_toml(document)), document)

    def test_an_unsupported_value_raises_rather_than_degrades(self):
        """A writer that silently dropped a value would produce a config the
        collector reads differently from the one the manifest describes."""
        with self.assertRaises(TypeError):
            writers.as_toml({"a": {"b": object()}})


class Yaml(unittest.TestCase):
    def test_scalars_are_quoted_unconditionally(self):
        """Quoting costs nothing and removes the class of bug where `yes` or a
        date parses as something other than the string it was written as."""
        text = writers.as_yaml({"extensions": {"probe": {"command": "yes"}}})
        self.assertIn('command: "yes"', text)

    def test_lists_render_as_block_items(self):
        text = writers.as_yaml({"extensions": {"probe": {"args": ["a", "b"]}}})
        self.assertIn('- "a"', text)
        self.assertIn('- "b"', text)


class Bodies(unittest.TestCase):
    def test_every_artifact_is_marked_as_a_test_artifact(self):
        """So nobody finds one on a machine later and wonders what it is."""
        for text in (bodies.skill("s"), bodies.command("c"), bodies.subagent("a"),
                     bodies.instructions("i"), bodies.backup_script(), bodies.llm_wrapper(),
                     bodies.probe_server(), bodies.malformed_bundle()):
            self.assertIn(bodies.MARKER, text)

    def test_the_malformed_bundle_declares_nothing_runnable(self):
        """It must be recorded as malformed, not as a server: a collector that
        reports it as a server is inventing one."""
        bundle = json.loads(bodies.malformed_bundle())
        self.assertEqual(bundle["server"], {})
        self.assertIn("manifest_version", bundle)

    def test_the_lookalike_script_does_nothing_mcp_shaped(self):
        """N-07's whole point is that "mcp" appears in its path and nowhere in
        what it does. The comments may say so; the executable lines may not."""
        code = [line for line in bodies.backup_script().splitlines()
                if line.strip() and not line.strip().startswith("#")]
        for line in code:
            self.assertNotIn("mcp", line.lower(), line)

    def test_the_wrapper_looks_like_ai_without_being_classifiable(self):
        """N-10 must be worth reviewing and impossible to name."""
        text = bodies.llm_wrapper()
        self.assertIn("completions", text)

    def test_a_hook_fragment_carries_its_event_and_command(self):
        fragment = bodies.hook("PreToolUse", "audit.sh --token abc")
        entry = fragment["hooks"]["PreToolUse"][0]["hooks"][0]
        self.assertEqual(entry["command"], "audit.sh --token abc")


if __name__ == "__main__":
    unittest.main()
