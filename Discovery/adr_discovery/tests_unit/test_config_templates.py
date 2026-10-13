"""Config-file templates cover the macOS and Windows locations of each host."""

from __future__ import annotations

import pytest

from adr_discovery.enumerator.markers import CONFIG_FILE_TEMPLATES
from adr_discovery.enumerator.sources.appstate import from_app_state

HOME_TEMPLATES = [t for t in CONFIG_FILE_TEMPLATES if t.startswith("~")]

REQUIRED = [
    "~/Library/Application Support/Claude/claude_desktop_config.json",
    "~/AppData/Roaming/Claude/claude_desktop_config.json",
    "~/Library/Application Support/Code/User/mcp.json",
    "~/AppData/Roaming/Code/User/mcp.json",
    "~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
    "~/AppData/Roaming/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
    "~/.claude/settings.json",
    "~/.claude/settings.local.json",
    "/Library/Application Support/ClaudeCode/managed-settings.json",
]


@pytest.mark.parametrize("template", REQUIRED)
def test_required_locations_are_templates(template):
    assert template in CONFIG_FILE_TEMPLATES


@pytest.mark.parametrize("template", HOME_TEMPLATES)
def test_a_file_at_each_home_template_yields_a_candidate(world, template):
    path = "/Users/alice" + template[1:]
    world.file(path, "{}")

    candidates = from_app_state(world.gate(), ("/Users/alice",))

    hits = [c for c in candidates if c.source == "app_state:config" and c.path == path]
    assert len(hits) == 1
    assert hits[0].kind in ("marker_file", "shell_profile")


def test_absolute_template_yields_a_candidate(world):
    path = "/Library/Application Support/ClaudeCode/managed-settings.json"
    world.file(path, "{}")

    candidates = from_app_state(world.gate(), ("/Users/alice",))

    assert path in {c.path for c in candidates if c.source == "app_state:config"}
