"""JSON with comments: VS Code's mcp.json, Zed's settings.json, `.jsonc`."""

from __future__ import annotations

import pytest

from adr_discovery.contracts.records import Candidate
from adr_discovery.extractor import extract
from adr_discovery.extractor.formats import parse

VSCODE = """{
  // Inputs are prompted on first server start, then stored by VS Code.
  "inputs": [],
  "servers": {
    "fetch": {"command": "uvx", "args": ["mcp-server-fetch"]},
    /* "old": {"command": "retired"}, */
  },
}
"""


def test_commented_vscode_mcp_json_is_read(world):
    path = "/Users/a/Library/Application Support/Code/User/mcp.json"
    world.file(path, VSCODE)

    result = extract(world.gate(), Candidate("marker_file", path, "sweep"))

    assert result.errors == ()
    assert [d.name for d in result.declarations] == ["fetch"]


def test_comment_markers_inside_strings_are_kept():
    text = '{"url": "https://x.example//a", "s": "\\"/*", // note\n "t": [1, 2,],}'

    assert parse(text, "json") == {"url": "https://x.example//a", "s": '"/*', "t": [1, 2]}


def test_invalid_json_still_raises():
    with pytest.raises(ValueError):
        parse('{"a": }', "json")
