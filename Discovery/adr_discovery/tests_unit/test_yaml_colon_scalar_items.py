"""A sequence item containing a colon is not necessarily a mapping.

`- localhost:9000`, `- https://host/path` and `- "8080:80"` are scalars in
YAML; only `- key: value` (or `- key:`) opens a mapping.
"""

from __future__ import annotations

from adr_discovery.extractor.formats.yaml import loads


def test_colon_scalars_stay_scalars():
    doc = loads(
        "items:\n"
        "  - localhost:9000\n"
        "  - https://example.com/mcp\n"
        "  - \"8080:80\"\n"
        "  - 'a: b'\n"
    )

    assert doc == {"items": ["localhost:9000", "https://example.com/mcp", "8080:80", "a: b"]}


def test_key_value_items_still_open_mappings():
    doc = loads("steps:\n  - uses: actions/checkout@v4\n  - name:\n    run: x\n")

    assert doc == {"steps": [{"uses": "actions/checkout@v4"}, {"name": None, "run": "x"}]}
