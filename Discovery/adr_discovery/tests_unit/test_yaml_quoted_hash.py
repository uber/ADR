"""` #` inside a quoted value is text, not the start of a comment."""

from __future__ import annotations

from adr_discovery.extractor.formats.yaml import loads


def test_hash_inside_quotes_survives():
    doc = loads("name: \"a # b\"\nlabel: 'c #d'\nitems:\n  - \"x # y\"\n")

    assert doc == {"name": "a # b", "label": "c #d", "items": ["x # y"]}


def test_comments_outside_quotes_are_still_dropped():
    doc = loads("# header\nname: \"a\"  # trailing\nother: it's # gone\nn: 3 # c\n")

    assert doc == {"name": "a", "other": "it's", "n": 3}
