"""Assets carry when the file behind them last changed."""

from __future__ import annotations

import json
import os

from adr_discovery.contracts.records import Kind
from adr_discovery.pipeline import discover
from adr_discovery.reporter import to_json
from adr_discovery.reporter.snapshot import from_dict

T_SKILL = 1_760_000_000  # 2025-10-09T08:53:20Z
T_DIR = 1_700_000_000


def _touch(world, path, when):
    os.utime(world.root + path, (when, when))


def test_a_skill_reports_its_skill_md_time_not_its_directory(world, catalog):
    world.file("/home/a/.claude/skills/s/SKILL.md", "---\nname: s\n---\n")
    _touch(world, "/home/a/.claude/skills/s/SKILL.md", T_SKILL)
    _touch(world, "/home/a/.claude/skills/s", T_DIR)

    (skill,) = [a for a in discover(world.gate(), catalog).assets if a.kind is Kind.SKILL]

    assert skill.modified == "2025-10-09T08:53:20+00:00"


def test_an_identified_binary_reports_its_file_time(world, catalog):
    release = "/home/a/.local/share/claude/versions/2.1.287"
    world.binary(release, "\x7fELF")
    world.symlink("/home/a/.local/bin/claude", release)
    _touch(world, release, T_SKILL)

    (asset,) = [a for a in discover(world.gate(), catalog).assets if a.catalog_id == "claude-code"]

    assert asset.modified == "2025-10-09T08:53:20+00:00"


def test_modified_survives_a_round_trip(world, catalog):
    world.file("/home/a/proj/CLAUDE.md", "# x\n")
    snapshot = discover(world.gate(), catalog)

    (asset,) = from_dict(json.loads(to_json(snapshot))).assets

    assert asset.modified and asset.modified == snapshot.assets[0].modified
