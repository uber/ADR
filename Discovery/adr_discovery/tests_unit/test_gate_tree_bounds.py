"""Tree enumeration must be bounded even when directories hold no files."""

from __future__ import annotations

import os
from contextlib import contextmanager

from adr_discovery.world.budget import Budget
from adr_discovery.world.gate import Gate


def test_empty_directories_have_a_separate_tree_budget(tmp_path):
    for name in ("a", "b", "c"):
        (tmp_path / name).mkdir()
    gate = Gate(str(tmp_path), budget=Budget(max_tree_directories=2))

    result = gate.hash_tree("/")

    assert not result.ok and result.reason == "too_many_directories"
    assert gate.ledger.freeze().boundaries_hit[0].boundary == "no_folder_hash"


def test_empty_directory_depth_is_bounded(tmp_path):
    (tmp_path / "a" / "b" / "c").mkdir(parents=True)
    gate = Gate(str(tmp_path), budget=Budget(max_tree_depth=1))

    result = gate.hash_tree("/")

    assert not result.ok and result.reason == "tree_too_deep"


def test_tree_enumeration_honors_exhausted_scan_time(tmp_path):
    gate = Gate(str(tmp_path), budget=Budget(max_seconds=0))

    result = gate.hash_tree("/")

    assert not result.ok and result.reason == "time_budget_exhausted"


def test_tree_enumeration_detects_directory_replacement(tmp_path, monkeypatch):
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "payload").write_bytes(b"old")
    original_scandir = os.scandir

    @contextmanager
    def swapping_scandir(path):
        with original_scandir(path) as listing:
            yield listing
        tree.rename(tmp_path / "original")
        tree.mkdir()
        (tree / "payload").write_bytes(b"new")

    gate = Gate(str(tmp_path))
    with monkeypatch.context() as patch:
        patch.setattr(os, "scandir", swapping_scandir)
        result = gate.hash_tree("/tree")

    assert not result.ok and result.reason == "unlistable"
    assert "swapped" in gate.ledger.freeze().boundaries_hit[0].detail
