"""Native Windows coverage for Gate; executed by the Windows CI job only."""

from __future__ import annotations

import hashlib
import os
import subprocess
from contextlib import contextmanager

import pytest

from adr_discovery.world.budget import Budget
from adr_discovery.world.gate import Gate

pytestmark = pytest.mark.skipif(os.name != "nt", reason="requires native Windows filesystem semantics")


def _junction(link, target):
    command = os.path.join(os.environ["SYSTEMROOT"], "System32", "cmd.exe")
    subprocess.run(
        [command, "/d", "/c", "mklink", "/J", str(link), str(target)],
        check=True, capture_output=True, timeout=10,
    )


def test_live_world_reads_native_paths_and_keeps_unc_anchors(tmp_path):
    target = tmp_path / "中文 file.bin"
    target.write_bytes(b"payload")
    gate = Gate()

    result = gate.read_bytes(str(target))

    assert result.ok and result.value == b"payload"
    assert gate.logical_path(str(target)) == target.as_posix()
    assert gate.host_path(r"\\server\share\folder") == r"\\server\share\folder"
    assert gate.host_path(r"D:\apps\tool.exe") == r"D:\apps\tool.exe"
    assert gate.host_path(r"\\?\C:\apps\tool.exe") == r"\\?\C:\apps\tool.exe"


def test_fixture_containment_supports_drive_roots_and_roundtrips(tmp_path):
    root_gate = Gate(tmp_path.anchor)
    stat = root_gate.stat(str(tmp_path))
    assert stat.ok, stat

    fixture = tmp_path / "fixture"
    fixture.mkdir()
    target = fixture / "nested" / "settings.json"
    target.parent.mkdir()
    target.write_bytes(b"{}")
    gate = Gate(str(fixture))

    assert gate.read_bytes("/nested/settings.json").value == b"{}"
    assert gate.logical_path(str(target)) == "/nested/settings.json"
    assert os.path.samefile(gate.host_path(gate.logical_path(str(target))), target)
    assert gate.logical_path(str(fixture)) == "/"
    assert gate.stat(str(target).swapcase()).ok

    sibling = tmp_path / "fixture-neighbor"
    sibling.mkdir()
    assert gate.stat(str(sibling)).reason == "outside_root"
    assert gate.stat("/../fixture-neighbor").reason == "outside_root"
    other_drive = "Z:" if tmp_path.drive.upper() != "Z:" else "Y:"
    assert gate.stat(other_drive + r"\outside").reason == "outside_root"


def test_directory_listing_retains_logical_paths_and_budget(tmp_path):
    for name in ("a", "b", "中文"):
        (tmp_path / name).mkdir()
    gate = Gate(str(tmp_path), budget=Budget(max_entries=2))

    result = gate.list_dir("/")

    assert result.ok and len(result.value) == 2
    assert all(entry.path.startswith("/") and "\\" not in entry.path for entry in result.value)
    assert all(entry.is_dir for entry in result.value)
    assert gate.budget.entries_used == 2
    assert any(b.boundary == "budget_exhausted" for b in gate.ledger.freeze().boundaries_hit)

    fresh = Gate(str(tmp_path))
    first = fresh.list_dir("/", retain=True)
    used = fresh.budget.entries_used
    assert first.ok and fresh.list_dir("/") == first
    assert fresh.budget.entries_used == used
    assert fresh.list_dir("/missing").reason == "absent"


def test_directory_swap_before_enumeration_is_refused(tmp_path):
    folder = tmp_path / "folder"
    folder.mkdir()
    gate = Gate(str(tmp_path))

    def replace_directory(_resolved):
        folder.rename(tmp_path / "original")
        folder.mkdir()
        (folder / "untrusted").write_bytes(b"x")

    gate.on_validated = replace_directory
    result = gate.list_dir("/folder", retain=True)

    assert not result.ok and result.reason == "swapped"
    assert gate.ledger.freeze().denied
    gate.on_validated = None
    assert [e.path for e in gate.list_dir("/folder").value] == ["/folder/untrusted"]


def test_directory_swap_after_enumeration_is_not_published(tmp_path, monkeypatch):
    folder = tmp_path / "folder"
    folder.mkdir()
    (folder / "old").write_bytes(b"x")
    original_scandir = os.scandir

    @contextmanager
    def swapping_scandir(path):
        with original_scandir(path) as listing:
            yield listing
        folder.rename(tmp_path / "original")
        folder.mkdir()

    gate = Gate(str(tmp_path))
    with monkeypatch.context() as patch:
        patch.setattr(os, "scandir", swapping_scandir)
        result = gate.list_dir("/folder", retain=True)

    assert not result.ok and result.reason == "swapped"
    assert gate.ledger.freeze().denied
    assert gate.list_dir("/folder").value == ()


def test_reads_and_folder_hash_preserve_raw_bytes(tmp_path):
    payload = b"first\r\nsecond\x1aafter-eof\x00\xff"
    target = tmp_path / "payload.bin"
    target.write_bytes(payload)
    gate = Gate(str(tmp_path))

    assert gate.read_bytes("/payload.bin").value == payload
    result = gate.hash_tree("/")

    executable = b"1" if target.stat().st_mode & 0o111 else b"0"
    expected = hashlib.sha256(b"payload.bin\n" + executable + b"\n" + payload).hexdigest()
    assert result.ok
    assert result.value.sha256 == expected
    assert result.value.bytes == len(payload)


def test_junction_cycle_is_not_followed_by_walk_or_hash(tmp_path):
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "SKILL.md").write_bytes(b"skill\r\n")
    link = skill / "parent"
    gate = Gate(str(tmp_path))
    before = gate.hash_tree("/skill")
    _junction(link, skill)
    try:
        listing = gate.list_dir("/skill")
        junction = next(e for e in listing.value if e.path.endswith("/parent"))
        assert junction.is_reparse
        walked = list(gate.walk("/skill"))
        assert not any("/parent/" in e.path for e in walked)
        assert gate.hash_tree("/skill").value.sha256 == before.value.sha256
    finally:
        link.rmdir()


def test_junction_target_still_obeys_fixture_and_personal_boundaries(tmp_path):
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "private.bin").write_bytes(b"secret")
    personal = fixture / "Users" / "Alice" / "Documents"
    personal.mkdir(parents=True)
    (personal / "private.bin").write_bytes(b"secret")
    escape, notes = fixture / "escape", fixture / "notes"
    _junction(escape, outside)
    _junction(notes, personal)
    try:
        gate = Gate(str(fixture))
        assert gate.read_bytes("/escape/private.bin").reason == "outside_root"
        assert gate.list_dir("/escape").reason == "outside_root"
        assert gate.read_bytes("/notes/private.bin").reason == "personal_path"
        assert gate.list_dir("/notes").reason == "personal_path"
    finally:
        escape.rmdir()
        notes.rmdir()
