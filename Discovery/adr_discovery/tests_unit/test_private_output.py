"""Output failure boundaries and publication; these need no live inventory scan."""

from __future__ import annotations

import json
import stat
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from adr_discovery import pipeline
from adr_discovery.archive import Archiver, zip_content_sha256
from adr_discovery.cli import _write_private
from adr_discovery.contracts.records import Asset, Kind
from adr_discovery.coverage.ledger import Ledger
from adr_discovery.world import private_output
from adr_discovery.world.gate import FolderHash, Ok
from adr_discovery.world.private_output import private_directory
from adr_discovery.world.store import ArchiveStore


def test_snapshot_roundtrip_existing_output_and_exclusive_name(tmp_path):
    output = tmp_path / "输出 with spaces"
    body = '{"value":"中文"}\r\n'
    target = _write_private(str(output), "snapshot.json", body)
    with open(target, "rb") as source:
        assert source.read() == body.encode("utf-8")
    with pytest.raises(FileExistsError):
        _write_private(str(output), "snapshot.json", "replacement")
    _write_private(str(output), "next.json", "{}")
    assert sorted(path.name for path in output.iterdir()) == ["next.json", "snapshot.json"]


@pytest.mark.parametrize("name", ["../outside", "..\\outside", "stream:secret", "NUL", "CON.txt", "name."])
def test_output_name_cannot_escape_or_address_a_windows_device(tmp_path, name):
    with pytest.raises(OSError):
        _write_private(str(tmp_path / "out"), name, "private")
    assert not (tmp_path / "out").exists()


def test_failed_snapshot_write_removes_partial_target(tmp_path, monkeypatch):
    def fail_sync(_fd):
        raise OSError("disk full")

    monkeypatch.setattr(private_output.os, "fsync", fail_sync)
    with pytest.raises(OSError, match="disk full"):
        _write_private(str(tmp_path / "out"), "snapshot.json", "private")
    assert list((tmp_path / "out").iterdir()) == []


def test_failed_index_replace_keeps_old_index_and_removes_temporary(tmp_path, monkeypatch):
    store = ArchiveStore(str(tmp_path / "out"))
    store.replace("index.jsonl", b"original\n")
    with private_directory(store.directory) as directory:
        directory_type = type(directory)

    def fail_publish(_self, _temporary, _name, *, replace):
        assert replace
        raise PermissionError("index held open")

    monkeypatch.setattr(directory_type, "publish", fail_publish)
    with pytest.raises(PermissionError, match="held open"):
        store.replace("index.jsonl", b"replacement\n")
    assert store.read("index.jsonl") == b"original\n"
    assert [path.name for path in (tmp_path / "out").iterdir()] == ["index.jsonl"]


def test_failed_temporary_write_is_removed(tmp_path, monkeypatch):
    def fail_sync(_fd):
        raise OSError("disk full")

    monkeypatch.setattr(private_output.os, "fsync", fail_sync)
    store = ArchiveStore(str(tmp_path / "out"))
    with pytest.raises(OSError, match="disk full"):
        store.put_once("archive.zip", b"private archive")
    assert list((tmp_path / "out").iterdir()) == []


def test_concurrent_archive_publication_has_one_complete_winner(tmp_path):
    store = ArchiveStore(str(tmp_path / "out"))
    store.open()
    payloads = [bytes([index]) * 100_000 for index in range(8)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(lambda data: store.put_once("archive.zip", data), payloads))
    assert sum(outcomes) == 1
    assert store.read("archive.zip") == payloads[outcomes.index(True)]
    assert [path.name for path in (tmp_path / "out").iterdir()] == ["archive.zip"]


class _TreeGate:
    """Only the tree-read contract; Windows output is exercised on real disk."""

    def __init__(self, trees):
        self.trees = trees
        self.ledger = Ledger()

    def read_tree(self, path, sink):
        data = self.trees[path]
        sink.begin(b"SKILL.md", stat.S_IFREG | 0o644)
        sink.update(data)
        return Ok(SimpleNamespace(files=1, bytes=len(data)))


def _hash(data):
    digest = FolderHash()
    digest.begin(b"SKILL.md", stat.S_IFREG | 0o644)
    digest.update(data)
    return digest.digest.hexdigest()


def _assets(trees):
    return tuple(Asset(asset_id=str(index), identity=path, kind=Kind.SKILL, name=str(index),
                       install_path=path, skill_sha256=_hash(data))
                 for index, (path, data) in enumerate(trees.items()))


def test_archive_preserves_raw_bytes_and_can_be_verified(tmp_path):
    data = b"---\r\nname: example\r\n---\r\n\x1a\0\xff"
    gate = _TreeGate({"skill": data})
    result = Archiver(ArchiveStore(str(tmp_path / "out"))).archive(gate, "skill", expected=_hash(data))
    assert result.ok
    with open(result.value.path, "rb") as source:
        assert zip_content_sha256(source.read()) == _hash(data)


def test_one_archive_io_failure_preserves_assets_and_continues(tmp_path, monkeypatch):
    class FailingOnce(ArchiveStore):
        failed = False

        def put_once(self, name, data):
            if not self.failed:
                self.failed = True
                raise PermissionError("one archive refused")
            return super().put_once(name, data)

    trees = {"/home/a/first": b"first", "/home/a/second": b"second"}
    gate = _TreeGate(trees)
    monkeypatch.setattr(pipeline, "homes", lambda _gate: ("/home/a",))
    assets = pipeline._archived(gate, _assets(trees), FailingOnce(str(tmp_path / "out")), "2026-10-17")
    assert len(assets) == 2
    assert assets[0].archive is None
    assert assets[1].archive is not None
    assert any(probe.status == "degraded" and "one archive refused" in probe.detail
               for probe in gate.ledger.freeze().probes)
    index = json.loads((tmp_path / "out" / "index.jsonl").read_text())
    assert index["skill_sha256"] == _hash(b"second")


def test_unreadable_index_is_not_replaced_with_an_empty_index(tmp_path, monkeypatch):
    class UnreadableIndex(ArchiveStore):
        def read(self, name):
            if name == self.INDEX:
                raise PermissionError("index read refused")
            return super().read(name)

    store = UnreadableIndex(str(tmp_path / "out"))
    store.replace(store.INDEX, b"original index\n")
    trees = {"/home/a/first": b"first", "/home/a/second": b"second"}
    gate = _TreeGate(trees)
    monkeypatch.setattr(pipeline, "homes", lambda _gate: ("/home/a",))
    assets = pipeline._archived(gate, _assets(trees), store, "2026-10-17")
    assert all(asset.archive is not None for asset in assets)
    assert (tmp_path / "out" / "index.jsonl").read_bytes() == b"original index\n"
    assert sum("index entry not recorded" in probe.detail for probe in gate.ledger.freeze().probes) == 2
