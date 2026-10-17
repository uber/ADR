"""Skill archives: a skill directory as a zip, named by its folder hash.

So that a user who learns a skill on their machine is malicious can hand
over exactly that skill, and whoever receives it can prove it is the one a
snapshot named. Opt-in, local only, never transmitted by the collector.

The zip is deterministic and holds what the folder hash covers and nothing
else:

- every regular file, symlinks never followed, entries sorted by their
  ``/``-separated path relative to the skill directory, no top-level folder;
- each entry dated 1980-01-01, deflated at a fixed level, with its Unix
  mode in the external attributes so the execute bit survives.

`zip_content_sha256` recomputes the folder hash from a zip without
extracting it; an archive is kept only when that equals the hash of the
tree it was read from. The directory is content-addressed
(``<skill_sha256>.zip``): an existing archive is verified, never rewritten.
``index.jsonl`` beside the archives says where each was seen and when.
"""

from __future__ import annotations

import hashlib
import io
import json
import posixpath
import stat
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone

from .contracts.records import ArchiveRef
from .world.gate import FolderHash, Gate, Ok, Refused, Result
from .world.store import ArchiveStore

ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)
COMPRESS_LEVEL = 9
#: Limits on reading an archive someone else made: the same as the caps
#: on hashing a tree, so anything this module writes it can also read.
MAX_MEMBERS = 10_000
MAX_FILE_BYTES = 20 * 1024 * 1024
MAX_TOTAL_BYTES = 100 * 1024 * 1024


class ArchiveError(ValueError):
    """A zip that is unsafe, over the limits, or not an archive at all."""


@dataclass(frozen=True, slots=True)
class Archived:
    skill_sha256: str
    archive_sha256: str
    path: str
    files: int
    bytes: int
    #: False when an identical archive was already in the directory.
    written: bool

    @property
    def ref(self) -> ArchiveRef:
        return ArchiveRef(path=self.path, sha256=self.archive_sha256)


# --------------------------------------------------------------- format


def zip_content_sha256(data: bytes) -> str:
    """The folder hash of the tree a zip holds, read without extracting.

    Entries are untrusted: absolute paths, ``..`` escapes and duplicates are
    refused, links and other non-regular entries are not content, and the
    member, per-file and total limits hold whatever the headers claim.
    """
    return _content(data)[0]


def _content(data: bytes) -> tuple[str, int, int]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise ArchiveError(f"not a zip archive: {exc}") from exc
    with archive:
        infos = archive.infolist()
        if len(infos) > MAX_MEMBERS:
            raise ArchiveError(f"{len(infos)} entries; limit {MAX_MEMBERS}")
        members: dict[str, zipfile.ZipInfo] = {}
        for info in infos:
            name = _safe_name(info.filename)
            mode = info.external_attr >> 16
            if info.is_dir() or (mode and not stat.S_ISREG(mode)):
                continue
            if name in members:
                raise ArchiveError(f"duplicate entry: {name!r}")
            members[name] = info

        digest = FolderHash()
        total = 0
        for name in sorted(members, key=lambda n: n.encode("utf-8")):
            info = members[name]
            digest.begin(name.encode("utf-8"), info.external_attr >> 16)
            size = 0
            with archive.open(info) as source:
                while chunk := source.read(1 << 20):
                    size += len(chunk)
                    total += len(chunk)
                    if size > MAX_FILE_BYTES:
                        raise ArchiveError(f"{name!r} exceeds {MAX_FILE_BYTES} bytes")
                    if total > MAX_TOTAL_BYTES:
                        raise ArchiveError(f"archive exceeds {MAX_TOTAL_BYTES} bytes")
                    digest.update(chunk)
        return digest.digest.hexdigest(), len(members), total


def _safe_name(name: str) -> str:
    if not name or name.startswith("/") or "\\" in name or (len(name) > 1 and name[1] == ":"):
        raise ArchiveError(f"unsafe entry path: {name!r}")
    trailing = "/" if name.endswith("/") else ""
    normalized = posixpath.normpath(name)
    if normalized in ("", ".", "..") or normalized.startswith("../"):
        raise ArchiveError(f"entry escapes the archive: {name!r}")
    return normalized + trailing


class _Pack:
    """Builds the zip and the folder hash in one read of the tree, so the
    archive and the name it is filed under cannot describe two trees."""

    def __init__(self) -> None:
        self.hash = FolderHash()
        self._buffer = io.BytesIO()
        self._zip = zipfile.ZipFile(self._buffer, "w", zipfile.ZIP_DEFLATED)
        self._entry: zipfile.ZipInfo | None = None
        self._chunks: list[bytes] = []

    def begin(self, rel: bytes, mode: int) -> None:
        self._flush()
        self.hash.begin(rel, mode)
        entry = zipfile.ZipInfo(rel.decode("utf-8"), date_time=ZIP_EPOCH)
        entry.compress_type = zipfile.ZIP_DEFLATED
        entry.create_system = 3  # Unix, so the external attributes are a mode
        entry.external_attr = (stat.S_IFREG | stat.S_IMODE(mode)) << 16
        self._entry = entry

    def update(self, chunk: bytes) -> None:
        self.hash.update(chunk)
        self._chunks.append(chunk)

    def finish(self) -> bytes:
        self._flush()
        self._zip.close()
        return self._buffer.getvalue()

    def close(self) -> None:
        self._zip.close()

    def _flush(self) -> None:
        if self._entry is not None:
            self._zip.writestr(self._entry, b"".join(self._chunks), compresslevel=COMPRESS_LEVEL)
        self._entry, self._chunks = None, []


# ------------------------------------------------------------- archiver


class Archiver:
    """Archives skills into one store and keeps its index for one run."""

    def __init__(self, store: ArchiveStore, now: str = "") -> None:
        self.store = store
        self.now = now or datetime.now(timezone.utc).isoformat(timespec="seconds")
        self._index: dict[tuple[str, str], dict] | None = None
        self._dirty = False

    def archive(self, gate: Gate, path: str, expected: str | None = None) -> Result[Archived]:
        """Archive the skill directory at `path` (a logical path, read
        through `gate`). With `expected`, an archive already filed under
        that hash is verified and reused without reading the tree again."""
        try:
            return self._archive(gate, path, expected)
        except (OSError, ArchiveError, zipfile.BadZipFile) as exc:
            return Refused("archive_failed", str(exc))

    def _archive(self, gate: Gate, path: str, expected: str | None) -> Result[Archived]:
        if expected is not None:
            kept = self._existing(expected)
            if kept is not None:
                return kept
        pack = _Pack()
        try:
            try:
                read = gate.read_tree(path, pack)
            except UnicodeDecodeError:
                return Refused("unencodable_name", "a file name is not UTF-8")
            if not read.ok:
                return read
            digest = pack.hash.digest.hexdigest()
            if expected is not None and digest != expected:
                return Refused("changed", "the tree changed after it was hashed")
            kept = self._existing(digest)
            if kept is not None:
                return kept
            data = pack.finish()
        finally:
            pack.close()
        if zip_content_sha256(data) != digest:
            return Refused("verify_failed", "archive does not reproduce the folder hash")
        written = self.store.put_once(f"{digest}.zip", data)
        if not written:
            return self._existing(digest) or Refused("verify_failed", "a concurrent archive did not verify")
        return Ok(Archived(digest, hashlib.sha256(data).hexdigest(), self.store.path_of(f"{digest}.zip"),
                           read.value.files, read.value.bytes, written=True))

    def _existing(self, digest: str) -> Result[Archived] | None:
        data = self.store.read(f"{digest}.zip")
        if data is None:
            return None
        try:
            content, files, size = _content(data)
        except (ArchiveError, zipfile.BadZipFile) as exc:
            return Refused("corrupt_archive", str(exc))
        if content != digest:
            return Refused("corrupt_archive", f"{digest}.zip holds {content}")
        return Ok(Archived(digest, hashlib.sha256(data).hexdigest(), self.store.path_of(f"{digest}.zip"),
                           files, size, written=False))

    def record(self, archived: Archived, name: str, source: str, provenance: dict | None = None) -> None:
        """Note in the index that this archive was seen at `source` now."""
        index = self._load()
        key = (archived.skill_sha256, source)
        previous = index.get(key)
        row = {
            "skill_sha256": archived.skill_sha256,
            "archive": f"{archived.skill_sha256}.zip",
            "archive_sha256": archived.archive_sha256,
            "name": name,
            "source": source,
            "provenance": provenance,
            "files": archived.files,
            "bytes": archived.bytes,
            "first_seen": previous["first_seen"] if previous else self.now,
            "last_seen": self.now,
        }
        if row != previous:
            index[key] = row
            self._dirty = True

    def close(self) -> None:
        if not self._dirty or self._index is None:
            return
        lines = [json.dumps(self._index[key], sort_keys=True) for key in sorted(self._index)]
        self.store.replace(ArchiveStore.INDEX, ("\n".join(lines) + "\n").encode("utf-8"))
        self._dirty = False

    def _load(self) -> dict[tuple[str, str], dict]:
        if self._index is None:
            index = {}
            raw = self.store.read(ArchiveStore.INDEX) or b""
            for line in raw.decode("utf-8", errors="replace").splitlines():
                try:
                    row = json.loads(line)
                    index[(row["skill_sha256"], row["source"])] = row
                except (ValueError, KeyError, TypeError):
                    continue  # a damaged line is dropped, not fatal
            self._index = index
        return self._index


def archive_skill(path: str, dest: str, gate: Gate | None = None, now: str = "") -> Result[Archived]:
    """Archive one skill directory into `dest`, outside a scan.

    For a detection step that flags a skill the scan did not archive. `path`
    is a path on this machine unless `gate` says otherwise.
    """
    store = ArchiveStore(dest)
    try:
        store.open()
        archiver = Archiver(store, now)
        result = archiver.archive(gate if gate is not None else Gate("/"), path)
        if result.ok:
            name = path.rstrip("/\\").replace("\\", "/").rsplit("/", 1)[-1]
            archiver.record(result.value, name=name, source=path)
            archiver.close()
        return result
    except OSError as exc:
        return Refused("archive_failed", str(exc))
