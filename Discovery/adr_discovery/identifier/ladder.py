"""The evidence ladder -- cheapest and strongest first.

A candidate stops climbing as soon as it has proof, which is both the cost
control and the correctness rule. Convention sits on the bottom rung and
raises priority; it never concludes, because the next rename breaks any
verdict that rests on it.

    1  provenance   which package owns this file        one cacheable query
    2  content      hash, format metadata, strings      one size-capped read
    3  behaviour    a probe whose output must match     one sandboxed run
    4  convention   filename, path, directory shape     free, never conclusive
"""

from __future__ import annotations

import hashlib

from ..contracts.evidence import Channel, Evidence, Rung
from ..contracts.records import Candidate, Kind, Verdict
from .openworld import score, signals_for
from .verify import check_version

MAX_HASH_BYTES = 8 * 1024 * 1024

#: Executable formats, by magic. Cheap, and it distinguishes a compiled
#: build from a shell wrapper that happens to answer a version probe.
_MAGIC: tuple[tuple[bytes, str], ...] = (
    (b"\x7fELF", "elf"),
    (b"\xcf\xfa\xed\xfe", "mach-o"),
    (b"\xce\xfa\xed\xfe", "mach-o"),
    (b"\xca\xfe\xba\xbe", "mach-o-universal"),
    (b"MZ", "pe"),
    (b"#!", "script"),
)

#: Only a compiled object is content evidence of identity. A `#!` wrapper
#: is a file that runs something else -- which is precisely the decoy
#: shape, and must not be allowed to strengthen a verdict.
COMPILED_FORMATS = frozenset({"elf", "mach-o", "mach-o-universal", "pe"})


def binary_format(gate, path: str) -> str | None:
    """What kind of executable this is, from its first bytes."""
    raw = gate.read_bytes(path, limit=64)
    if not raw.ok or not raw.value:
        return None
    for magic, name in _MAGIC:
        if raw.value.startswith(magic):
            return name
    return None


def content_hash(gate, path: str, limit: int = MAX_HASH_BYTES) -> str | None:
    """One size-capped read. Returns None when the target is not a file we
    are allowed, or able, to read -- never a hash of partial bytes."""
    stat = gate.stat(path)
    if not stat.ok or stat.value.size > limit:
        return None
    raw = gate.read_bytes(path, limit=limit)
    if not raw.ok or len(raw.value) < stat.value.size:
        return None
    return hashlib.sha256(raw.value).hexdigest()


def identify(gate, candidate: Candidate, catalog) -> Verdict:
    """Produce a verdict, with the proof that produced it."""
    name = candidate.path.rsplit("/", 1)[-1]

    if candidate.kind == "model_weight_candidate":
        raw = gate.read_bytes(candidate.path, limit=64)
        if raw.ok and _is_model_weight(raw.value, candidate.path):
            return Verdict(
                catalog_id=None, kind=Kind.MODEL_WEIGHTS, name=name,
                rung=Rung.CONTENT,
                evidence=(Evidence("identifier", Channel.FILESYSTEM, candidate.path,
                                   "verified model-weight format", 0.85, Rung.CONTENT),),
            )

    # ---------------------------------------------------------- rung 1
    entry, evidence, pkg_version = _by_provenance(gate, candidate, catalog)
    if entry is not None:
        # Before accepting it, ask whether any other channel names something
        # else. A silent preference is how an inventory becomes confidently
        # wrong; a recorded conflict is something a reviewer can settle.
        conflict = _conflicting(catalog, candidate, name, entry)
        return _catalogued(gate, entry, candidate, Rung.PROVENANCE, evidence,
                           probe=False, version=pkg_version, conflict=conflict)

    # ---------------------------------------------------------- rung 2
    entry, evidence = _by_content(gate, candidate, catalog)
    if entry is not None:
        return _catalogued(gate, entry, candidate, Rung.CONTENT, evidence, probe=True)

    # ---------------------------------------------------------- rung 4 (as a hint)
    suspected = _suspected(catalog, candidate, name)

    # ---------------------------------------------------------- rung 3
    if suspected is not None and candidate.kind in ("binary", "process", "exec_event", "package"):
        version, proof = check_version(gate, candidate.path, suspected.version_probe, suspected.version_shape)
        if version is not None:
            evidence = [
                Evidence("identifier", Channel.RUNTIME, candidate.path, proof, 0.8, Rung.BEHAVIOUR)
            ]
            # A self-compiled build has no package record and no known
            # hash, but it is still a compiled object -- which separates it
            # from a shell wrapper that merely answers the same way.
            fmt = binary_format(gate, candidate.path)
            compiled = fmt in COMPILED_FORMATS
            if compiled:
                evidence.insert(0, Evidence(
                    "identifier", Channel.FILESYSTEM, candidate.path,
                    f"{fmt} executable", 0.4, Rung.CONTENT))
            return Verdict(
                catalog_id=suspected.id, kind=_kind(suspected), name=suspected.name,
                vendor=suspected.vendor, version=version,
                rung=Rung.CONTENT if compiled else Rung.BEHAVIOUR,
                evidence=tuple(evidence),
            )
        # The output was not believed. Fall through to open-world rather
        # than recording a version nobody verified.
        gate.ledger.probe("version_probe", "degraded", f"{candidate.path}: {proof}")

    # ------------------------------------------------- uncatalogued, scored
    signals = signals_for(candidate)
    value, fired = score(candidate, signals)
    hint = (
        (Evidence("identifier", Channel.FILESYSTEM, candidate.path,
                  f"name resembles {suspected.id!r}", 0.1, Rung.CONVENTION),)
        if suspected is not None else ()
    )
    return Verdict(
        catalog_id=None, kind=None, name=name, rung=Rung.CONVENTION if hint else None,
        evidence=hint or (
            Evidence("identifier", Channel.FILESYSTEM, candidate.path,
                     "no conclusive evidence", 0.0, None),
        ),
        signals=fired, score=value,
    )


# ------------------------------------------------------------------ rungs


def _by_provenance(gate, candidate: Candidate, catalog):
    """Definitive for anything a package manager installed, which is most
    things -- and it survives a rename, because the package record does."""
    if candidate.source.startswith("package:"):
        manager = candidate.source.split(":", 1)[1]
        pkg_name = str(candidate.detail.get("name", ""))
        entry = catalog.match("packages", f"{manager}:{pkg_name}")
        if entry is not None:
            return entry, (
                Evidence("identifier", Channel.PACKAGE, candidate.path,
                         f"{manager} owns {pkg_name}", 0.95, Rung.PROVENANCE),
            ), candidate.detail.get("version")

    # An OS application registry and an editor/browser extension registry are
    # installed-artifact records, not filename conventions. Their stable IDs
    # are provenance and are sufficient to establish identity.
    if candidate.kind == "application":
        ident = str(candidate.detail.get("ident", ""))
        entry = catalog.match("bundle_ids", ident) or catalog.match("desktop_ids", ident)
        if entry is not None:
            return entry, (
                Evidence("identifier", Channel.REGISTRY, candidate.path,
                         f"application registry id {ident}", 0.9, Rung.PROVENANCE),
            ), candidate.detail.get("version")
    if candidate.kind == "extension":
        ident = str(candidate.detail.get("extension_id", ""))
        entry = catalog.match("extension_ids", ident)
        if entry is not None:
            return entry, (
                Evidence("identifier", Channel.REGISTRY, candidate.path,
                         f"extension registry id {ident}", 0.9, Rung.PROVENANCE),
            ), candidate.detail.get("version")

    # Package ownership is a subprocess on Linux. Running it for every entry
    # in /usr/bin turns one scan into thousands of sequential dpkg queries.
    # Package-registry candidates were already handled above; for filesystem
    # binaries, query ownership only when another channel makes the path
    # relevant. Live processes and journal events remain eligible because
    # execution itself is that independent signal and must survive renames.
    basename = candidate.path.rstrip("/").rsplit("/", 1)[-1]
    ownership_relevant = (
        candidate.kind in ("process", "exec_event")
        or catalog.match("binaries", basename) is not None
    )
    if not ownership_relevant:
        return None, (), None

    owner = gate.package_owner(candidate.path)
    if owner.ok:
        pkg = owner.value
        entry = catalog.match("packages", f"{pkg.manager}:{pkg.name}")
        if entry is not None:
            return entry, (
                Evidence("identifier", Channel.PACKAGE, candidate.path,
                         f"{pkg.manager} -S resolved to {pkg.name}", 0.95, Rung.PROVENANCE),
            ), pkg.version
    return None, (), None


def _by_content(gate, candidate: Candidate, catalog):
    """Survives renaming, catches copies, identifies self-compiled builds."""
    known = catalog.index.get("content_hashes") or {}
    if not known:
        return None, ()
    digest = content_hash(gate, candidate.path)
    if digest is None:
        return None, ()
    entry_id = known.get(digest.lower())
    if entry_id is None:
        return None, ()
    return catalog.by_id[entry_id], (
        Evidence("identifier", Channel.FILESYSTEM, candidate.path,
                 f"sha256 {digest[:12]} is a known build", 0.9, Rung.CONTENT),
    )


def _suspected(catalog, candidate: Candidate, name: str):
    """Convention. Raises priority; concludes nothing."""
    for kind, value in (
        ("binaries", name),
        ("bundle_ids", str(candidate.detail.get("ident", ""))),
        ("desktop_ids", str(candidate.detail.get("ident", ""))),
        ("extension_ids", str(candidate.detail.get("extension_id", ""))),
        ("ports", str(candidate.detail.get("port", ""))),
        ("state_dirs", candidate.path),
        ("state_dirs", _home_relative(candidate.path)),
    ):
        if not value:
            continue
        entry = catalog.match(kind, value)
        if entry is not None:
            return entry
    return None


def _home_relative(path: str) -> str:
    """`~/.claude` in the catalog must match /Users/alice/.claude on disk."""
    for base in ("/Users/", "/home/"):
        if path.startswith(base):
            tail = path[len(base):]
            if "/" in tail:
                return "~/" + tail.split("/", 1)[1]
    return ""


def _conflicting(catalog, candidate: Candidate, name: str, chosen) -> str | None:
    """Another channel naming a different entry."""
    other = _suspected(catalog, candidate, name)
    if other is not None and other.id != chosen.id:
        return f"convention names {other.id!r}, provenance names {chosen.id!r}"
    return None


def _catalogued(gate, entry, candidate: Candidate, rung: Rung, evidence,
                probe: bool, version: object = None, conflict: str | None = None) -> Verdict:
    """Identity is settled; a version may still be worth asking for."""
    version = version or candidate.detail.get("version")
    extra: tuple[Evidence, ...] = ()
    if version is None and probe and entry.version_probe:
        version, proof = check_version(gate, candidate.path, entry.version_probe, entry.version_shape)
        if version is not None:
            extra = (Evidence("identifier", Channel.RUNTIME, candidate.path, proof, 0.8, Rung.BEHAVIOUR),)
    if conflict is not None:
        extra += (Evidence("identifier", Channel.FILESYSTEM, candidate.path,
                           conflict, 0.0, Rung.CONVENTION),)
    return Verdict(
        catalog_id=entry.id, kind=_kind(entry), name=entry.name, vendor=entry.vendor,
        version=str(version) if version else None, rung=rung,
        evidence=tuple(evidence) + extra, conflict=conflict,
    )


def _kind(entry) -> Kind | None:
    try:
        return Kind(entry.kind)
    except ValueError:
        return None


def _is_model_weight(header: bytes, path: str) -> bool:
    if header.startswith(b"GGUF"):
        return True
    if path.endswith(".safetensors") and len(header) >= 9:
        length = int.from_bytes(header[:8], "little")
        return 1 < length < (1 << 30) and header[8:9] == b"{"
    return False
