"""C1 -- the catalog, as data.

This package imports nothing from the collector, on purpose: the landscape
changes weekly and a client release cannot, so the catalog has to ship on
its own cadence. Coupling it to the pipeline would put that churn rate on
the release train.

Every rule below is enforced *at load*. A catalog defect that first shows up
at match time has already shipped to the fleet.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field


class CatalogError(ValueError):
    """Rejected at load, with the reason. Never a warning."""


@dataclass(frozen=True, slots=True)
class Entry:
    id: str
    name: str
    vendor: str
    kind: str
    fingerprints: dict[str, list] = field(default_factory=dict)
    proofs: dict[str, object] = field(default_factory=dict)
    risk_factors: tuple[str, ...] = ()

    @property
    def version_probe(self) -> tuple[str, ...]:
        return tuple(self.proofs.get("version_probe") or ())

    @property
    def version_shape(self) -> str | None:
        shape = self.proofs.get("version_shape")
        return str(shape) if shape else None

    @property
    def provenance(self) -> tuple[str, ...]:
        return tuple(self.proofs.get("provenance") or ())

    @property
    def content_hashes(self) -> tuple[str, ...]:
        return tuple(self.proofs.get("content_hashes") or ())


@dataclass(frozen=True, slots=True)
class Layout:
    """A directory a vendor's own installer manages.

    A native installer leaves no package record, so its files are proven by
    where the installer put them: `~/.local/share/claude/versions/2.1.0` is
    Claude Code because that directory belongs to its updater. The glob
    sits in the last segment only, so a layout names one directory.
    """

    entry_id: str
    target: str
    parent: str
    pattern: str
    version_from: str | None = None


@dataclass(frozen=True, slots=True)
class Catalog:
    version: str
    entries: tuple[Entry, ...]
    by_id: dict[str, Entry]
    #: fingerprint kind -> value -> entry id. Built at load, which is where
    #: an ambiguous value is caught.
    index: dict[str, dict[str, str]]
    layouts: tuple[Layout, ...] = ()

    def match(self, kind: str, value: str) -> Entry | None:
        entry_id = self.index.get(kind, {}).get(str(value).lower())
        return self.by_id.get(entry_id) if entry_id else None

    def __len__(self) -> int:
        return len(self.entries)


EMPTY = Catalog("empty", (), {}, {})

#: Fingerprint kinds that must be unique across the whole catalog.
UNIQUE_KINDS = (
    "binaries", "packages", "bundle_ids", "registry_names",
    "extension_ids", "desktop_ids", "ports", "model_dirs",
)

#: Proof kinds, indexed the same way and subject to the same ambiguity
#: rule. A hash claimed by two entries is the worst kind of ambiguity --
#: it is the one piece of evidence that is supposed to be conclusive.
UNIQUE_PROOFS = ("content_hashes",)

INDEXED_KINDS = UNIQUE_KINDS + UNIQUE_PROOFS

#: How a layout's version is read from the matched path, if at all.
VERSION_FROM = frozenset({"basename", "parent"})
_GLOB = re.compile(r"[*?\[]")


def loads(text: str) -> Catalog:
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CatalogError(f"catalog is not valid JSON: {exc}") from exc

    version = str(document.get("version", "unknown"))
    entries: list[Entry] = []
    by_id: dict[str, Entry] = {}
    index: dict[str, dict[str, str]] = {kind: {} for kind in INDEXED_KINDS}
    layouts: dict[str, Layout] = {}

    for raw in document.get("entries", []):
        entry = _entry(raw)
        if entry.id in by_id:
            raise CatalogError(f"duplicate entry id {entry.id!r}")
        by_id[entry.id] = entry
        entries.append(entry)

        for kind in INDEXED_KINDS:
            source = entry.proofs if kind in UNIQUE_PROOFS else entry.fingerprints
            values = list(source.get(kind, ()) or ())
            if kind == "packages":
                # `proofs.provenance` entries are "<manager>:<package>" records
                # (e.g. brew:claude): the same identity as a package fingerprint,
                # and held to the same ambiguity rule.
                values += list(entry.provenance)
            for value in values:
                key = str(value).lower()
                owner = index[kind].get(key)
                if owner is not None and owner != entry.id:
                    # Whichever loaded last would otherwise win every match,
                    # and the fleet is attributed to a tool nobody chose.
                    raise CatalogError(
                        f"ambiguous fingerprint {kind}:{value!r} claimed by "
                        f"{owner!r} and {entry.id!r}"
                    )
                index[kind][key] = entry.id

        for layout in _layouts(entry):
            owner = layouts.get(layout.target)
            if owner is not None and owner.entry_id != entry.id:
                raise CatalogError(
                    f"ambiguous install layout {layout.target!r} claimed by "
                    f"{owner.entry_id!r} and {entry.id!r}"
                )
            layouts[layout.target] = layout

    return Catalog(version, tuple(entries), by_id, index, tuple(layouts.values()))


def _layouts(entry: Entry) -> list[Layout]:
    raw = entry.fingerprints.get("install_layouts") or []
    if not isinstance(raw, list):
        raise CatalogError(f"{entry.id}: install_layouts must be a list")
    out: list[Layout] = []
    for item in raw:
        if not isinstance(item, dict) or not isinstance(item.get("target"), str):
            raise CatalogError(f"{entry.id}: install layout needs a string target")
        target = item["target"].rstrip("/")
        if not target.startswith(("~/", "/")):
            raise CatalogError(f"{entry.id}: install layout {target!r} must start with ~/ or /")
        parent, _, pattern = target.rpartition("/")
        if not pattern or _GLOB.search(parent):
            raise CatalogError(
                f"{entry.id}: install layout {target!r} may glob only its last segment"
            )
        version_from = item.get("version_from")
        if version_from is not None and version_from not in VERSION_FROM:
            raise CatalogError(
                f"{entry.id}: install layout version_from must be one of {sorted(VERSION_FROM)}"
            )
        out.append(Layout(entry.id, target, parent, pattern, version_from))
    return out


def _entry(raw: object) -> Entry:
    if not isinstance(raw, dict):
        raise CatalogError(f"entry must be a mapping, got {type(raw).__name__}")
    for required in ("id", "name", "vendor", "kind"):
        if not isinstance(raw.get(required), str) or not raw[required]:
            raise CatalogError(f"entry missing {required!r}: {raw.get('id', '?')}")

    proofs = raw.get("proofs") or {}
    if not isinstance(proofs, dict):
        raise CatalogError(f"{raw['id']}: proofs must be a mapping")

    probe, shape = proofs.get("version_probe"), proofs.get("version_shape")
    if probe and not shape:
        # An unverified probe is how a renamed `sleep` acquired version 9.4.
        raise CatalogError(
            f"{raw['id']}: version_probe without version_shape -- "
            "a probe whose output is not checked is not a proof"
        )
    if shape:
        try:
            re.compile(str(shape))
        except re.error as exc:
            raise CatalogError(f"{raw['id']}: version_shape is not a valid regex: {exc}") from exc

    fingerprints = raw.get("fingerprints") or {}
    if not isinstance(fingerprints, dict):
        raise CatalogError(f"{raw['id']}: fingerprints must be a mapping")

    return Entry(
        id=raw["id"], name=raw["name"], vendor=raw["vendor"], kind=raw["kind"],
        fingerprints=fingerprints, proofs=proofs,
        risk_factors=tuple(raw.get("risk_factors") or ()),
    )
