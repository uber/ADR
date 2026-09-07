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
class Catalog:
    version: str
    entries: tuple[Entry, ...]
    by_id: dict[str, Entry]
    #: fingerprint kind -> value -> entry id. Built at load, which is where
    #: an ambiguous value is caught.
    index: dict[str, dict[str, str]]

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


def loads(text: str) -> Catalog:
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CatalogError(f"catalog is not valid JSON: {exc}") from exc

    version = str(document.get("version", "unknown"))
    entries: list[Entry] = []
    by_id: dict[str, Entry] = {}
    index: dict[str, dict[str, str]] = {kind: {} for kind in INDEXED_KINDS}

    for raw in document.get("entries", []):
        entry = _entry(raw)
        if entry.id in by_id:
            raise CatalogError(f"duplicate entry id {entry.id!r}")
        by_id[entry.id] = entry
        entries.append(entry)

        for kind in INDEXED_KINDS:
            source = entry.proofs if kind in UNIQUE_PROOFS else entry.fingerprints
            for value in source.get(kind, ()) or ():
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

    return Catalog(version, tuple(entries), by_id, index)


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
