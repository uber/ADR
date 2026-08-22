"""The fingerprint catalog, loaded as data.

Shipped as JSON rather than code on purpose. The tool landscape churns weekly,
and a catalog that can only change with a client release leaves discovery
permanently behind the thing it exists to find.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

_DEFAULT_PATH = Path(__file__).with_name("catalog.json")

#: Fields indexed for the exact-match lookups probes make.
INDEXED_FIELDS = ("binaries", "npm_packages", "pypi_packages", "bundle_ids",
                  "registry_names", "desktop_ids", "extension_ids", "sha256")


class Catalog:
    """Known-tool fingerprints with the indexes probes need."""

    def __init__(self, entries: List[Dict[str, Any]], version: str = "unknown",
                 strict: bool = False):
        self.entries = entries
        self.version = version
        #: Fingerprints claimed by more than one entry. Left silent, whichever
        #: entry happened to load last wins every match, so the fleet is
        #: attributed to a tool nobody chose.
        self.duplicates: List[Dict[str, str]] = []
        self._by_id = {entry["id"]: entry for entry in entries}
        self._index: Dict[str, Dict[str, Dict[str, Any]]] = {}
        for field in INDEXED_FIELDS:
            bucket: Dict[str, Dict[str, Any]] = {}
            for entry in entries:
                for value in entry.get(field, []) or []:
                    key = str(value).lower()
                    if key in bucket and bucket[key]["id"] != entry["id"]:
                        self.duplicates.append({"field": field, "value": key,
                                                "entries": "%s,%s" % (bucket[key]["id"],
                                                                      entry["id"])})
                        continue
                    bucket[key] = entry
            self._index[field] = bucket
        if self.duplicates and strict:
            raise ValueError("catalog has ambiguous fingerprints: %s" % self.duplicates)
        self._ports: Dict[int, Dict[str, Any]] = {}
        for entry in entries:
            for port in entry.get("ports", []) or []:
                self._ports[int(port)] = entry

    @classmethod
    def load(cls, path: Optional[Path] = None, strict: bool = False) -> "Catalog":
        data = json.loads(Path(path or _DEFAULT_PATH).read_text())
        return cls(data.get("entries", []), data.get("version", "unknown"), strict=strict)

    def get(self, catalog_id: str) -> Optional[Dict[str, Any]]:
        return self._by_id.get(catalog_id)

    def match(self, field: str, value: Optional[str]) -> Optional[Dict[str, Any]]:
        if not value:
            return None
        return self._index.get(field, {}).get(str(value).lower())

    def match_port(self, port: int) -> Optional[Dict[str, Any]]:
        return self._ports.get(int(port))

    def has_hashes(self) -> bool:
        """Whether hash matching is worth the Tier 2 cost on this fleet."""
        return bool(self._index.get("sha256"))

    def state_dir_names(self) -> List[str]:
        return sorted({d for entry in self.entries for d in entry.get("state_dirs", []) or []})
