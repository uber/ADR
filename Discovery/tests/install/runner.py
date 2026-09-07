"""Execute the manifest in dependency order, and record reality.

Entries are not independent, so the runner does not follow manifest order.
VS Code must exist before its extensions; an MCP declaration written into an
application's config directory before that application exists creates a path
the collector may treat differently from one the application itself created;
and the three runtime-state entries must still be alive when the second scan
runs, so they go last.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from ..manifest import Entry, Manifest
from ..provision.driver import Driver

#: Families in the order they must run. The comment on each is the reason it
#: cannot simply be sorted by id.
ORDER: Tuple[str, ...] = (
    "baseline-prereq",   # already in the golden image; verified, not installed
    "npm-global",        # binaries on PATH
    "pipx",
    "vendor-binary",
    "app-installer",     # VS Code must exist before its extensions
    "non-ai-app",
    "vscode-ext",        # depends on app-installer
    "service",           # start, wait for a port, pull a model
    "declare-mcp",       # config sites depend on their host app existing
    "artifact",
    "channel-variant",   # second installs, after the first ones
    "scheduler",
    "identity",          # asserted, never scripted
    "runtime-state",     # last: processes must be alive at scan #2
)

INSTALLED, UNAVAILABLE, FAILED = "installed", "unavailable", "failed"

#: A recipe takes a driver and an entry and reports what happened.
Recipe = Callable[[Driver, Entry, str], "Outcome"]


@dataclass(frozen=True)
class Outcome:
    id: str
    status: str
    catalog_id: Optional[str] = None
    version: Optional[str] = None
    path: Optional[str] = None
    method: Optional[str] = None
    reason: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        row = {"id": self.id, "status": self.status}
        for name in ("catalog_id", "version", "path", "method", "reason"):
            value = getattr(self, name)
            if value is not None:
                row[name] = value
        return row


class UnknownFamily(KeyError):
    """A manifest row naming a recipe nobody has written yet."""


def ordered(entries: Sequence[Entry]) -> List[Entry]:
    """Manifest rows in the order they must actually be executed."""
    rank = {family: position for position, family in enumerate(ORDER)}
    unknown = sorted({e.family for e in entries} - set(rank))
    if unknown:
        raise UnknownFamily(f"no execution slot for families {unknown}")
    return sorted(entries, key=lambda e: (rank[e.family], e.id))


def run(driver: Driver, manifest: Manifest, *, platform: str,
        recipes: Optional[Dict[str, Recipe]] = None,
        image: str = "unknown", collector: str = "unknown") -> Dict[str, Any]:
    """Execute every applicable entry and return manifest.actual as a dict."""
    from .recipes import REGISTRY

    recipes = recipes or REGISTRY
    entries = ordered(manifest.for_platform(platform))
    outcomes: List[Outcome] = []

    for entry in entries:
        recipe = recipes.get(entry.family)
        if recipe is None:
            outcomes.append(Outcome(entry.id, UNAVAILABLE,
                                    reason=f"no recipe for family {entry.family!r}"))
            continue
        try:
            outcomes.append(recipe(driver, entry, platform))
        except Exception as failure:  # noqa: BLE001 - a broken recipe is a failed entry, not a dead run
            outcomes.append(Outcome(entry.id, FAILED, reason=f"{type(failure).__name__}: {failure}"))

    return actual(outcomes, platform=platform, image=image, collector=collector)


def actual(outcomes: Sequence[Outcome], *, platform: str, image: str,
           collector: str) -> Dict[str, Any]:
    """The file scoring reads. Intent lives in the manifest; this is reality."""
    tally = {INSTALLED: 0, UNAVAILABLE: 0, FAILED: 0}
    for outcome in outcomes:
        tally[outcome.status] = tally.get(outcome.status, 0) + 1
    return {
        "run_id": f"{platform}-{image}",
        "os": platform,
        "image": image,
        "collector": collector,
        "applicable": len(outcomes),
        "installed": tally[INSTALLED],
        "unavailable": tally[UNAVAILABLE],
        "failed": tally[FAILED],
        "entries": [o.as_dict() for o in outcomes],
    }


def write(document: Dict[str, Any], path: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, sort_keys=True)
        handle.write("\n")


__all__ = ["FAILED", "INSTALLED", "ORDER", "Outcome", "Recipe", "UNAVAILABLE",
           "UnknownFamily", "actual", "ordered", "run", "write"]
