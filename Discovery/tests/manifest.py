"""The manifest: what we intend to install, and what we expect back.

This module is the only place that reads ``manifests/*.yaml``. Everything
downstream - the runner, the scorer, the report - works on :class:`Entry`
objects, so a change to the file format touches one file.

The three checks at the bottom need no VM. They are static properties of the
manifest and the catalog, so they run per-commit in ordinary CI: the expensive
instrument should never be the thing that discovers a typo.
"""

import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

try:  # Python 3.11+
    import tomllib
except ImportError:  # pragma: no cover - older interpreters
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError as exc:
        raise SystemExit("the e2e harness needs tomllib (Python 3.11+) or tomli") from exc

MANIFEST_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "manifests")

#: The files that make up the manifest, in the order a reader should meet them.
MANIFEST_FILES = ("tools.toml", "mcp.toml", "artifacts.toml", "agents.toml", "negative.toml")

PLATFORMS = ("mac", "linux", "win")

#: Fourteen recipe families cover all 120 entries. Adding a tool that uses an
#: existing family is a manifest edit with no code, which is the property that
#: keeps the inventory cheap to grow.
FAMILIES = frozenset({
    "declare-mcp", "artifact", "app-installer", "service", "npm-global", "channel-variant",
    "vscode-ext", "scheduler", "identity", "baseline-prereq", "runtime-state", "vendor-binary",
    "non-ai-app", "pipx",
})

#: Which report table an entry belongs to. Recall is reported per category
#: because the categories fail for different reasons and pooling them hides
#: which surface regressed.
CATEGORIES = ("cli_agent", "app", "extension", "model_runtime", "channel_variant",
              "mcp_server", "artifact", "agent", "negative_control")

CANARY_REF = re.compile(r"\{\{canary:([a-z0-9_]+)\}\}")

_SUBCATEGORY_TO_CATEGORY = {
    "cli_agent": "cli_agent",
    "app": "app",
    "extension": "extension",
    "model_runtime": "model_runtime",
    "channel_variant": "channel_variant",
    "mcp_site": "mcp_server",
    "mcp_launch": "mcp_server",
    "mcp_special": "mcp_server",
    "skill": "artifact",
    "command": "artifact",
    "style": "artifact",
    "subagent": "artifact",
    "plugin": "artifact",
    "hook": "artifact",
    "instructions": "artifact",
    "runtime_state": "agent",
    "scheduled": "agent",
    "identity": "agent",
    "env_credential": "agent",
    "prerequisite": "negative_control",
    "non_ai_app": "negative_control",
    "lookalike": "negative_control",
    "open_world": "negative_control",
}


class ManifestError(ValueError):
    """A manifest that cannot be trusted to describe a run."""


@dataclass
class Entry:
    """One row of the manifest: a stable id and everything it implies.

    The id is what the runner executes, what ``manifest.actual.json`` records
    an outcome against, and what a scorecard reports a miss under. It is the
    join key for the whole harness, which is why nothing here is allowed to
    exist without one.
    """

    id: str
    name: str
    category: str
    subcategory: str
    platforms: List[str]
    family: str
    catalog_id: Optional[str] = None
    install: Dict[str, Any] = field(default_factory=dict)
    declare: Dict[str, Any] = field(default_factory=dict)
    create: Dict[str, Any] = field(default_factory=dict)
    state: Dict[str, Any] = field(default_factory=dict)
    expect: Dict[str, Any] = field(default_factory=dict)
    canaries: List[str] = field(default_factory=list)
    depends_on: List[str] = field(default_factory=list)
    variant_of: Optional[str] = None
    verify: Optional[str] = None
    privileged: bool = False
    must_not_appear: bool = False
    must_be_reviewed: bool = False
    must_not_be: Optional[str] = None
    explains_error: bool = False
    reason: Optional[str] = None
    detect: Dict[str, Any] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def shape(self) -> str:
        """Which block the entry carries, which is what matching keys off.

        Four shapes cover all 120 rows, and the shape - not the category -
        decides how an entry is matched to an asset.
        """
        if self.declare:
            return "declare"
        if self.create:
            return "create"
        if self.state:
            return "state"
        return "install"

    @property
    def is_negative(self) -> bool:
        return self.category == "negative_control"

    def applies_to(self, platform: str) -> bool:
        """An entry absent from a platform list is never scored as a miss there."""
        return platform in self.platforms

    def path_for(self, platform: str) -> Optional[str]:
        """The path this entry writes on ``platform``, if it writes one.

        Paths are per-OS for most artifacts and a bare string for the rest, so
        callers get one accessor instead of repeating the isinstance dance.
        """
        block = self.create or self.declare
        path = block.get("path")
        if isinstance(path, dict):
            return path.get(platform)
        return path


def load(directory: str = MANIFEST_DIR) -> "Manifest":
    """Read every manifest file into one validated :class:`Manifest`."""
    entries: List[Entry] = []
    for name in MANIFEST_FILES:
        path = os.path.join(directory, name)
        with open(path, "rb") as handle:
            document = tomllib.load(handle)
        if not document or "entries" not in document:
            raise ManifestError("%s declares no entries" % name)
        for row in document["entries"]:
            entries.append(_entry(row, source=name))
    canaries = _load_side_file(directory, "canaries.toml", "canaries")
    sources = _load_side_file(directory, "sources.toml", "sources")
    _resolve_sites(entries)
    manifest = Manifest(entries=entries, canaries=canaries, sources=sources)
    manifest.validate()
    return manifest


def _resolve_sites(entries: List[Entry]) -> None:
    """Give every declaration a path, using the sites that already name one.

    The fourteen M-SITE rows enumerate the declaration sites and where each one
    lives per OS. The pinned and special-case rows reuse those sites by name and
    carry no path of their own, so without this they would be unwritable by the
    runner and unmatchable by the scorer for reasons that have nothing to do
    with the collector.
    """
    known: Dict[str, Dict[str, str]] = {}
    for entry in entries:
        site = entry.declare.get("site")
        path = entry.declare.get("path")
        if site and isinstance(path, dict):
            known.setdefault(str(site), {}).update({k: v for k, v in path.items() if v})

    for entry in entries:
        if not entry.declare or entry.declare.get("path"):
            continue
        names = entry.declare.get("sites") or [entry.declare.get("site")]
        for name in names:
            resolved = known.get(str(name))
            if resolved:
                entry.declare["path"] = dict(resolved)
                break


def _load_side_file(directory: str, name: str, key: str) -> Any:
    with open(os.path.join(directory, name), "rb") as handle:
        return (tomllib.load(handle) or {}).get(key) or {}


def _entry(row: Dict[str, Any], source: str) -> Entry:
    try:
        subcategory = row["subcategory"]
        entry = Entry(
            id=row["id"],
            name=row["name"],
            subcategory=subcategory,
            category=_SUBCATEGORY_TO_CATEGORY[subcategory],
            platforms=list(row["platforms"]),
            family=_family(row),
            catalog_id=row.get("catalog_id"),
            install=dict(row.get("install") or {}),
            declare=dict(row.get("declare") or {}),
            create=dict(row.get("create") or {}),
            state=dict(row.get("state") or {}),
            expect=dict(row.get("expect") or {}),
            canaries=list(row.get("canaries") or []),
            depends_on=list(row.get("depends_on") or []),
            variant_of=row.get("variant_of"),
            verify=row.get("verify"),
            privileged=bool(row.get("privileged")),
            must_not_appear=bool(row.get("must_not_appear")),
            must_be_reviewed=bool(row.get("must_be_reviewed")),
            must_not_be=row.get("must_not_be"),
            explains_error=bool(row.get("explains_error")),
            reason=row.get("reason"),
            detect=dict(row.get("detect") or {}),
            raw=row,
        )
    except KeyError as exc:
        raise ManifestError("%s: entry %r is missing %s" % (source, row.get("id", "?"), exc)) from exc
    return entry


def _family(row: Dict[str, Any]) -> str:
    """Derive the recipe family from the block the entry carries.

    Derived rather than declared so the two can never disagree: a row that says
    ``family: artifact`` while carrying an ``install`` block would be executed
    one way and reported another.
    """
    if row.get("declare"):
        return "declare-mcp"
    if row.get("create"):
        return "artifact"
    if row.get("state"):
        method = row["state"].get("method")
        if method not in FAMILIES:
            raise ManifestError("%s: unknown state method %r" % (row.get("id"), method))
        return method
    method = (row.get("install") or {}).get("method")
    if method not in FAMILIES:
        raise ManifestError("%s: unknown install method %r" % (row.get("id"), method))
    return method


@dataclass
class Manifest:
    """The whole inventory, plus the two side files it references."""

    entries: List[Entry]
    canaries: List[Dict[str, Any]] = field(default_factory=list)
    sources: Dict[str, Any] = field(default_factory=dict)

    def __iter__(self) -> Iterable[Entry]:
        return iter(self.entries)

    def __len__(self) -> int:
        return len(self.entries)

    def by_id(self, entry_id: str) -> Entry:
        for entry in self.entries:
            if entry.id == entry_id:
                return entry
        raise KeyError(entry_id)

    def for_platform(self, platform: str) -> List[Entry]:
        """The applicable set for one OS - the denominator for its recall."""
        if platform not in PLATFORMS:
            raise ManifestError("unknown platform %r" % platform)
        return [entry for entry in self.entries if entry.applies_to(platform)]

    def canary_names(self) -> List[str]:
        return [item["name"] for item in self.canaries]

    # -- validation ----------------------------------------------------

    def validate(self) -> None:
        """The structural rules the format enforces, at load time.

        Load-time rather than run-time because the alternative is discovering a
        broken row twenty minutes into a VM run that then has to start again.
        """
        problems: List[str] = []
        problems.extend(self._check_pins())
        problems.extend(self._check_references())
        if problems:
            raise ManifestError("manifest is invalid:\n  " + "\n  ".join(problems))

    def _check_pins(self) -> List[str]:
        """Every installed package names a version.

        An unpinned install makes the expected ``version`` unscoreable, because
        the right answer becomes whatever the registry served that morning.
        """
        problems = []
        for entry in self.entries:
            if entry.family in ("npm-global", "pipx", "vscode-ext") and not entry.install.get("version"):
                problems.append("%s installs %s unpinned"
                                % (entry.id, entry.install.get("package") or entry.install.get("extension_id")))
        return problems

    def _check_references(self) -> List[str]:
        """``depends_on`` and ``variant_of`` must name rows that exist.

        A variant that names a base the scorer cannot find would be counted as
        a second asset rather than as the duplicate it exists to provoke.
        """
        problems = []
        known = {entry.id for entry in self.entries}
        for entry in self.entries:
            for reference in list(entry.depends_on) + ([entry.variant_of] if entry.variant_of else []):
                if reference not in known:
                    problems.append("%s references unknown entry %s" % (entry.id, reference))
            if entry.variant_of:
                base = next(item for item in self.entries if item.id == entry.variant_of)
                for platform in entry.platforms:
                    if not base.applies_to(platform):
                        problems.append("%s is a %s variant of %s, which does not apply there"
                                        % (entry.id, platform, base.id))
        return problems


def _serialize(value: Any) -> str:
    """Flatten a nested row to text, for substring checks over the whole of it."""
    if isinstance(value, dict):
        return " ".join(_serialize(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return " ".join(_serialize(item) for item in value)
    return str(value)
