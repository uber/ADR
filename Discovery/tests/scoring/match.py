"""Matching reported assets to manifest entries.

The join is by entry *shape*, not by category: an installed tool is matched by
catalog id, a declared server by what it launches, an artifact by its path, and
a state by the asset it attaches to. Getting this wrong in either direction is
expensive - a missed join reads as a miss the collector never made, and a loose
join hides a real one - so every rule here is deliberately narrow and every
fallback is explicit.

Nothing in this module imports a probe. The collector is a black box; the only
things read are its published snapshot and its published diff.
"""

import posixpath
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ..manifest import Entry, Manifest
from .snapshot import Asset, Snapshot

#: What the collector writes in place of a value it refused to keep. Treated as
#: a wildcard when comparing a launch line, because the manifest holds the
#: plaintext the config was written with and the snapshot never will.
REDACTED = "[REDACTED]"

def load_snapshot(source: Any) -> Snapshot:
    """Read a snapshot the collector wrote. See :mod:`.snapshot` for why the
    harness models the format rather than importing it."""
    return Snapshot.load(source)


# -- normalization -----------------------------------------------------


def expand(path: Optional[str], home: Optional[str] = None, platform: str = "linux") -> str:
    """Resolve the spellings a manifest uses for "the user's home".

    The manifest is written in ``~`` and ``%USERPROFILE%`` because that is what
    a reader should see; the machine records absolute paths. Without this the
    two never compare equal, and every artifact entry scores as a miss for a
    reason that has nothing to do with the collector.
    """
    if not path:
        return ""
    text = str(path)
    if home:
        text = text.replace("~", home).replace("%USERPROFILE%", home)
        text = text.replace("%APPDATA%", posixpath.join(home, "AppData/Roaming"))
    return norm_path(text, platform)


def norm_path(path: Optional[str], platform: str = "linux") -> str:
    """One spelling for a path, so two spellings of one file compare equal.

    Windows is case-insensitive and mixes separators, and usr-merge means a
    Linux binary has two true names. Neither is a difference the scorer should
    be able to see.
    """
    if not path:
        return ""
    text = str(path).replace("\\", "/").rstrip("/")
    if platform == "win":
        text = text.lower()
    return text


def norm_command(command: Optional[str]) -> str:
    """A launcher's identity is its name, not where it was found.

    ``C:\\Tools\\npx.exe``, ``/usr/local/bin/npx`` and ``npx`` are one launcher;
    treating them as three would split a duplicate into two clean matches and
    hide exactly the defect these entries exist to provoke.
    """
    if not command:
        return ""
    base = posixpath.basename(str(command).replace("\\", "/")).lower()
    return base[:-4] if base.endswith(".exe") else base


def launch_key(command: Optional[str], args: Optional[Sequence[str]],
               url: Optional[str] = None) -> Tuple[str, Tuple[str, ...], str]:
    """What a declaration launches, reduced to something comparable.

    Redacted tokens become a wildcard rather than a value: the manifest holds
    the plaintext a config was written with, the snapshot holds the collector's
    redaction of it, and requiring those to be equal would mean every entry that
    carries a credential scored as a miss - punishing the collector for doing
    the right thing.
    """
    normalized = []
    for arg in args or []:
        text = str(arg)
        normalized.append("*" if REDACTED in text or "{{canary:" in text else text)
    return norm_command(command), tuple(normalized), (url or "").rstrip("/")


def _asset_launch_key(asset: Asset) -> Tuple[str, Tuple[str, ...], str]:
    risk = asset.risk or {}
    return launch_key(risk.get("command"), risk.get("args"), (asset.network or {}).get("endpoint"))


def _asset_paths(asset: Asset, platform: str) -> List[str]:
    """Every path that could reasonably identify this asset.

    Evidence paths are included because an artifact is discovered *at* a path
    that is not always the path the resolver settles on as ``install_path`` -
    a hook lives in a settings file, not in a file of its own.
    """
    paths = [asset.install_path, asset.install_root]
    paths.extend(item.path for item in asset.evidence)
    return [norm_path(path, platform) for path in paths if path]


# -- matching ----------------------------------------------------------


class Match:
    """One entry's verdict, with the assets that produced it.

    Carries the assets rather than just a count because the aggregate number is
    for tracking and the individual rows are what somebody fixes.
    """

    __slots__ = ("entry", "assets", "outcome", "detail")

    def __init__(self, entry: Entry, assets: List[Asset], outcome: str, detail: str = ""):
        self.entry = entry
        self.assets = assets
        self.outcome = outcome
        self.detail = detail

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.entry.id, "name": self.entry.name, "category": self.entry.category,
                "outcome": self.outcome, "detail": self.detail,
                "assets": [{"asset_id": asset.asset_id, "name": asset.name, "kind": asset.kind,
                            "install_path": asset.install_path, "version": asset.version,
                            "evidence": [item.to_dict() for item in asset.evidence]}
                           for asset in self.assets]}


def match_all(manifest: Manifest, actual: Dict[str, Any],
              assets: Iterable[Asset]) -> Tuple[List[Match], List[Asset]]:
    """Match every scoreable entry, and return whatever no entry claimed.

    Only entries recorded ``installed`` are matched. An entry that a vendor no
    longer ships, or that failed to install, is not in the denominator at all -
    scoring it as a miss would blame the collector for the harness's own
    weather.
    """
    platform = actual.get("os", "linux")
    home = actual.get("home")
    assets = list(assets)
    outcomes: List[Match] = []
    claimed: set = set()
    statuses = {record.get("id"): record.get("status") for record in _records(actual)}

    for entry in manifest.for_platform(platform):
        record = (actual.get("entries") or {}).get(entry.id) if isinstance(actual.get("entries"), dict) \
            else _record_for(actual, entry.id)
        if entry.is_negative:
            found = _match_negative(entry, assets, platform, home)
            outcomes.append(Match(entry, found, "negative"))
            claimed.update(id(asset) for asset in found)
            continue
        if not record or record.get("status") != "installed":
            outcomes.append(Match(entry, [], "excluded",
                                  (record or {}).get("status", "not-attempted")))
            continue
        if entry.variant_of and statuses.get(entry.variant_of) != "installed":
            # A second install of a tool that was never installed once proves
            # nothing about duplication, and scoring it as a miss would blame
            # the collector for the base entry's absence.
            outcomes.append(Match(entry, [], "excluded",
                                  "base %s is %s" % (entry.variant_of,
                                                     statuses.get(entry.variant_of, "absent"))))
            continue
        found = _match_entry(entry, manifest, record, assets, platform, home)
        claimed.update(id(asset) for asset in found)
        outcomes.append(Match(entry, found, "matched" if found else "unmatched"))

    unclaimed = [asset for asset in assets if id(asset) not in claimed]
    return outcomes, unclaimed


def _records(actual: Dict[str, Any]) -> List[Dict[str, Any]]:
    entries = actual.get("entries", [])
    return list(entries.values()) if isinstance(entries, dict) else list(entries)


def _record_for(actual: Dict[str, Any], entry_id: str) -> Optional[Dict[str, Any]]:
    for record in actual.get("entries", []):
        if record.get("id") == entry_id:
            return record
    return None


def _match_entry(entry: Entry, manifest: Manifest, record: Dict[str, Any],
                 assets: List[Asset], platform: str, home: Optional[str] = None) -> List[Asset]:
    shape = entry.shape
    if shape == "install":
        return _match_install(entry, manifest, record, assets, platform)
    if shape == "declare":
        return _match_declare(entry, record, assets, platform, home)
    if shape == "create":
        return _match_create(entry, record, assets, platform, home)
    return _match_state(entry, manifest, record, assets, platform, home)


def _match_install(entry: Entry, manifest: Manifest, record: Dict[str, Any],
                   assets: List[Asset], platform: str) -> List[Asset]:
    """Catalog id where there is one, the real installed path where there is not.

    A channel variant matches through its *base* entry's catalog id on purpose:
    the whole point of those rows is that a second install must not become a
    second asset, so both rows are matched by the same key and judged by how
    many assets come back. A variant that matched nothing would score as a miss
    and hide the duplicate it exists to provoke.
    """
    catalog_id = entry.catalog_id
    if not catalog_id and entry.variant_of:
        catalog_id = manifest.by_id(entry.variant_of).catalog_id
    if catalog_id:
        return [asset for asset in assets if asset.catalog_id == catalog_id]
    target = expand(record.get("path"), None, platform)
    if target:
        return [asset for asset in assets if target in _asset_paths(asset, platform)]
    # A service nothing declared - M-SP-01 - is identified by where it listens.
    port = entry.install.get("port")
    if port:
        return [asset for asset in assets if (asset.network or {}).get("port") == port]
    return []


def _match_declare(entry: Entry, record: Dict[str, Any], assets: List[Asset],
                   platform: str, home: Optional[str] = None) -> List[Asset]:
    """A declared server is what it launches - and, where it must be, where it
    was declared.

    Launch identity alone is not enough for the M-SITE rows: they deliberately
    declare the *same* trivial server in fourteen different config files so that
    a missed site shows as a specific miss rather than as a lower total. Keying
    on the launch line alone would make all fourteen match all fourteen assets
    and report a duplicate on every one of them. So where the entry names the
    file it wrote, the file is part of the key.

    Name is the last fallback, and mostly for remote servers: there is no
    command to compare, and the endpoint may have been redacted along with the
    credential that reaches it.
    """
    declared = entry.declare
    key = launch_key(declared.get("command"), declared.get("args"), declared.get("url"))
    by_launch = [asset for asset in assets
                 if asset.kind == "mcp_server" and _asset_launch_key(asset) == key]
    site = expand(record.get("path") or entry.path_for(platform), home, platform)
    if site and len(by_launch) > 1:
        # Empty is the right answer here, not a fallback. Fourteen sites declare
        # one server; if this site's file produced no asset while others did,
        # that site was missed - and returning the other thirteen would report a
        # duplicate on every row instead of a miss on this one.
        return [asset for asset in by_launch if site in _asset_paths(asset, platform)]
    if by_launch:
        return by_launch
    name = declared.get("server_name")
    return [asset for asset in assets if asset.kind == "mcp_server" and asset.name == name]


def _match_create(entry: Entry, record: Dict[str, Any],
                  assets: List[Asset], platform: str, home: Optional[str] = None) -> List[Asset]:
    """An artifact is the file it is. Matched on the path actually written.

    ``record`` wins over the manifest because the runner expands ``~`` and the
    per-OS variants, and the expansion is what ended up on disk.
    """
    target = expand(record.get("path") or entry.path_for(platform), home, platform)
    if not target:
        return []
    found = [asset for asset in assets if target in _asset_paths(asset, platform)]
    if found or not entry.expect.get("env_name"):
        return found
    # A shell-exported key has no file of its own worth reporting: the signal is
    # the variable name, wherever the collector chose to hang it.
    name = entry.expect["env_name"]
    return [asset for asset in assets if name in (asset.risk or {}).get("env_names", [])]


def _match_state(entry: Entry, manifest: Manifest, record: Dict[str, Any],
                 assets: List[Asset], platform: str, home: Optional[str] = None) -> List[Asset]:
    """A state attaches to an asset; which asset depends on the method.

    A scheduler entry creates an asset of its own. A runtime or identity entry
    does not - it changes a field on an asset some other entry installed - so it
    resolves through ``depends_on`` and is then judged on that field. Sharing an
    asset between two entries is deliberate and is not a duplicate: duplication
    is one *entry* matching two assets, never two entries agreeing on one.
    """
    state = entry.state
    if state.get("method") == "scheduler":
        return _match_scheduler(entry, assets, platform, home)
    if state.get("method") == "runtime-state" and state.get("parent"):
        parent = manifest.by_id(state["parent"])
        base = manifest.by_id(parent.depends_on[0]) if parent.depends_on else None
        wanted = base.catalog_id if base else None
        return [asset for asset in assets if asset.parent_agent and
                (wanted is None or asset.parent_agent == wanted or asset.parent_agent == (base.name if base else ""))]
    base_id = entry.depends_on[0] if entry.depends_on else None
    if not base_id:
        return []
    base = manifest.by_id(base_id)
    if base.catalog_id:
        return [asset for asset in assets if asset.catalog_id == base.catalog_id]
    return []


def _match_scheduler(entry: Entry, assets: List[Asset], platform: str,
                     home: Optional[str] = None) -> List[Asset]:
    """A scheduled agent, discriminated by its backend rather than its command.

    Two schedulers on one OS - cron and a systemd user unit - run the identical
    command on purpose, because the question is whether the collector reads both
    surfaces. Matching on the command alone makes each entry match both assets
    and reports two duplicates where there are none, so the backend is what
    separates them: the unit file where there is one, the probe that found it
    where there is not.
    """
    state = entry.state
    backend = str(state.get("backend") or "").lower()
    unit = expand(state.get("path"), home, platform)
    scheduled = [asset for asset in assets if asset.kind == "scheduled_agent"]

    if unit:
        at_path = [asset for asset in scheduled if unit in _asset_paths(asset, platform)]
        if at_path:
            return at_path
    by_backend = [asset for asset in scheduled
                  if any(backend in (item.matched_on or "").lower() for item in asset.evidence)]
    if by_backend:
        return by_backend
    if state.get("task_name"):
        return [asset for asset in scheduled if asset.name == state["task_name"]]
    command = norm_command((state.get("command") or "").split(" ")[0])
    return [asset for asset in scheduled
            if norm_command((asset.risk or {}).get("command")) == command]


def _match_negative(entry: Entry, assets: List[Asset], platform: str,
                    home: Optional[str] = None) -> List[Asset]:
    """Assets attributable to a negative control.

    Attribution is the whole value: an FP that names the control that provoked
    it is a bug report, and an FP that names nothing is a mystery.
    """
    detect = entry.detect or {}
    names = {str(name).lower() for name in detect.get("names", [])}
    paths = {expand(path, home, platform) for path in detect.get("paths", [])}
    ports = set(detect.get("ports", []))
    found = []
    for asset in assets:
        at_path = bool(paths & set(_asset_paths(asset, platform)))
        # Where a control knows where it lives, the path decides. Name alone
        # attributes by coincidence: an MCP server legitimately called `git` is
        # not the `git` binary N-04 installed, and blaming the control for it
        # would turn a correct report into a fabricated false positive.
        named = (asset.name or "").lower() in names and (not paths or at_path)
        if at_path or named or (ports and (asset.network or {}).get("port") in ports):
            found.append(asset)
    return found
