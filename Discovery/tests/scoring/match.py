"""Manifest entry to reported asset, by entry shape.

The shape - not the category - decides how a row is matched, because the four
shapes are four different claims. An installed tool claims a catalog identity;
a declared server claims a launch identity; a created file claims a path; a
state claims an asset plus a liveness. Matching each by the wrong key is how a
harness reports confident nonsense.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from adr_discovery.contracts.records import Asset

from ..manifest import Entry

#: Environment references that appear in manifest paths but never in a
#: collector's realpath output.
_HOME_PREFIXES = ("~", "%USERPROFILE%", "$HOME")


@dataclass(frozen=True)
class Match:
    """One entry and every asset that answered to it.

    ``assets`` is a list rather than an optional because the count is the
    finding: zero is a blind spot, one is success, and two or more is the
    duplicate that inflates a fleet inventory.
    """

    entry_id: str
    assets: Tuple[str, ...] = ()
    key: str = ""
    how: str = ""


@dataclass(frozen=True)
class Matching:
    """The full join, in both directions."""

    matches: Tuple[Match, ...] = ()
    unmatched_assets: Tuple[str, ...] = ()

    def for_entry(self, entry_id: str) -> Optional[Match]:
        for match in self.matches:
            if match.entry_id == entry_id:
                return match
        return None


def normalize_path(path: Optional[str], home: str = "/root") -> str:
    """A manifest path and a collector path, made comparable.

    Manifests are written the way a person writes a path; collectors report
    what the filesystem resolved to. Comparing them literally produces false
    negatives that look like collector bugs.
    """
    if not path:
        return ""
    text = path.strip().replace("\\", "/")
    for prefix in _HOME_PREFIXES:
        if text == prefix:
            text = home
            break
        if text.startswith(prefix + "/"):
            text = home.rstrip("/") + "/" + text[len(prefix) + 1:]
            break
    text = posixpath.normpath(text)
    return text.rstrip("/").lower() or "/"


def launch_identity(command: Optional[str], args: Optional[Sequence[str]], home: str = "/root") -> str:
    """A declared server's identity: what would actually be executed.

    Normalized because ``docker run x`` and ``/usr/bin/docker   run  x`` are
    the same server declared by two people, and a scorer that disagrees is
    measuring formatting.
    """
    binary = posixpath.basename(normalize_path(command, home)) if command else ""
    parts = [binary]
    for arg in args or ():
        token = str(arg).strip()
        if not token:
            continue
        if _looks_like_path(token):
            token = normalize_path(token, home)
        parts.append(token.lower())
    return " ".join(p for p in parts if p)


def _looks_like_path(token: str) -> bool:
    return token.startswith(_HOME_PREFIXES) or "/" in token or "\\" in token


def match(entries: Iterable[Entry], assets: Sequence[Asset], *, outcomes: Optional[Mapping[str, Any]] = None,
          platform: str = "linux", home: str = "/root") -> Matching:
    """Join installed entries to reported assets.

    Keys come from what the runner recorded first and the manifest second: the
    manifest is intent, and an entry installed somewhere other than where it
    was declared is still installed.

    Rows that share a key are the normal case, not an edge case - nineteen
    skill rows write into a handful of settings files. Assets at a shared key
    are therefore distributed one per row rather than handed wholesale to
    whichever row sorts first, and only a genuine surplus is reported as a
    duplicate. Without that, DUP would measure how the manifest is written
    rather than what the collector did.
    """
    outcomes = outcomes or {}
    index = _Index(assets, home=home)
    ordered = sorted(entries, key=lambda e: e.id)

    found: Dict[str, Match] = {}
    groups: Dict[str, List[Tuple[Entry, str]]] = {}

    attachments: List[Entry] = []
    for entry in ordered:
        if _attaches_to(entry):
            attachments.append(entry)
            continue
        if entry.variant_of:
            # A second install of a tool already claimed by its base row.
            # Letting it claim too would manufacture the duplicate it detects.
            found[entry.id] = Match(entry.id, (), entry.variant_of, "variant")
            continue
        key, how = _key_for(entry, outcomes.get(entry.id), platform=platform, home=home)
        if not key:
            found[entry.id] = Match(entry.id, (), key, how)
            continue
        groups.setdefault(f"{how}\x00{key}", []).append((entry, how))

    claimed: Dict[str, str] = {}
    for bucket, members in sorted(groups.items()):
        how, key = bucket.split("\x00", 1)
        available = [a for a in index.lookup(key, how) if a not in claimed]
        for position, (entry, entry_how) in enumerate(members):
            if position >= len(available):
                mine: List[str] = []
            elif position == len(members) - 1:
                # The last row absorbs any surplus, so an extra asset at a
                # shared key is reported as a duplicate instead of vanishing.
                mine = available[position:]
            else:
                mine = [available[position]]
            for asset_id in mine:
                claimed[asset_id] = entry.id
            found[entry.id] = Match(entry.id, tuple(mine), key, entry_how)

    for entry in attachments:
        # Resolved after the main pass and deliberately without claiming: the
        # asset belongs to the row that installed the tool, and an assertion
        # about it is not a second sighting of it.
        target = str(_attaches_to(entry)).strip().lower()
        found[entry.id] = Match(entry.id, tuple(index.lookup(target, "catalog_id")), target, "attached")

    matches = tuple(found[entry.id] for entry in ordered)
    leftover = tuple(a.asset_id for a in assets if a.asset_id not in claimed)
    return Matching(matches=matches, unmatched_assets=leftover)


def _attaches_to(entry: Entry) -> Optional[str]:
    """The tool an ``assert_only`` state row makes a claim about, if any."""
    if entry.shape != "state":
        return None
    block = entry.state
    return block.get("tool") if block.get("assert_only") else None


def identity_of(entry: Entry, outcome: Any = None, *, platform: str = "linux",
                home: str = "/root") -> str:
    """What a correct collector would report as this entry's identity.

    Public because the synthesizer needs the same answer: a fixture built from
    a different notion of identity than the scorer uses tests the fixture.
    """
    recorded_id = getattr(outcome, "catalog_id", None)
    recorded_path = getattr(outcome, "path", None)
    shape = entry.shape

    if shape == "install":
        named = recorded_id or entry.catalog_id or entry.install.get("source") or entry.install.get("binary")
        if named:
            return str(named).strip().lower()
        return normalize_path(recorded_path or entry.install.get("path"), home) or entry.id.lower()
    if shape == "declare":
        command = entry.declare.get("command")
        if command:
            return launch_identity(command, entry.declare.get("args"), home)
        # A remote server launches nothing; it is identified by where it points.
        remote = entry.declare.get("url") or entry.declare.get("server_name")
        return str(remote or "").strip().lower()
    if shape == "create":
        return normalize_path(recorded_path or entry.path_for(platform), home)
    return _state_key(entry, home=home)


def _key_for(entry: Entry, outcome: Any, *, platform: str, home: str) -> Tuple[str, str]:
    """The single value this entry is matched on, and the rule that chose it."""
    identity = identity_of(entry, outcome, platform=platform, home=home)
    shape = entry.shape

    if shape == "install":
        if getattr(outcome, "catalog_id", None) or entry.catalog_id:
            return identity, "catalog_id"
        return identity, "install_path" if identity.startswith("/") else "identity"
    if shape == "declare":
        site = normalize_path(getattr(outcome, "path", None) or entry.path_for(platform), home)
        scope = str(entry.declare.get("scope") or "").lower()
        return "|".join(p for p in (identity, site, scope) if p), "launch_identity"
    if shape == "create":
        return identity, "path"
    return identity, "identity" if not identity.startswith("/") else "path"


def _state_key(entry: Entry, *, home: str) -> str:
    """A state attaches to something: the command it runs, or the file it is in."""
    block = entry.state
    command = block.get("command") or block.get("launch")
    if command:
        return launch_identity(_program(command), _arguments(command), home)
    return normalize_path(block.get("path"), home)


def _program(command: str) -> str:
    parts = re.split(r"\s+", str(command).strip())
    return parts[0] if parts else ""


def _arguments(command: str) -> List[str]:
    parts = re.split(r"\s+", str(command).strip())
    return parts[1:]


class _Index:
    """Assets, keyed every way an entry might ask for them."""

    def __init__(self, assets: Sequence[Asset], *, home: str) -> None:
        self.by_catalog: Dict[str, List[str]] = {}
        self.by_path: Dict[str, List[str]] = {}
        self.by_identity: Dict[str, List[str]] = {}
        self.assets = {a.asset_id: a for a in assets}
        for asset in assets:
            if asset.catalog_id:
                self.by_catalog.setdefault(asset.catalog_id, []).append(asset.asset_id)
            for path in {normalize_path(p, home) for p in (asset.install_path, asset.install_root)}:
                if path:
                    self.by_path.setdefault(path, []).append(asset.asset_id)
            identity = (asset.identity or "").strip().lower()
            if identity:
                self.by_identity.setdefault(identity, []).append(asset.asset_id)

    def lookup(self, key: str, how: str) -> List[str]:
        if not key:
            return []
        if how == "catalog_id":
            return list(self.by_catalog.get(key, ()))
        if how in ("install_path", "path"):
            return list(self.by_path.get(key, ()))
        if how == "identity":
            return list(self.by_identity.get(key, ())) or list(self.by_path.get(key, ()))
        identity, _, rest = key.partition("|")
        site = rest.partition("|")[0]
        by_identity = list(self.by_identity.get(identity, ()))
        if site:
            at_site = set(self.by_path.get(site, ()))
            narrowed = [a for a in by_identity if a in at_site]
            if narrowed:
                return narrowed
            if by_identity:
                return by_identity
            # A server the collector identified differently is still the same
            # server if it sits in the config file the manifest declared it in.
            return list(self.by_path.get(site, ()))
        return by_identity


__all__ = ["Match", "Matching", "identity_of", "launch_identity", "match", "normalize_path"]
