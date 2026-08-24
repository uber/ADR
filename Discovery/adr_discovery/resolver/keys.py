"""Merge keys, strongest first.

    content hash          same bytes, wherever they sit
  > real path / inode     same file, reached by any number of links
  > package identity      same package record
  > signature identity    same publisher and product
  > catalog + owner + normalized install root

The first line is the addition. Ollama was counted twice because the
model-directory observation had no path to merge on and the binary
observation did -- two rows, one identity, disagreeing about version and
liveness. An observation that describes an *attribute* of an install binds
to the install rather than standing alone.
"""

from __future__ import annotations

import hashlib
import re

from ..contracts.records import Observation

#: Content-addressed store paths carry a build hash that changes on every
#: rebuild without the install changing. Normalizing it is what lets
#: `asset_id` survive a store rebuild (U5-11).
_STORE_PATTERNS = (
    re.compile(r"^(/nix/store)/[a-z0-9]{32}-(.+?)(/.*)?$"),
    re.compile(r"^(/gnu/store)/[a-z0-9]{32}-(.+?)(/.*)?$"),
    re.compile(r"^(.*/\.pnpm)/[^/]+@[^/]+(/.*)?$"),
)


def normalize_root(path: str | None) -> str | None:
    if not path:
        return path
    for pattern in _STORE_PATTERNS:
        m = pattern.match(path)
        if m:
            return f"{m.group(1)}/*-{m.group(2)}"
    return path


def keys_for(obs: Observation) -> tuple[tuple[str, str], ...]:
    """Every key this observation can be merged on, strongest first."""
    out: list[tuple[str, str]] = []
    if obs.content_hash:
        out.append(("content", obs.content_hash))
    if obs.real_path:
        out.append(("realpath", obs.real_path))
    if obs.inode:
        out.append(("inode", obs.inode))
    if obs.package_id:
        out.append(("package", obs.package_id))
    if obs.signature_id:
        out.append(("signature", obs.signature_id))
    if obs.catalog_id:
        root = normalize_root(obs.install_root) or ""
        out.append(("catalog", f"{obs.catalog_id}|{obs.owner or 'system'}|{root}"))
    else:
        # Uncatalogued things still have an identity. Without this key a
        # server declared in two scopes becomes two assets -- a false split
        # that looks exactly like two servers.
        out.append(("identity", f"{obs.kind.value}|{obs.identity}|{obs.owner or 'system'}"))
    # An attribute binds to *its* install and never stands alone, so both
    # sides of the binding have to emit the same key. Keying on the
    # parent's path rather than its identity is what keeps two installs of
    # one tool -- a release and a vendored alpha -- from collapsing into one.
    if obs.attribute_of:
        out.append(("install", obs.attribute_of))
    elif obs.path:
        out.append(("install", obs.path))
    return tuple(out)


def identity_of(obs: Observation) -> str:
    """What must stay singular within a merged group.

    Two observations that name different tools may never merge, however
    many weak keys they happen to share.
    """
    return obs.catalog_id or obs.identity


def asset_id(kind: str, identity: str, owner: str, install_root: str | None) -> str:
    """Stable across benign change.

    Deliberately excludes the version (an upgrade is not a new asset), any
    credential material (a rotation is not a new asset), and the build hash
    inside a content-addressed store path (a rebuild is not a new asset).
    """
    root = normalize_root(install_root) or ""
    payload = f"{kind}\0{identity}\0{owner}\0{root}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]
