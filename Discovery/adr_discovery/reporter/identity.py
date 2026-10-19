"""Matching assets across two snapshots.

The delta depends entirely on `asset_id` holding still under change that is
not a change. It must survive a version upgrade, a content-addressed store
rebuild and a credential rotation -- the last of which requires that no
secret material reach the hash, which is why the id is computed inside M5
rather than assembled by its callers.

`reinstalled` is the one case where the id legitimately moves: same
identity and owner, different install root.
"""

from __future__ import annotations

from ..contracts.records import Asset


def by_id(assets: tuple[Asset, ...]) -> dict[str, Asset]:
    return {a.asset_id: a for a in assets}


def by_identity(assets: tuple[Asset, ...]) -> dict[tuple[str, str, str], list[Asset]]:
    """A weaker key, used only to tell a reinstall from a disappearance.

    Several assets can share it (two installs of one tool by one owner), so
    every one is kept, in snapshot order.
    """
    grouped: dict[tuple[str, str, str], list[Asset]] = {}
    for a in assets:
        grouped.setdefault((a.kind.value, a.identity, a.owner), []).append(a)
    return grouped
