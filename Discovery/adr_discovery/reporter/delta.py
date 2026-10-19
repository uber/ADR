"""What the delta says.

    appeared · disappeared · version_changed · config_changed · reinstalled
  + content_changed  same asset, different bytes: a version string is
                     whatever the publisher wrote, a hash is not
  + risk_delta       pinned -> floating is a silent regression otherwise
  + coverage_delta   a surface that became unreadable is a change too

Fleet fan-out -- the same new asset landing on many endpoints at once -- is
computable only centrally and is deliberately absent from this module.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..contracts.snapshot import Snapshot
from .identity import by_id, by_identity


class DifferentEndpoints(ValueError):
    """A diff compares one endpoint with itself unless told otherwise.

    Diffing two machines produces a fictional delta in which every asset on
    each looks like a change, and nothing in the output says so.
    """


@dataclass(frozen=True, slots=True)
class Change:
    kind: str
    asset_id: str
    name: str
    detail: str = ""


@dataclass(frozen=True, slots=True)
class Delta:
    endpoint: str
    changes: tuple[Change, ...] = ()
    coverage_delta: tuple[str, ...] = ()

    def of(self, kind: str) -> tuple[Change, ...]:
        return tuple(c for c in self.changes if c.kind == kind)

    @property
    def is_empty(self) -> bool:
        return not self.changes and not self.coverage_delta


def diff(before: Snapshot, after: Snapshot, allow_cross_endpoint: bool = False) -> Delta:
    if before.hostname != after.hostname and not allow_cross_endpoint:
        raise DifferentEndpoints(
            f"refusing to diff {before.hostname!r} against {after.hostname!r}; "
            "pass allow_cross_endpoint=True if that is genuinely what you want"
        )

    old_by_id, new_by_id = by_id(before.assets), by_id(after.assets)
    # Old assets whose id is gone, by identity: each may pair with at most
    # one new asset as a reinstall, and is a disappearance otherwise.
    vanished = by_identity(tuple(a for a in before.assets if a.asset_id not in new_by_id))
    reinstalled: set[str] = set()
    changes: list[Change] = []

    for asset_id, new in new_by_id.items():
        old = old_by_id.get(asset_id)
        if old is None:
            key = (new.kind.value, new.identity, new.owner)
            unpaired = [a for a in vanished.get(key, ()) if a.asset_id not in reinstalled]
            if unpaired:
                previous = unpaired[0]
                reinstalled.add(previous.asset_id)
                changes.append(
                    Change("reinstalled", new.asset_id, new.name,
                           f"{previous.install_root} -> {new.install_root}")
                )
            else:
                changes.append(Change("appeared", new.asset_id, new.name))
            continue

        if old.version != new.version:
            changes.append(
                Change("version_changed", asset_id, new.name, f"{old.version} -> {new.version}")
            )
        if _config_of(old) != _config_of(new):
            changes.append(Change("config_changed", asset_id, new.name))
        moved = _content_moved(old, new)
        if moved:
            changes.append(Change("content_changed", asset_id, new.name, moved))
        # An asset set that did not move can still carry a regression.
        if old.risk.pinned is True and new.risk.pinned is False:
            changes.append(
                Change("risk_delta", asset_id, new.name, "pinned -> floating")
            )
        elif set(new.risk.factors) - set(old.risk.factors):
            changes.append(
                Change("risk_delta", asset_id, new.name,
                       "+" + ",".join(sorted(set(new.risk.factors) - set(old.risk.factors))))
            )

    for asset_id, old in old_by_id.items():
        if asset_id in new_by_id or asset_id in reinstalled:
            continue  # still present, or already reported as a reinstall
        changes.append(Change("disappeared", asset_id, old.name))

    return Delta(after.hostname, tuple(changes), _coverage_delta(before, after))


def _config_of(asset) -> tuple:
    return (asset.install_path, asset.risk.transport, tuple(sorted(asset.risk.env_names)))


def _content_moved(old, new) -> str:
    """Which content hashes differ, as ``field old -> new`` (12-hex prefixes)."""
    moved = []
    for field in ("skill_sha256", "content_hash"):
        before, after = getattr(old, field), getattr(new, field)
        if before != after:
            moved.append(f"{field} {_short(before)} -> {_short(after)}")
    return "; ".join(moved)


def _short(digest: str | None) -> str:
    return digest[:12] if digest else "none"


def _coverage_delta(before: Snapshot, after: Snapshot) -> tuple[str, ...]:
    """A surface that became unreadable is a change, and a silent one."""
    out: list[str] = []
    old_denied = {d.path for d in before.coverage.denied}
    new_denied = {d.path for d in after.coverage.denied}
    for path in sorted(new_denied - old_denied):
        out.append(f"became unreadable: {path}")
    for path in sorted(old_denied - new_denied):
        out.append(f"became readable: {path}")

    old_gone = {u.provider for u in before.coverage.unavailable}
    new_gone = {u.provider for u in after.coverage.unavailable}
    for provider in sorted(new_gone - old_gone):
        out.append(f"provider became unavailable: {provider}")
    return tuple(out)
