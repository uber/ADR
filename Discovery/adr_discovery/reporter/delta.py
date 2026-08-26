"""What the delta says.

    appeared · disappeared · version_changed · config_changed · reinstalled
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
    old_by_identity, new_by_identity = by_identity(before.assets), by_identity(after.assets)
    changes: list[Change] = []

    for asset_id, new in new_by_id.items():
        old = old_by_id.get(asset_id)
        if old is None:
            key = (new.kind.value, new.identity, new.owner)
            previous = old_by_identity.get(key)
            if previous is not None and previous.asset_id not in new_by_id:
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
        if asset_id in new_by_id:
            continue
        key = (old.kind.value, old.identity, old.owner)
        if key in new_by_identity and new_by_identity[key].asset_id not in old_by_id:
            continue  # already reported as a reinstall
        changes.append(Change("disappeared", asset_id, old.name))

    return Delta(after.hostname, tuple(changes), _coverage_delta(before, after))


def _config_of(asset) -> tuple:
    return (asset.install_path, asset.risk.transport, tuple(sorted(asset.risk.env_names)))


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
