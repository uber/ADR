"""M5 -- one real thing becomes exactly one asset.

The count is the product, and both ways of getting it wrong are invisible
from the inside: a false split inflates the inventory, a false merge hides
a tool, and each produces a plausible-looking answer.
"""

from __future__ import annotations

from types import MappingProxyType

from ..contracts.records import Asset, Liveness, Observation, Risk
from .confidence import band_for
from .keys import asset_id, identity_of, normalize_root
from .merge import group

__all__ = ["resolve", "asset_id", "normalize_root"]

#: Strongest liveness wins when observations of one install disagree: a
#: process is proof the thing runs, whatever the config says.
_LIVENESS_RANK = MappingProxyType(
    {Liveness.RUNNING: 2, Liveness.INSTALLED: 1, Liveness.DECLARED_ONLY: 0}
)


def resolve(observations: tuple[Observation, ...], telemetry: dict[str, str] | None = None,
            ledger=None) -> tuple[Asset, ...]:
    """Merge observations into assets, derive confidence, decide liveness."""
    if not observations:
        return ()

    observations = bind_contained(observations)
    groups, refused = group(observations)
    if ledger is not None and refused:
        ledger.probe("resolver", "ran", f"{refused} bridging merge(s) refused")

    assets: list[Asset] = []
    for members in groups:
        rows = [observations[i] for i in members]
        primary = _primary(rows)

        evidence = tuple(e for row in rows for e in row.evidence)
        liveness = max((r.liveness for r in rows), key=_LIVENESS_RANK.__getitem__)
        install_root = next((r.install_root for r in rows if r.install_root), None)
        identity = identity_of(primary)
        owner = next((r.owner for r in rows if r.owner), "system")

        rungs = tuple(sorted({e.rung for e in evidence if e.rung is not None},
                             key=lambda r: r.value))
        last_used = (telemetry or {}).get(primary.catalog_id or identity)

        assets.append(
            Asset(
                asset_id=asset_id(primary.kind.value, identity, owner, install_root),
                kind=primary.kind,
                name=primary.detail.get("name") or identity,
                identity=identity,
                catalog_id=primary.catalog_id,
                vendor=primary.detail.get("vendor"),
                version=next((r.version for r in rows if r.version), None),
                install_path=primary.path,
                install_root=install_root,
                install_method=primary.detail.get("install_method"),
                owner=owner,
                location=primary.detail.get("location", "local"),
                liveness=liveness,
                last_used=last_used,
                confidence=band_for(evidence),
                verification=rungs,
                evidence=evidence,
                risk=_runtime_risk(rows),
                flags=_flags(rows),
            )
        )
    return tuple(assets)


def bind_contained(observations: tuple[Observation, ...]) -> tuple[Observation, ...]:
    """An observation that lives inside another install describes it.

    A package directory and the `bin` symlink pointing into it are one
    install reached two ways. Neither shares a content hash (one is a
    directory), an inode, or a normalized root -- so without this pass they
    are two assets that agree about everything, which is the false split in
    its most ordinary form.

    Containment is only allowed to bind observations whose catalogued
    identities do not disagree; the group rule in `merge` still has the
    final say.
    """
    from dataclasses import replace

    roots = [
        (obs.path.rstrip("/"), obs)
        for obs in observations
        if obs.path and not obs.attribute_of
    ]
    roots.sort(key=lambda pair: len(pair[0]), reverse=True)

    bound: list[Observation] = []
    for obs in observations:
        if obs.attribute_of or not obs.path:
            bound.append(obs)
            continue
        inside = _containing(obs, roots)
        bound.append(replace(obs, attribute_of=inside) if inside else obs)
    return tuple(bound)


def _containing(obs: Observation, roots) -> str | None:
    probes = [p for p in (obs.real_path, obs.path) if p]
    for root, other in roots:
        if other is obs or not root:
            continue
        if obs.catalog_id and other.catalog_id and obs.catalog_id != other.catalog_id:
            continue
        if any(probe.startswith(root + "/") for probe in probes):
            return other.path
    return None


def _primary(rows: list[Observation]) -> Observation:
    """The observation that best describes the install itself.

    An attribute -- a model directory, a state folder -- describes something
    about an install and must never become the row the asset is named from.
    """
    real = [r for r in rows if not r.attribute_of]
    pool = real or rows
    return max(pool, key=lambda r: (bool(r.catalog_id), bool(r.content_hash), bool(r.path)))


def _flags(rows: list[Observation]) -> tuple[str, ...]:
    flags: set[str] = set()
    if all(r.attribute_of for r in rows):
        flags.add("state_only")
    if any(r.detail.get("alias") for r in rows):
        flags.add("alias")
    if len(rows) > 1:
        flags.add(f"merged_{len(rows)}")
    for row in rows:
        flags.update(str(flag) for flag in (row.detail.get("flags") or ()))
        scope = row.detail.get("scope")
        if scope:
            flags.add(f"config_scope={scope}")
    return tuple(sorted(flags))


def _runtime_risk(rows: list[Observation]) -> Risk:
    """Carry derived live-process facts, never raw argv or environment values."""
    env_names = tuple(sorted({
        str(name)
        for row in rows
        for name in (row.detail.get("env_names") or ())
    }))
    return Risk(
        env_names=env_names,
        unattended=any(bool(row.detail.get("unattended")) for row in rows),
    )
