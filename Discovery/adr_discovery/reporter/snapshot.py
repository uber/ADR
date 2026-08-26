"""Serialization.

A snapshot is emitted even when nothing is found: to fleet coverage, a host
that reported an empty inventory and a host that never reported are very
different facts, and only one of them is evidence.
"""

from __future__ import annotations

import dataclasses
import json
from enum import Enum

from ..contracts.evidence import Band, Channel, Evidence, Rung
from ..contracts.records import Asset, Finding, Kind, Liveness, ReviewItem, Risk
from ..contracts.snapshot import (
    SCHEMA_VERSION,
    BoundaryHit,
    Coverage,
    Denied,
    ProbeRun,
    RootSwept,
    Snapshot,
    Truncated,
    Unavailable,
)


def to_dict(snapshot: Snapshot) -> dict:
    return _encode(snapshot)


def to_json(snapshot: Snapshot, indent: int | None = 2) -> str:
    return json.dumps(to_dict(snapshot), indent=indent, sort_keys=True)


def _encode(value):
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: _encode(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(k): _encode(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_encode(v) for v in value]
    return value


def from_dict(document: dict) -> Snapshot:
    """Rebuild a snapshot from its serialized form.

    Needed because the delta is the product: comparing this scan with the
    last one means reading the last one back, and a snapshot that can only
    be written is a snapshot that can only be filed away.
    """
    return Snapshot(
        hostname=document.get("hostname", "unknown"),
        username=document.get("username", "unknown"),
        platform=document.get("platform", "unknown"),
        timestamp=document.get("timestamp", ""),
        assets=tuple(_asset(a) for a in document.get("assets", ())),
        findings=tuple(_finding(f) for f in document.get("findings", ())),
        review_queue=tuple(
            ReviewItem(path=r.get("path", ""), score=r.get("score", 0.0),
                       signals=tuple(r.get("signals", ())))
            for r in document.get("review_queue", ())
        ),
        coverage=_coverage(document.get("coverage") or {}),
        catalog_version=document.get("catalog_version", "unknown"),
        schema_version=document.get("schema_version", SCHEMA_VERSION),
    )


def _asset(row: dict) -> Asset:
    risk = row.get("risk") or {}
    band = row.get("confidence") or {}
    return Asset(
        asset_id=row["asset_id"],
        kind=Kind(row["kind"]),
        name=row.get("name", ""),
        identity=row.get("identity", ""),
        catalog_id=row.get("catalog_id"),
        vendor=row.get("vendor"),
        version=row.get("version"),
        install_path=row.get("install_path"),
        install_root=row.get("install_root"),
        install_method=row.get("install_method"),
        owner=row.get("owner", "system"),
        location=row.get("location", "local"),
        liveness=Liveness(row.get("liveness", "installed")),
        last_used=row.get("last_used"),
        confidence=Band(band.get("label", "none"),
                        tuple(Channel(c) for c in band.get("channels", ()))),
        verification=tuple(Rung(r) for r in row.get("verification", ())),
        evidence=tuple(
            Evidence(e.get("stage", ""), Channel(e["channel"]), e.get("path", ""),
                     e.get("proof", ""), e.get("confidence", 0.0),
                     Rung(e["rung"]) if e.get("rung") else None)
            for e in row.get("evidence", ())
        ),
        risk=Risk(
            pinned=risk.get("pinned"),
            factors=tuple(risk.get("factors", ())),
            credential_kinds=tuple(risk.get("credential_kinds", ())),
            env_names=tuple(risk.get("env_names", ())),
            transport=risk.get("transport"),
            destinations=tuple(risk.get("destinations", ())),
            unattended=risk.get("unattended", False),
        ),
        sanction=row.get("sanction", "unknown"),
        flags=tuple(row.get("flags", ())),
    )


def _finding(row: dict) -> Finding:
    return Finding(rule=row.get("rule", ""), severity=row.get("severity", "medium"),
                   asset_id=row.get("asset_id", ""), summary=row.get("summary", ""))


def _coverage(row: dict) -> Coverage:
    return Coverage(
        roots_swept=tuple(RootSwept(**r) for r in row.get("roots_swept", ())),
        boundaries_hit=tuple(BoundaryHit(**b) for b in row.get("boundaries_hit", ())),
        denied=tuple(Denied(**d) for d in row.get("denied", ())),
        unavailable=tuple(Unavailable(**u) for u in row.get("unavailable", ())),
        truncated=tuple(Truncated(**t) for t in row.get("truncated", ())),
        probes=tuple(ProbeRun(**p) for p in row.get("probes", ())),
        out_of_scope=tuple(row.get("out_of_scope", ())),
    )


def stats(snapshot: Snapshot) -> dict[str, int]:
    return {
        "asset_count": len(snapshot.assets),
        "finding_count": len(snapshot.findings),
        "review_queue_count": len(snapshot.review_queue),
        "coverage_gaps": (
            len(snapshot.coverage.denied)
            + len(snapshot.coverage.unavailable)
            + len(snapshot.coverage.boundaries_hit)
            + len(snapshot.coverage.truncated)
        ),
    }
