"""Stage 5: the delta, which is the output that actually matters.

Discovery is a repeated function. An asset list is a spreadsheet; the change
between two of them is the security signal.
"""

import hashlib
from typing import Any, Dict, Iterable, List, Tuple

from .schema import DiscoveredAsset, DiscoverySnapshot


def config_fingerprint(asset: DiscoveredAsset) -> str:
    """What a config change means for an asset, reduced to twelve characters."""
    risk = asset.risk or {}
    payload = "|".join([asset.transport or "", str(risk.get("command", "")),
                        str(risk.get("args", "")), str(risk.get("pinned", "")),
                        asset.network.get("endpoint", "")])
    return hashlib.sha256(payload.encode()).hexdigest()[:12]


def diff_snapshots(previous: DiscoverySnapshot, current: DiscoverySnapshot) -> List[Dict[str, Any]]:
    """Deltas between two snapshots of one endpoint.

    Order-stable by construction: ``diff(a, b)`` is the exact inverse of
    ``diff(b, a)``, so a skewed clock cannot change what the delta says.
    """
    before = {asset.asset_id: asset for asset in previous.assets}
    after = {asset.asset_id: asset for asset in current.assets}
    changes: List[Dict[str, Any]] = []

    for asset_id in sorted(set(before) & set(after)):
        old, new = before[asset_id], after[asset_id]
        if (old.version or "") != (new.version or ""):
            changes.append({"change": "version_changed", "asset_id": asset_id, "name": new.name,
                            "from": old.version, "to": new.version})
        if config_fingerprint(old) != config_fingerprint(new):
            entry = {"change": "config_changed", "asset_id": asset_id, "name": new.name}
            if bool(old.risk.get("pinned", True)) != bool(new.risk.get("pinned", True)):
                # A pinned server edited to resolve at run time is a silent risk
                # regression, and the reason config_changed alone is not enough.
                entry["risk_delta"] = {"pinned": [old.risk.get("pinned"), new.risk.get("pinned")]}
            changes.append(entry)

    gone = [before[key] for key in sorted(set(before) - set(after))]
    arrived = [after[key] for key in sorted(set(after) - set(before))]
    changes.extend(_pair_reinstalls(gone, arrived))
    return changes


def _pair_reinstalls(gone: List[DiscoveredAsset], arrived: List[DiscoveredAsset]) -> List[Dict[str, Any]]:
    """A tool reinstalled through another package manager is one event."""
    changes: List[Dict[str, Any]] = []
    matched_old, matched_new = set(), set()
    for old in gone:
        for new in arrived:
            if new.asset_id in matched_new:
                continue
            if (old.identity, old.owner, old.kind) == (new.identity, new.owner, new.kind):
                changes.append({"change": "reinstalled", "asset_id": new.asset_id,
                                "from_asset_id": old.asset_id, "name": new.name,
                                "from_install_method": old.install_method,
                                "to_install_method": new.install_method})
                matched_old.add(old.asset_id)
                matched_new.add(new.asset_id)
                break
    for old in gone:
        if old.asset_id not in matched_old:
            changes.append({"change": "disappeared", "asset_id": old.asset_id, "name": old.name,
                            "kind": old.kind})
    for new in arrived:
        if new.asset_id not in matched_new:
            changes.append({"change": "appeared", "asset_id": new.asset_id, "name": new.name,
                            "kind": new.kind, "risk": new.risk})
    return changes


def fleet_drift(pairs: Iterable[Tuple[str, List[Dict[str, Any]]]],
                min_hosts: int = 10) -> List[Dict[str, Any]]:
    """One fleet-level finding when the same new asset lands on many endpoints.

    Computable only centrally, and the earliest available signal of an AI
    supply-chain event. Reported once, not once per endpoint.
    """
    by_asset: Dict[str, Dict[str, Any]] = {}
    for hostname, changes in pairs:
        for change in changes:
            if change.get("change") != "appeared":
                continue
            record = by_asset.setdefault(change["asset_id"],
                                         {"name": change.get("name"), "hosts": set(),
                                          "risk": change.get("risk") or {}})
            record["hosts"].add(hostname)
    findings = []
    for asset_id, record in sorted(by_asset.items()):
        if len(record["hosts"]) >= min_hosts:
            findings.append({"finding": "fleet_fanout", "asset_id": asset_id,
                             "name": record["name"], "host_count": len(record["hosts"]),
                             "risk": record["risk"],
                             "severity": "high" if record["risk"].get("factors") else "medium"})
    return findings
