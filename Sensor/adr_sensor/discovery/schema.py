"""Normalized output of discovery: evidence, assets, snapshots."""

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

#: Independent evidence channels. Confidence comes from how many *distinct*
#: channels agree, never from how many observations were made: a binary and its
#: symlink are one fact, and multiplying their confidences would manufacture
#: certainty out of a single observation.
CHANNELS = ("filesystem", "package_registry", "code_signature", "config", "runtime", "telemetry")

BAND_THRESHOLDS = ((0.8, "high"), (0.55, "medium"), (0.0, "low"))


@dataclass
class Evidence:
    """Why we believe an asset exists. Never collapsed away."""

    probe: str
    channel: str
    path: str
    matched_on: str
    confidence: float = 0.5

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DiscoveredAsset:
    """One resolved thing on the endpoint."""

    kind: str
    name: str
    identity: str
    owner: str = ""
    vendor: Optional[str] = None
    version: Optional[str] = None
    install_path: Optional[str] = None
    install_root: Optional[str] = None
    install_method: str = "unknown"
    catalog_id: Optional[str] = None
    evidence: List[Evidence] = field(default_factory=list)
    signature: Dict[str, Any] = field(default_factory=dict)
    network: Dict[str, Any] = field(default_factory=dict)
    config_scope: Optional[str] = None
    liveness: str = "installed"
    transport: Optional[str] = None
    parent_agent: Optional[str] = None
    models: List[str] = field(default_factory=list)
    flags: List[str] = field(default_factory=list)
    risk: Dict[str, Any] = field(default_factory=lambda: {"factors": []})
    last_used: Optional[str] = None
    asset_id: str = ""

    @property
    def channels(self) -> List[str]:
        seen = []
        for item in self.evidence:
            if item.channel not in seen and item.channel in CHANNELS:
                seen.append(item.channel)
        return sorted(seen, key=CHANNELS.index)

    @property
    def confidence(self) -> float:
        """Confidence from the count of agreeing independent channels."""
        base = {0: 0.0, 1: 0.45, 2: 0.7}.get(len(self.channels), 0.9)
        if "state_only" in self.flags:
            # A leftover state directory must never resurrect an uninstalled
            # tool at full confidence.
            base = min(base, 0.4)
        return round(base, 2)

    @property
    def confidence_band(self) -> str:
        value = self.confidence
        for floor, name in BAND_THRESHOLDS:
            if value >= floor:
                return name
        return "low"

    def compute_id(self) -> str:
        """Stable identity for diffing and for keying prevention policy.

        Deliberately excludes the version: an upgrade must read as
        ``version_changed``, not as an uninstall followed by a fresh install.
        """
        payload = "|".join([self.kind, self.identity, self.owner, self.install_root or ""])
        self.asset_id = hashlib.sha256(payload.encode()).hexdigest()[:16]
        return self.asset_id

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["evidence"] = [item.to_dict() for item in self.evidence]
        data["channels"] = self.channels
        data["confidence"] = self.confidence
        data["confidence_band"] = self.confidence_band
        return data


@dataclass
class DiscoverySnapshot:
    """One endpoint, one moment.

    Emitted even when nothing is found: to fleet coverage, a host that reported
    an empty inventory and a host that never reported are different facts.
    """

    hostname: str
    username: str
    platform: str
    timestamp: str
    assets: List[DiscoveredAsset] = field(default_factory=list)
    review_queue: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[Dict[str, str]] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hostname": self.hostname,
            "username": self.username,
            "platform": self.platform,
            "timestamp": self.timestamp,
            "assets": [asset.to_dict() for asset in self.assets],
            "review_queue": self.review_queue,
            "findings": self.findings,
            "errors": self.errors,
            "stats": self.stats,
        }

    def to_json(self, indent: Optional[int] = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def by_kind(self, kind: str) -> List[DiscoveredAsset]:
        return [asset for asset in self.assets if asset.kind == kind]
