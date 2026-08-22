"""A reader's view of the snapshot the collector emitted.

The harness treats the collector as a black box: it never imports the package
under test, not even for the delta. Two reasons, and the second is the one that
matters.

The first is practical - the harness must run from this directory alone, so
that scoring a recorded run needs nothing installed and nothing checked out
beside it.

The second is that a test which imports the thing it measures stops being able
to catch a whole class of defect. If the scorer computed "what arrived" with
the collector's own diff, then a diff that dropped assets would drop them from
the measurement too, and the run would score a clean sheet while quietly
measuring less. Re-deriving the delta here means the two definitions can
disagree - and a disagreement is exactly the finding worth having.

The cost is that this file encodes an expectation about the snapshot format.
That is deliberate: the format is the collector's published contract, and if it
changes silently, a test that fails is the correct outcome.
"""

import json
import os
from typing import Any, Dict, Iterable, List, Optional

#: Every field the scorer reads off an asset. Anything outside this list is
#: carried through untouched in ``raw`` rather than modelled, because the
#: harness has no business having an opinion about fields it does not score.
ASSET_FIELDS = ("kind", "name", "identity", "owner", "vendor", "version", "install_path",
                "install_root", "install_method", "catalog_id", "config_scope", "liveness",
                "location", "transport", "parent_agent", "asset_id")


class Evidence:
    """Why the collector believes an asset exists. Never collapsed away.

    Carried into the scorecard verbatim: an aggregate recall number says a probe
    regressed, and the evidence line says which probe, which channel and which
    path - which is the difference between a metric and a bug report.
    """

    __slots__ = ("probe", "channel", "path", "matched_on", "confidence")

    def __init__(self, payload: Dict[str, Any]):
        self.probe = payload.get("probe", "")
        self.channel = payload.get("channel", "")
        self.path = payload.get("path", "")
        self.matched_on = payload.get("matched_on", "")
        self.confidence = payload.get("confidence", 0.0)

    def to_dict(self) -> Dict[str, Any]:
        return {"probe": self.probe, "channel": self.channel, "path": self.path,
                "matched_on": self.matched_on, "confidence": self.confidence}


class Asset:
    """One reported thing on the endpoint, as the scorer needs to read it."""

    __slots__ = ASSET_FIELDS + ("risk", "network", "signature", "models", "flags",
                                "evidence", "confidence", "confidence_band", "raw")

    def __init__(self, payload: Dict[str, Any]):
        for field in ASSET_FIELDS:
            setattr(self, field, payload.get(field))
        self.risk = payload.get("risk") or {}
        self.network = payload.get("network") or {}
        self.signature = payload.get("signature") or {}
        self.models = payload.get("models") or []
        self.flags = payload.get("flags") or []
        self.evidence = [Evidence(item) for item in payload.get("evidence") or []]
        self.confidence = payload.get("confidence")
        self.confidence_band = payload.get("confidence_band")
        self.raw = payload

    def __repr__(self) -> str:
        return "Asset(%s %s)" % (self.kind, self.name)

    @property
    def pinned(self) -> Optional[bool]:
        return self.risk.get("pinned")

    @property
    def env_names(self) -> List[str]:
        return list(self.risk.get("env_names") or [])

    def summary(self) -> Dict[str, Any]:
        """The compact form a scorecard row shows."""
        return {"asset_id": self.asset_id, "name": self.name, "kind": self.kind,
                "version": self.version, "install_path": self.install_path,
                "install_method": self.install_method, "config_scope": self.config_scope,
                "evidence": [item.to_dict() for item in self.evidence]}


class Snapshot:
    """One endpoint, one moment - read from the JSON the collector wrote."""

    def __init__(self, payload: Dict[str, Any]):
        self.hostname = payload.get("hostname", "")
        self.username = payload.get("username", "")
        self.platform = payload.get("platform", "")
        self.timestamp = payload.get("timestamp", "")
        self.assets = [Asset(item) for item in payload.get("assets") or []]
        self.review_queue = list(payload.get("review_queue") or [])
        self.findings = list(payload.get("findings") or [])
        self.errors = list(payload.get("errors") or [])
        self.stats = dict(payload.get("stats") or {})
        self.raw = payload

    @classmethod
    def load(cls, source: Any) -> "Snapshot":
        if isinstance(source, (str, bytes, os.PathLike)):
            with open(source, encoding="utf-8") as handle:
                return cls(json.load(handle))
        return cls(source)

    def serialized(self) -> str:
        """Every byte the collector would have written out.

        What the canary check searches. Reconstructing it from the parsed model
        would search only the fields this file happens to model, and a
        credential that leaked into a field nobody modelled is exactly the one
        that would be missed - so the original document is what gets searched.
        """
        return json.dumps(self.raw, sort_keys=True, default=str)

    def by_id(self) -> Dict[str, Asset]:
        return {asset.asset_id: asset for asset in self.assets if asset.asset_id}


def added_assets(before: Snapshot, after: Snapshot) -> List[Asset]:
    """The assets installation added.

    Scoring the delta rather than the raw ``after`` snapshot means residual
    baseline noise cancels out instead of being attributed to the manifest. The
    baseline is separately asserted to be near-empty, so anything it reported is
    a false positive with nothing to blame - which fails the run before
    installation ever begins.

    A tool that changed channel between the two scans counts as added: the
    identity is the same but the asset id is not, and dropping it here would
    score a tool that is demonstrably present as a miss.
    """
    if before.hostname and after.hostname and before.hostname != after.hostname:
        # Comparing two machines produces a delta that looks authoritative and
        # means nothing.
        raise ValueError("refusing to diff snapshots from different hosts: %s vs %s"
                         % (before.hostname, after.hostname))
    seen = set(before.by_id())
    return [asset for asset in after.assets if asset.asset_id not in seen]


def duplicate_ids(snapshot: Snapshot) -> List[str]:
    """Asset ids the snapshot repeats.

    A snapshot with a repeated id is malformed - the id is what a fleet store
    keys on - and it would silently halve a delta, so the scorer refuses to
    read one rather than reporting whatever falls out.
    """
    counts: Dict[str, int] = {}
    for asset in snapshot.assets:
        counts[asset.asset_id] = counts.get(asset.asset_id, 0) + 1
    return sorted(key for key, count in counts.items() if count > 1)


def iter_paths(assets: Iterable[Asset]) -> Iterable[str]:
    for asset in assets:
        for path in (asset.install_path, asset.install_root):
            if path:
                yield path
        for item in asset.evidence:
            if item.path:
                yield item.path
