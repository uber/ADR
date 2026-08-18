"""Stage 3: merge observations into assets, and Stage 4: rank them by liveness.

This is where inventories fail, in both directions. A false split counts one
tool four times and destroys operator trust on first read; a false merge
collapses two tools and silently hides one. Real-path resolution prevents the
first, conflicting identity prevents the second.
"""

from typing import Dict, List, Optional

from .base_probe import Observation
from .schema import DiscoveredAsset, Evidence

#: Kind precedence when observations of one asset disagree.
KIND_RANK = ("mcp_server", "model_runtime", "app", "cli_agent", "extension")


class _UnionFind:
    def __init__(self, size: int):
        self.parent = list(range(size))

    def find(self, index: int) -> int:
        while self.parent[index] != index:
            self.parent[index] = self.parent[self.parent[index]]
            index = self.parent[index]
        return index

    def union(self, left: int, right: int) -> None:
        root_left, root_right = self.find(left), self.find(right)
        if root_left != root_right:
            self.parent[root_right] = root_left


def merge_keys(observation: Observation) -> List[str]:
    """Identity keys, strongest first. A missing key is never a match.

    An MCP server has no path to resolve, so its identity is what it launches.
    Everything else resolves through the real path, which is what collapses a
    binary, its symlink and its package metadata into one asset.
    """
    if observation.kind == "mcp_server" and observation.identity_hint:
        return [observation.identity_hint]
    keys = []
    if observation.realpath:
        keys.append("rp:" + observation.realpath)
    if observation.pkg_identity:
        keys.append("pkg:" + observation.pkg_identity)
    team = (observation.signature or {}).get("team_id")
    if team and observation.catalog_id:
        keys.append("sig:%s:%s" % (team, observation.catalog_id))
    return keys


def conflicts(left: Observation, right: Observation) -> bool:
    """Two observations that name different things may never merge.

    Without this, two unrelated CLIs whose shims resolve through one shared
    wrapper collapse into a single asset and one of them disappears from the
    inventory entirely.
    """
    if left.catalog_id and right.catalog_id and left.catalog_id != right.catalog_id:
        return True
    if left.pkg_identity and right.pkg_identity and left.pkg_identity != right.pkg_identity:
        return True
    if left.owner and right.owner and left.owner != right.owner:
        return True
    return False


def resolve(observations: List[Observation],
            telemetry: Optional[Dict[str, str]] = None) -> List[DiscoveredAsset]:
    """Union-find over identity keys, then one asset per group."""
    telemetry = telemetry or {}
    state_dirs = [o for o in observations if (o.identity_hint or "").startswith("state:")]
    primary = [o for o in observations if not (o.identity_hint or "").startswith("state:")]

    union = _UnionFind(len(primary))
    buckets: Dict[str, List[int]] = {}
    for index, observation in enumerate(primary):
        for key in merge_keys(observation):
            buckets.setdefault(key, []).append(index)
    for members in buckets.values():
        anchor = members[0]
        for other in members[1:]:
            if not conflicts(primary[anchor], primary[other]):
                union.union(anchor, other)

    groups: Dict[int, List[Observation]] = {}
    for index, observation in enumerate(primary):
        groups.setdefault(union.find(index), []).append(observation)

    assets = [_build(group) for group in groups.values()]
    _attach_state_dirs(assets, state_dirs)
    for asset in assets:
        _apply_telemetry(asset, telemetry)
        _finalize_liveness(asset)
        asset.compute_id()
    return sorted(assets, key=lambda a: (a.kind, a.name.lower(), a.install_path or ""))


def _build(group: List[Observation]) -> DiscoveredAsset:
    ordered = sorted(group, key=lambda o: (-o.confidence, o.path))
    kind = min((o.kind for o in ordered),
               key=lambda value: KIND_RANK.index(value) if value in KIND_RANK else 99)
    anchor = next((o for o in ordered if o.catalog_id), ordered[0])
    asset = DiscoveredAsset(kind=kind, name=anchor.name, identity=_identity(anchor, ordered),
                            owner=anchor.owner, vendor=anchor.vendor, catalog_id=anchor.catalog_id)
    for observation in ordered:
        asset.evidence.append(Evidence(observation.probe, observation.channel, observation.path,
                                       observation.matched_on, observation.confidence))
        _absorb(asset, observation)
    if not asset.install_path:
        asset.install_path = anchor.path
    asset.signature.setdefault("signed", False)
    if any(o.matched_on.startswith("sha256:") for o in ordered) and "alias" not in asset.flags:
        asset.flags.append("alias")
    return asset


def _absorb(asset: DiscoveredAsset, observation: Observation) -> None:
    """Fold one observation's facts into the asset, first writer wins."""
    extra = observation.extra or {}
    if observation.version and not asset.version:
        asset.version = observation.version
    if observation.install_root and not asset.install_root:
        asset.install_root = observation.install_root
    if observation.install_method != "unknown" and asset.install_method == "unknown":
        asset.install_method = observation.install_method
    if observation.channel in ("filesystem", "package_registry", "config") and not asset.install_path:
        asset.install_path = observation.path
    if (observation.signature or {}).get("signed") or not asset.signature:
        asset.signature = dict(observation.signature or {})
    for flag in extra.get("flags", []):
        if flag not in asset.flags:
            asset.flags.append(flag)
    if extra.get("models"):
        asset.models = sorted(set(asset.models) | set(extra["models"]))
    if extra.get("port"):
        ports = set(asset.network.get("listening_ports", [])) | {extra["port"]}
        asset.network["listening_ports"] = sorted(ports)
    if extra.get("url"):
        asset.network["endpoint"] = extra["url"]
    if extra.get("transport"):
        asset.transport = extra["transport"]
    if extra.get("scope"):
        asset.config_scope = extra["scope"]
    if extra.get("parent_agent"):
        asset.parent_agent = extra["parent_agent"]
    if extra.get("argv") and "argv" not in asset.risk:
        # Flag *names* are kept because they carry the risk signal - permission
        # bypass, unpinned launch, remote target. Their values were dropped in
        # the collector before this point.
        asset.risk["argv"] = extra["argv"]
    if extra.get("command") is not None and "command" not in asset.risk:
        asset.risk["command"] = extra.get("command")
        asset.risk["args"] = extra.get("args")
    if "pinned" in extra:
        # Any declaration that is unpinned makes the asset unpinned: the risky
        # launch is the one that will happen.
        asset.risk["pinned"] = bool(extra["pinned"]) and asset.risk.get("pinned", True)
    for factor in extra.get("risk_factors", []):
        if factor not in asset.risk["factors"]:
            asset.risk["factors"].append(factor)
    if extra.get("env_names"):
        asset.risk["env_names"] = extra["env_names"]
    if extra.get("credential_kinds"):
        asset.risk["credential_kinds"] = extra["credential_kinds"]
    if extra.get("running"):
        asset.liveness = "running"


def _identity(anchor: Observation, group: List[Observation]) -> str:
    if anchor.kind == "mcp_server" and anchor.identity_hint:
        return anchor.identity_hint
    if anchor.catalog_id:
        return anchor.catalog_id
    for observation in group:
        if observation.realpath:
            return "unknown:" + observation.realpath
    return "unknown:" + anchor.path


def _attach_state_dirs(assets: List[DiscoveredAsset], state_dirs: List[Observation]) -> None:
    """Bind a state directory to its install, or let it stand alone, quietly.

    A leftover state directory must not resurrect an uninstalled tool at full
    confidence, so an unbound one becomes its own ``state_only`` asset.
    """
    for observation in state_dirs:
        catalog_id = observation.identity_hint.split(":", 1)[1]
        candidates = [asset for asset in assets
                      if asset.catalog_id == catalog_id and asset.owner == observation.owner
                      and "state_only" not in asset.flags]
        if candidates:
            target = sorted(candidates, key=lambda a: (-len(a.channels), a.install_path or ""))[0]
            target.evidence.append(Evidence(observation.probe, observation.channel,
                                            observation.path, observation.matched_on,
                                            observation.confidence))
            continue
        orphan = DiscoveredAsset(kind=observation.kind, name=observation.name, identity=catalog_id,
                                 owner=observation.owner, vendor=observation.vendor,
                                 catalog_id=catalog_id, install_path=observation.path,
                                 install_root=observation.path, flags=["state_only"])
        orphan.evidence.append(Evidence(observation.probe, observation.channel, observation.path,
                                        observation.matched_on, observation.confidence))
        assets.append(orphan)


def _apply_telemetry(asset: DiscoveredAsset, telemetry: Dict[str, str]) -> None:
    """Usage attribution from Sensor events: free, continuous, and ours alone."""
    stamp = telemetry.get(asset.catalog_id or "") or telemetry.get(asset.identity)
    if not stamp:
        return
    asset.last_used = stamp
    asset.evidence.append(Evidence("sensor", "telemetry", asset.install_path or "",
                                   "session_events", 0.7))


def _finalize_liveness(asset: DiscoveredAsset) -> None:
    if asset.liveness == "running":
        return
    if asset.channels == ["config"]:
        # Declared but never seen running and never used: a cleanup candidate,
        # not a threat.
        asset.liveness = "installed" if asset.last_used else "declared_only"
