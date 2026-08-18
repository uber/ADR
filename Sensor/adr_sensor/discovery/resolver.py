"""Stage 3: merge observations into assets, and Stage 4: rank them by liveness.

This is where inventories fail, in both directions. A false split counts one
tool four times and destroys operator trust on first read; a false merge
collapses two tools and silently hides one. Real-path resolution prevents the
first, conflicting identity prevents the second.
"""

import hashlib
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


#: Identity fields that may hold at most one distinct value per asset. ``owner``
#: tolerates "system" alongside a person: a user's shim pointing at a
#: machine-wide install is one asset, two people's installs are two.
IDENTITY_FIELDS = ("catalog_id", "pkg_identity", "owner")


def _identity_sets(observation: Observation) -> Dict[str, set]:
    sets: Dict[str, set] = {}
    for field in IDENTITY_FIELDS:
        value = getattr(observation, field, None)
        sets[field] = {value} if value else set()
    return sets


def _merge_identity(left: Dict[str, set], right: Dict[str, set]) -> Optional[Dict[str, set]]:
    """Union two groups' identities, or None when that would name two things."""
    merged: Dict[str, set] = {}
    for field in IDENTITY_FIELDS:
        values = left.get(field, set()) | right.get(field, set())
        if field == "owner":
            values_to_count = {value for value in values if value != "system"}
        else:
            values_to_count = values
        if len(values_to_count) > 1:
            return None
        merged[field] = values
    return merged


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
    if (left.owner and right.owner and left.owner != right.owner
            and "system" not in (left.owner, right.owner)):
        # Two people's installs are two assets. A user's shim pointing at a
        # machine-wide install is still one asset.
        return True
    return False


def resolve(observations: List[Observation],
            telemetry: Optional[Dict[str, str]] = None) -> List[DiscoveredAsset]:
    """Union-find over identity keys, then one asset per group."""
    telemetry = telemetry or {}
    # Attributes of an install rather than installs in their own right: a state
    # directory, a model store, a listening port. They bind to the install they
    # belong to, and only stand alone when there is nothing to bind to.
    attributes = [o for o in observations if (o.identity_hint or "").startswith("attr:")]
    primary = [o for o in observations if not (o.identity_hint or "").startswith("attr:")]

    union = _UnionFind(len(primary))
    buckets: Dict[str, List[int]] = {}
    for index, observation in enumerate(primary):
        for key in merge_keys(observation):
            buckets.setdefault(key, []).append(index)
    # Conflict is a property of the merged group, never of a pair. A bridging
    # observation shares a key with two unrelated tools, and pairwise checks
    # wave it through in both directions; transitivity then unites the tools and
    # one of them disappears from the inventory.
    identity: Dict[int, Dict[str, set]] = {}
    for index, observation in enumerate(primary):
        identity[index] = _identity_sets(observation)
    for members in buckets.values():
        anchor = members[0]
        for other in members[1:]:
            left, right = union.find(anchor), union.find(other)
            if left == right:
                continue
            merged = _merge_identity(identity.get(left, {}), identity.get(right, {}))
            if merged is None:
                continue
            union.union(anchor, other)
            identity[union.find(anchor)] = merged

    groups: Dict[int, List[Observation]] = {}
    for index, observation in enumerate(primary):
        groups.setdefault(union.find(index), []).append(observation)

    assets = [_build(group) for group in groups.values()]
    _attach_attributes(assets, attributes)
    for asset in assets:
        _apply_telemetry(asset, telemetry)
        _finalize_liveness(asset)
        asset.compute_id()
    _ensure_unique_ids(assets)
    return sorted(assets, key=lambda a: (a.kind, a.name.lower(), a.install_path or ""))


def _ensure_unique_ids(assets: List[DiscoveredAsset]) -> None:
    """Guarantee one id per asset before anything downstream indexes by it.

    Two assets sharing an id are indistinguishable to every consumer: a diff
    keyed on it silently keeps whichever came last, so one of them stops
    existing without anything reporting a loss.
    """
    seen: Dict[str, DiscoveredAsset] = {}
    for asset in assets:
        if asset.asset_id not in seen:
            seen[asset.asset_id] = asset
            continue
        discriminator = hashlib.sha256(
            ("%s|%s" % (asset.install_path or "", len(seen))).encode()).hexdigest()[:6]
        asset.asset_id = "%s-%s" % (asset.asset_id[:9], discriminator)
        if "ambiguous_identity" not in asset.flags:
            asset.flags.append("ambiguous_identity")
        seen[asset.asset_id] = asset


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


#: Observation metadata carried onto the asset as-is. These are descriptive
#: facts a probe learned - a hook's event, a skill's description, an
#: instruction file's format - rather than fields the resolver reasons about.
PASSTHROUGH_KEYS = (
    "scope", "host_app", "plugin", "description", "line_count", "helpers", "network_hosts",
    "event", "matcher", "handler", "target", "destination", "server", "format", "imports",
    "globs", "author", "source", "tools", "model", "event_known", "bundle", "project",
    "host", "extension_id", "schedule", "trigger", "repository", "image", "account_type",
    "auth_method", "session_count", "worktrees", "repositories", "mode", "mounts",
    "secrets", "session", "sessions", "enabled_by",
)

#: Version sources, most authoritative first. A self-updating CLI leaves stale
#: package metadata behind, so what the binary reports wins.
VERSION_PRECEDENCE = ("runtime", "plist", "registry", "package", "unknown")


def _absorb(asset: DiscoveredAsset, observation: Observation) -> None:
    """Fold one observation's facts into the asset, first writer wins."""
    extra = observation.extra or {}
    if observation.version:
        _absorb_version(asset, observation.version, extra.get("version_source", "unknown"))
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
    if extra.get("bytes"):
        asset.risk["bytes"] = extra["bytes"]
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
        asset.parent_agent = asset.parent_agent or extra["parent_agent"]
        parents = set(asset.risk.get("parent_agents", [])) | {extra["parent_agent"]}
        asset.risk["parent_agents"] = sorted(parents)
    if extra.get("enabled") is not None:
        # A server enabled anywhere it is declared is live. Disabled in one
        # place and enabled in another is enabled. An unknown approval state is
        # left unknown rather than promoted to either answer.
        asset.risk["enabled"] = bool(asset.risk.get("enabled")) or bool(extra["enabled"])
    if extra.get("stored_credential"):
        asset.risk["stored_credential"] = True
    if extra.get("source"):
        asset.risk["source"] = extra["source"]
    if extra.get("location") and not asset.location:
        asset.location = extra["location"]
    if extra.get("ai_enabled") is not None:
        asset.risk["ai_enabled"] = extra["ai_enabled"]
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
    for key in PASSTHROUGH_KEYS:
        if key in extra and extra[key] is not None and key not in asset.risk:
            asset.risk[key] = extra[key]


def _absorb_version(asset: DiscoveredAsset, version: str, source: str) -> None:
    """Take the most authoritative version, and say so when sources disagree."""
    rank = VERSION_PRECEDENCE.index(source) if source in VERSION_PRECEDENCE else 99
    current = asset.risk.get("version_rank", 99)
    if asset.version and asset.version != version and "version_conflict" not in asset.flags:
        asset.flags.append("version_conflict")
    if asset.version is None or rank < current:
        asset.version = version
        asset.risk["version_rank"] = rank


def _identity(anchor: Observation, group: List[Observation]) -> str:
    if anchor.kind == "mcp_server" and anchor.identity_hint:
        return anchor.identity_hint
    if anchor.catalog_id:
        return anchor.catalog_id
    for observation in group:
        if observation.realpath:
            return "unknown:" + observation.realpath
    return "unknown:" + anchor.path


def _attach_attributes(assets: List[DiscoveredAsset], attributes: List[Observation]) -> None:
    """Bind an attribute observation to its install, or let it stand alone.

    A leftover state directory must not resurrect an uninstalled tool at full
    confidence, so an unbound one becomes its own ``state_only`` asset. A model
    store or a listening port with no install behind it is reported the same way
    - present, but not pretending to be a full install record.
    """
    orphans: Dict[tuple, DiscoveredAsset] = {}
    for observation in attributes:
        catalog_id = observation.identity_hint.split(":", 1)[1]
        # Prefer an install owned by the same user; fall back to a system-wide
        # one, since a machine-wide app with per-user state is the normal shape.
        candidates = [asset for asset in assets
                      if asset.catalog_id == catalog_id and "state_only" not in asset.flags
                      and asset.owner in (observation.owner, "system", "")]
        if candidates:
            target = sorted(candidates,
                            key=lambda a: (a.owner != observation.owner, -len(a.channels),
                                           a.install_path or ""))[0]
            target.evidence.append(Evidence(observation.probe, observation.channel,
                                            observation.path, observation.matched_on,
                                            observation.confidence))
            _absorb(target, observation)
            continue
        existing = orphans.get((catalog_id, observation.owner))
        if existing is not None:
            # Several attributes of one absent install - a state directory and a
            # model store, say - are one record, not one record each.
            existing.evidence.append(Evidence(observation.probe, observation.channel,
                                              observation.path, observation.matched_on,
                                              observation.confidence))
            _absorb(existing, observation)
            continue
        orphan = DiscoveredAsset(kind=observation.kind, name=observation.name, identity=catalog_id,
                                 owner=observation.owner, vendor=observation.vendor,
                                 catalog_id=catalog_id, install_path=observation.path,
                                 install_root=observation.path)
        if observation.matched_on == "state_dir":
            orphan.flags.append("state_only")
        orphan.evidence.append(Evidence(observation.probe, observation.channel, observation.path,
                                        observation.matched_on, observation.confidence))
        _absorb(orphan, observation)
        orphans[(catalog_id, observation.owner)] = orphan
        assets.append(orphan)


def _apply_telemetry(asset: DiscoveredAsset, telemetry: Dict[str, str]) -> None:
    """Usage attribution from Sensor events: free, continuous, and ours alone."""
    stamp = telemetry.get(asset.catalog_id or "") or telemetry.get(asset.identity)
    if not stamp:
        return
    asset.last_used = stamp
    asset.evidence.append(Evidence("sensor", "telemetry", asset.install_path or "",
                                   "session_events", 0.7))


#: Kinds that describe something arranged to run rather than something running.
DECLARATIVE_KINDS = ("agent_definition", "scheduled_agent", "ci_agent", "cloud_agent",
                     "skill", "command", "hook", "output_style", "rules", "instructions",
                     "plugin")


def _finalize_liveness(asset: DiscoveredAsset) -> None:
    if asset.liveness == "running":
        return
    if asset.kind in DECLARATIVE_KINDS:
        # A definition is not an installation. It is arranged to run, and until
        # telemetry or a process says otherwise that is all we know.
        asset.liveness = "declared_only"
        return
    if "state_only" in asset.flags:
        # A leftover state directory is residue. Calling it installed invites
        # somebody to go looking for a binary that is not there.
        asset.liveness = "declared_only"
        return
    if asset.channels == ["config"]:
        # Declared but never seen running and never used: a cleanup candidate,
        # not a threat.
        asset.liveness = "installed" if asset.last_used else "declared_only"
