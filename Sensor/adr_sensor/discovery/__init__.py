"""ADR Discovery - inventory of the AI tools and agents present on an endpoint.

This package is Plane A of ADR Discovery: the endpoint collector. Probes
enumerate candidate surfaces, a catalog fingerprints the known ones, an
open-world scorer flags the unknown ones, and a resolver merges every
observation into assets.

Every probe reads the world through an injected
:class:`~adr_sensor.discovery.env.DiscoveryEnv` rather than touching the live
machine, so the whole pipeline can be pointed at a fixture world and graded.
"""

from .diff import diff_snapshots, fleet_drift
from .env import DiscoveryEnv, ProcessInfo, SocketInfo
from .runner import discover
from .schema import DiscoveredAsset, DiscoverySnapshot, Evidence

__all__ = [
    "DiscoveryEnv",
    "ProcessInfo",
    "SocketInfo",
    "discover",
    "DiscoveredAsset",
    "DiscoverySnapshot",
    "Evidence",
    "diff_snapshots",
    "fleet_drift",
]
