"""Common probe machinery: observations, the deny-list, and never raising."""

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .env import DiscoveryEnv
from .redact import is_denied, sanitize


@dataclass
class Observation:
    """One probe's sighting of one thing.

    Probes never decide what exists; they report sightings with a channel and a
    confidence. All merging happens in the resolver, so false-split and
    false-merge have exactly one owner.
    """

    probe: str
    channel: str
    kind: str
    name: str
    path: str
    matched_on: str
    catalog_id: Optional[str] = None
    version: Optional[str] = None
    vendor: Optional[str] = None
    realpath: Optional[str] = None
    install_root: Optional[str] = None
    install_method: str = "unknown"
    pkg_identity: Optional[str] = None
    signature: Dict[str, Any] = field(default_factory=dict)
    owner: str = ""
    identity_hint: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.5


class BaseProbe:
    """Base class for every probe.

    Two guarantees hold for all subclasses: a probe returns partial results plus
    an error record rather than raising, and it never emits a path that falls in
    the personal-content deny-list.
    """

    name = "base"
    platforms = ("darwin", "windows", "linux")

    def __init__(self, catalog=None):
        from .catalog import Catalog

        self.catalog = catalog or Catalog.load()

    def supports(self, env: DiscoveryEnv) -> bool:
        return env.platform in self.platforms

    def run(self, env: DiscoveryEnv) -> List[Observation]:
        """Collect observations, converting any failure into an error record."""
        try:
            found = list(self.collect(env))
        except Exception as exc:  # a probe must never take the scan down
            env.errors.append({"probe": self.name, "stage": "collect",
                               "error_type": exc.__class__.__name__, "message": str(exc)})
            return []
        return [item for item in found if not is_denied(item.path)]

    def collect(self, env: DiscoveryEnv) -> List[Observation]:
        raise NotImplementedError

    # -- helpers shared by probes ----------------------------------------

    def error(self, env: DiscoveryEnv, path: str, message: str) -> None:
        env.errors.append({"probe": self.name, "path": sanitize(path), "message": sanitize(message)})

    def read_json(self, env: DiscoveryEnv, logical: str) -> Optional[Any]:
        """Bounded read plus tolerant parse. Malformed input is one error record.

        One unreadable config must never cost the rest of the scan, because a
        probe that silently returns nothing is indistinguishable from a machine
        on which the tool is simply not installed.
        """
        result = env.read(logical)
        if not result:
            self.error(env, logical, result.error or "unreadable")
            return None
        if result.truncated:
            self.error(env, logical, "truncated at read ceiling")
        try:
            return json.loads(result.text)
        except ValueError as exc:
            self.error(env, logical, "malformed json: %s" % exc)
            return None
