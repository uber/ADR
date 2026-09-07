"""Build a run directory without a guest.

This is what lets the scoring engine exist before any VM does. It emits the
same four files a real run produces, from the manifest itself, so the scorer
can be developed and regression-tested in milliseconds against a run whose
correct answer is known by construction.

It also injects faults on demand. A scorer that has only ever seen a perfect
run is a scorer nobody has tested: the fault modes below are the ones the
gate exists to catch, and each has a test asserting the score moves.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from adr_discovery.contracts.evidence import Band, Channel, Evidence
from adr_discovery.contracts.records import Asset, Kind, Liveness, ReviewItem
from adr_discovery.contracts.snapshot import Coverage, Denied, Snapshot
from adr_discovery.reporter.snapshot import to_dict

from .. import manifest as manifest_module
from ..manifest import Entry
from ..scoring.match import _attaches_to, identity_of, normalize_path

HOME = "/root"
HOSTNAME = "adr-disco-synthetic"

#: Faults the synthesizer can plant, each mapping to a gate condition.
FAULTS = ("miss", "invent", "duplicate", "leak", "dirty-baseline", "wrong-field")


@dataclass
class Plan:
    """What this synthetic run will contain, before any file is written."""

    platform: str = "linux"
    faults: Tuple[str, ...] = ()
    unavailable: Tuple[str, ...] = ()
    failed: Tuple[str, ...] = ()
    seed: int = 7

    def __post_init__(self) -> None:
        unknown = sorted(set(self.faults) - set(FAULTS))
        if unknown:
            raise ValueError(f"unknown faults {unknown}; known faults are {list(FAULTS)}")


#: The filler alphabet. Deliberately excludes nothing clever - the marker in
#: each declared shape is what makes a value unmistakably ours.
_FILL = "ADRE2E0123456789abcdefghijklmnop"


def canary_values(manifest: manifest_module.Manifest, seed: int = 7) -> Dict[str, str]:
    """Render each declared shape, so redaction meets the format it expects.

    The shapes exist because redaction is partly shape-driven: a value that
    does not look like the vendor's token exercises a different code path from
    the one that would leak in production. Rendering the shape rather than
    inventing a format is what makes the check mean anything.

    Deterministic from the seed so a run is reproducible, and never written to
    git - see ``manifests/canaries.toml``. A fake credential in a repository is
    still a credential to whatever scans it.
    """
    values: Dict[str, str] = {}
    for index, declared in enumerate(manifest.canaries):
        name = declared.get("name")
        if not name:
            continue
        values[name] = _render(str(declared.get("shape") or ""), seed, index, name)
    return values


def _render(shape: str, seed: int, index: int, name: str) -> str:
    """Substitute ``{random:N}`` in a declared shape with reproducible filler."""
    if not shape:
        return f"adr-e2e-canary-{name}-{_filler(seed, index, 32)}"

    def replace(match) -> str:
        return _filler(seed, index, int(match.group(1)))

    return re.sub(r"\{random:(\d+)\}", replace, shape)


def _filler(seed: int, index: int, width: int) -> str:
    start = (seed * 31 + index * 7) % len(_FILL)
    wheel = _FILL[start:] + _FILL[:start]
    return (wheel * (width // len(wheel) + 1))[:width]


def build(directory: str, *, plan: Optional[Plan] = None,
          manifest: Optional[manifest_module.Manifest] = None) -> Dict[str, str]:
    """Write before/after/manifest.actual/canaries into ``directory``."""
    plan = plan or Plan()
    manifest = manifest or manifest_module.load()
    os.makedirs(directory, exist_ok=True)

    entries = manifest.for_platform(plan.platform)
    outcomes = _outcomes(entries, plan)
    installed = [e for e in entries if outcomes[e.id]["status"] == "installed"
                 and not e.must_not_appear]

    canaries = canary_values(manifest, plan.seed)
    assets = _assets(installed, plan, canaries)
    review = _review(manifest, plan)

    before = Snapshot(
        hostname=HOSTNAME, username="root", platform=plan.platform,
        timestamp="2026-08-22T00:00:00Z",
        assets=tuple(_baseline_assets(plan)),
        catalog_version="2026.08.18",
    )
    after = Snapshot(
        hostname=HOSTNAME, username="root", platform=plan.platform,
        timestamp="2026-08-22T00:40:00Z",
        assets=tuple(before.assets) + tuple(assets),
        review_queue=tuple(review),
        coverage=Coverage(denied=(Denied(path=f"{HOME}/broken-link", reason="dangling symlink"),)),
        catalog_version="2026.08.18",
    )

    written = {
        "before.json": json.dumps(to_dict(before), indent=2, sort_keys=True),
        "after.json": json.dumps(to_dict(after), indent=2, sort_keys=True),
        "manifest.actual.json": json.dumps(
            _actual(plan, entries, outcomes), indent=2, sort_keys=True),
        "canaries.json": json.dumps(canaries, indent=2, sort_keys=True),
    }
    for name, body in written.items():
        with open(os.path.join(directory, name), "w", encoding="utf-8") as handle:
            handle.write(body + "\n")
    return written


def _outcomes(entries: Sequence[Entry], plan: Plan) -> Dict[str, Dict[str, Any]]:
    recorded: Dict[str, Dict[str, Any]] = {}
    absent = _absent_bases(entries, plan)
    for entry in entries:
        depends = entry.variant_of or _attaches_to(entry)
        if depends and str(depends).lower() in absent:
            recorded[entry.id] = {"id": entry.id, "status": "unavailable",
                                  "reason": f"depends on {depends}, which was not installed"}
            continue
        if entry.id in plan.unavailable:
            recorded[entry.id] = {"id": entry.id, "status": "unavailable",
                                  "reason": "vendor does not ship this platform"}
        elif entry.id in plan.failed:
            recorded[entry.id] = {"id": entry.id, "status": "failed",
                                  "reason": "install exited non-zero"}
        else:
            recorded[entry.id] = {
                "id": entry.id, "status": "installed",
                "catalog_id": entry.catalog_id,
                "version": entry.install.get("version"),
                "method": entry.install.get("method") or entry.family,
                "path": entry.path_for(plan.platform),
            }
    return recorded


def _absent_bases(entries: Sequence[Entry], plan: Plan) -> set:
    """Tools that will not be installed, by id and by catalog id.

    A channel variant of a tool nobody installed cannot itself be installed,
    and an assertion about it has nothing to assert against. Scoring either as
    a miss would blame the collector for the harness.
    """
    missing = set(plan.unavailable) | set(plan.failed)
    absent = {str(m).lower() for m in missing}
    for entry in entries:
        if entry.id in missing and entry.catalog_id:
            absent.add(entry.catalog_id.lower())
    return absent


def _actual(plan: Plan, entries: Sequence[Entry], outcomes: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    rows = [outcomes[e.id] for e in entries]
    tally = {"installed": 0, "unavailable": 0, "failed": 0}
    for row in rows:
        tally[row["status"]] += 1
    return {
        "run_id": f"synthetic-{plan.platform}",
        "os": plan.platform,
        "image": f"{plan.platform}-golden-synthetic",
        "collector": "0.1.0+synthetic",
        "applicable": len(rows),
        "installed": tally["installed"],
        "unavailable": tally["unavailable"],
        "failed": tally["failed"],
        "entries": rows,
    }


def _assets(entries: Sequence[Entry], plan: Plan, canaries: Dict[str, str]) -> List[Asset]:
    assets: List[Asset] = []
    skip = _first(entries, "miss") if "miss" in plan.faults else None
    twice = _first(entries, "duplicate") if "duplicate" in plan.faults else None

    asserted = _assertions(entries)
    for index, entry in enumerate(entries):
        if _attaches_to(entry):
            # Folded into the asset it describes, below.
            continue
        if entry.variant_of:
            # A second channel for a tool already reported once.
            continue
        if skip is not None and entry.id == skip.id:
            continue
        asset = _asset(entry, plan, index, canaries, extra=asserted.get(entry.catalog_id or "", ()))
        assets.append(asset)
        if twice is not None and entry.id == twice.id:
            assets.append(_asset(entry, plan, index, canaries, suffix="-again"))

    if "invent" in plan.faults:
        assets.append(Asset(
            asset_id="synthetic-invention",
            kind=Kind.CLI_AGENT,
            name="nonexistent-agent",
            identity="nonexistent-agent",
            install_path=f"{HOME}/.local/bin/nonexistent-agent",
            install_method="unknown",
            confidence=Band("low"),
        ))
    return assets


def _assertions(entries: Sequence[Entry]) -> Dict[str, Tuple[str, ...]]:
    """Properties an assert_only row claims about somebody else's asset."""
    claims: Dict[str, List[str]] = {}
    for entry in entries:
        target = _attaches_to(entry)
        if not target:
            continue
        for name, value in sorted(entry.expect.items()):
            if name != "kind":
                claims.setdefault(str(target), []).append(f"{name}={value}")
    return {tool: tuple(flags) for tool, flags in claims.items()}


def _asset(entry: Entry, plan: Plan, index: int, canaries: Dict[str, str],
           suffix: str = "", extra: Sequence[str] = ()) -> Asset:
    expect = dict(entry.expect)
    kind = _kind(expect.get("kind"), entry)
    version = entry.install.get("version")
    if "wrong-field" in plan.faults and version:
        version = "0.0.0-wrong"

    path = normalize_path(entry.path_for(plan.platform), HOME) or None
    identity = _identity(entry, plan.platform)
    flags = tuple(f"{name}={value}" for name, value in sorted(expect.items())
                  if name in ("transport", "config_scope", "pinned", "scope")) + tuple(extra)
    flags += tuple(str(f) for f in expect.get("flags", ()))

    proof = ""
    if "leak" in plan.faults and entry.canaries:
        proof = canaries.get(entry.canaries[0], "")

    return Asset(
        asset_id=f"{entry.id.lower()}{suffix}",
        kind=kind,
        name=entry.name,
        identity=identity,
        catalog_id=entry.catalog_id,
        version=version,
        install_path=path or (f"{HOME}/.local/bin/{entry.id.lower()}"),
        install_root=path,
        install_method=expect.get("install_method") or entry.install.get("method"),
        liveness=_liveness(expect.get("liveness")),
        confidence=Band("high"),
        evidence=(Evidence(stage="M3", channel=Channel.FILESYSTEM,
                           path=path or entry.id, proof=proof or entry.id, confidence=0.9),),
        flags=flags,
    )


def _identity(entry: Entry, platform: str) -> str:
    """Exactly what the scorer will look for, so the fixture tests the scorer."""
    return identity_of(entry, platform=platform, home=HOME) or entry.id.lower()


def _kind(declared: Optional[str], entry: Entry) -> Kind:
    for candidate in (declared, entry.subcategory, entry.category):
        try:
            return Kind(str(candidate))
        except ValueError:
            continue
    return Kind.CLI_AGENT


def _liveness(declared: Optional[str]) -> Liveness:
    try:
        return Liveness(str(declared))
    except ValueError:
        return Liveness.INSTALLED


def _baseline_assets(plan: Plan) -> List[Asset]:
    if "dirty-baseline" not in plan.faults:
        return []
    return [Asset(asset_id="baseline-noise", kind=Kind.CLI_AGENT, name="left-over",
                  identity="left-over", install_path=f"{HOME}/.local/bin/left-over")]


def _review(manifest: manifest_module.Manifest, plan: Plan) -> List[ReviewItem]:
    items: List[ReviewItem] = []
    for entry in manifest:
        if entry.must_be_reviewed:
            items.append(ReviewItem(path=f"{HOME}/bin/{entry.name}", score=0.6,
                                    signals=("in-house wrapper",)))
    return items


def _first(entries: Sequence[Entry], _fault: str) -> Optional[Entry]:
    """A stable victim, so a fault-injected run is reproducible."""
    ordered = sorted(entries, key=lambda e: e.id)
    return ordered[0] if ordered else None


__all__ = ["FAULTS", "HOME", "Plan", "build", "canary_values"]
