"""The composition root.

The only file in the package that imports more than one stage, which is
what keeps execution order an explicit statement here rather than an
emergent property of the import graph.

    M2 enumerate -> M3 extract -> M4 identify -> M5 resolve -> M6 judge -> M7 report

Every stage takes its input type and returns its output type. Coverage
travels beside the data the whole way and is frozen once, at the end.
"""

from __future__ import annotations

from .catalog.load import EMPTY as EMPTY_CATALOG
from .catalog.load import Catalog
from .contracts.evidence import Channel, Evidence
from .contracts.records import (
    Asset,
    Candidate,
    Declaration,
    Kind,
    Liveness,
    Observation,
    ReviewItem,
)
from .contracts.snapshot import Snapshot
from .enumerator import enumerate_candidates
from .extractor import extract
from .extractor.surfaces import surface_for
from .identifier import content_hash, identify, is_reviewable, score, signals_for
from .judge import EMPTY as EMPTY_POLICY
from .judge import Policy, judge
from .resolver import resolve
from .world.gate import Gate

CATALOG_RESOURCE = "catalog/catalog.json"

#: Candidate kinds that describe a *surface to read* rather than a thing.
#: A marker directory may be one too -- skills/, commands/, agents/ and
#: friends are records in directory form.
CONFIG_KINDS = frozenset({"marker_file", "marker_dir", "instruction_file", "shell_profile"})
#: Candidate kinds that never become an asset (§1).
LOCATOR_KINDS = frozenset({"locator"})


def discover(
    gate: Gate,
    catalog: Catalog | None = None,
    policy: Policy = EMPTY_POLICY,
    telemetry: dict[str, str] | None = None,
    hostname: str = "unknown",
    username: str = "unknown",
    platform_name: str = "unknown",
    timestamp: str = "",
) -> Snapshot:
    """One scan, one snapshot. Emitted even when nothing is found."""
    catalog = catalog if catalog is not None else EMPTY_CATALOG
    ledger = gate.ledger

    # -- M2 ------------------------------------------------------------
    candidates = enumerate_candidates(gate)

    # -- M3 ------------------------------------------------------------
    declarations: list[tuple[Candidate, Declaration]] = []
    for candidate in candidates:
        if candidate.kind not in CONFIG_KINDS:
            continue
        if candidate.kind == "marker_dir" and surface_for(candidate.path) is None:
            continue  # a repository marker locates work; it declares nothing
        extraction = extract(gate, candidate)
        for error in extraction.errors:
            ledger.probe("extractor", "degraded", f"{error.path}: {error.reason}")
        if extraction.declared and len(extraction.declarations) < extraction.declared:
            ledger.probe(
                "extractor", "degraded",
                f"{candidate.path}: {len(extraction.declarations)} of {extraction.declared} records read",
            )
        for declaration in extraction.declarations:
            declarations.append((candidate, declaration))

    # -- M4 ------------------------------------------------------------
    observations: list[Observation] = []
    review: list[ReviewItem] = []

    for candidate in candidates:
        if candidate.kind in CONFIG_KINDS | LOCATOR_KINDS:
            continue
        verdict = identify(gate, candidate, catalog)
        if verdict.is_concluded and verdict.kind is not None:
            observations.append(_observation_from(gate, candidate, verdict))
            continue
        value, fired = score(candidate, signals_for(candidate))
        # Network intent is uniquely strong operational evidence even though
        # its generic open-world score remains below the multi-signal cutoff.
        if is_reviewable(value) or "network_intent" in fired:
            review.append(
                ReviewItem(path=candidate.path, score=value, signals=fired, evidence=verdict.evidence)
            )

    for candidate, declaration in declarations:
        observations.append(_observation_from_declaration(candidate, declaration))

    # -- M5 ------------------------------------------------------------
    assets = resolve(tuple(observations), telemetry, ledger)
    assets = _mark_undeclared(assets, declarations)

    # -- M6 ------------------------------------------------------------
    by_asset = _declarations_by_asset(assets, declarations)
    assets, findings = judge(assets, by_asset, policy, ledger)

    # -- M7 ------------------------------------------------------------
    return Snapshot(
        hostname=hostname,
        username=username,
        platform=platform_name,
        timestamp=timestamp,
        assets=assets,
        findings=findings,
        review_queue=tuple(review),
        coverage=ledger.freeze(),
        catalog_version=catalog.version,
    )


# --------------------------------------------------------------- adapters


def _observation_from(gate, candidate: Candidate, verdict) -> Observation:
    # The real path and inode are the strong merge keys. Without them a
    # binary and the process running it are two rows that agree about
    # everything and merge on nothing -- the false split M5 exists to stop.
    stat = gate.stat(candidate.path)
    real_path = stat.value.real_path if stat.ok else None
    inode = stat.value.inode if stat.ok else None
    # Same bytes, wherever they sit: the strongest merge key, and the only
    # one that survives a copy to a second path. Computed for identified
    # files only, so the cost is bounded by what we already believe in.
    digest = content_hash(gate, candidate.path) if stat.ok and _is_file(stat.value) else None
    detail = dict(candidate.detail)
    # Raw argv is collection-only. M6 receives the derived facts it needs,
    # while a snapshot can never accidentally serialize prompts or tokens.
    detail.pop("argv", None)
    detail["name"] = verdict.name
    detail["vendor"] = verdict.vendor
    if candidate.source.startswith("package:"):
        detail["install_method"] = candidate.source.split(":", 1)[1]
    evidence = verdict.evidence
    if candidate.source.startswith("network:"):
        host = str(candidate.detail.get("remote_host") or candidate.path)
        evidence += (Evidence("enumerator", Channel.NETWORK, candidate.path,
                              f"connected to model provider {host}", 0.75),)
    return Observation(
        kind=verdict.kind,
        identity=verdict.catalog_id or candidate.path,
        path=candidate.path,
        install_root=_root_of(candidate.path),
        owner=str(candidate.detail.get("user") or "system"),
        version=verdict.version,
        catalog_id=verdict.catalog_id,
        package_id=_package_id(candidate),
        content_hash=digest,
        real_path=real_path,
        inode=inode,
        liveness=Liveness.RUNNING if candidate.kind == "process" else Liveness.INSTALLED,
        evidence=evidence,
        detail=detail,
    )


def _observation_from_declaration(candidate: Candidate, declaration: Declaration) -> Observation:
    detail = {"name": declaration.name, "scope": declaration.scope,
              "declared": True, "command": declaration.command}
    detail.update(declaration.raw)
    if declaration.kind is not Kind.MCP_SERVER:
        detail["install_method"] = "agent_artifact"
    return Observation(
        kind=declaration.kind,
        identity=f"{declaration.kind.value}:{declaration.name}",
        path=declaration.path,
        install_root=_root_of(declaration.path),
        liveness=Liveness.DECLARED_ONLY,
        evidence=(
            Evidence("extractor", Channel.CONFIG, declaration.path,
                     f"declared in {declaration.scope} scope", 0.85),
        ),
        detail=detail,
    )


def _mark_undeclared(assets: tuple[Asset, ...], declarations) -> tuple[Asset, ...]:
    """Declared-versus-running, correlated rather than guessed.

    A running server that no configuration declares is close to a definition
    of unsanctioned -- and is also the finding most easily turned into
    noise, which is why it is decided here against the declaration set and
    never from a command line.
    """
    from dataclasses import replace

    declared_names = {d.name for _, d in declarations}
    out = []
    for asset in assets:
        if (
            asset.kind is Kind.MCP_SERVER
            and asset.liveness is Liveness.RUNNING
            and asset.name not in declared_names
        ):
            out.append(replace(asset, flags=asset.flags + ("undeclared",)))
        else:
            out.append(asset)
    return tuple(out)


def _declarations_by_asset(assets: tuple[Asset, ...], declarations) -> dict[str, Declaration]:
    by_name = {d.name: d for _, d in declarations}
    return {a.asset_id: by_name[a.name] for a in assets if a.name in by_name}


def _is_file(stat) -> bool:
    #: S_IFREG without importing `stat` -- world/ owns the OS, not this file.
    return (stat.mode & 0o170000) == 0o100000


def _root_of(path: str | None) -> str | None:
    if not path or "/" not in path:
        return None
    return path.rsplit("/", 1)[0]


def _package_id(candidate: Candidate) -> str | None:
    if not candidate.source.startswith("package:"):
        return None
    manager = candidate.source.split(":", 1)[1]
    name = candidate.detail.get("name")
    return f"{manager}:{name}" if name else None
