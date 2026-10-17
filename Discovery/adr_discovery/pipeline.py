"""The composition root.

The only file in the package that imports more than one stage, which is
what keeps execution order an explicit statement here rather than an
emergent property of the import graph.

    M2 enumerate -> M3 extract -> M4 identify -> M5 resolve -> M6 judge -> M7 report

Every stage takes its input type and returns its output type. Coverage
travels beside the data the whole way and is frozen once, at the end.
"""

from __future__ import annotations

from datetime import datetime, timezone

from .archive import Archiver
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
    Provenance,
    ReviewItem,
)
from .contracts.snapshot import Snapshot
from .enumerator import enumerate_candidates
from .enumerator.roots import homes
from .extractor import extract
from .extractor.registries import (
    AVAILABLE,
    UNREGISTERED,
    home_relative,
    marketplace_at,
    plugin_roots,
    read_registries,
)
from .extractor.surfaces import plugin_declaration, surface_for
from .identifier import content_hash, identify, is_reviewable, score, signals_for
from .judge import EMPTY as EMPTY_POLICY
from .judge import Policy, judge
from .resolver import resolve
from .world.gate import Gate
from .world.store import ArchiveStore

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
    archive_to: ArchiveStore | None = None,
) -> Snapshot:
    """One scan, one snapshot. Emitted even when nothing is found.

    With `archive_to`, every skill that has a folder hash is also archived
    there (see `archive`), and its asset says where.
    """
    catalog = catalog if catalog is not None else EMPTY_CATALOG
    ledger = gate.ledger

    # -- M2 ------------------------------------------------------------
    candidates = enumerate_candidates(gate)

    # -- M3 ------------------------------------------------------------
    registries = read_registries(gate, homes(gate))
    roots = plugin_roots(registries)
    declarations: list[tuple[Candidate, Declaration]] = []
    for candidate in _dedupe_surfaces(gate, candidates):
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
    declarations.extend(_registered_plugins(gate, roots, declarations))

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
        observations.append(_observation_from_declaration(candidate, declaration, gate))

    # -- M5 ------------------------------------------------------------
    assets = resolve(tuple(observations), telemetry, ledger)
    assets = _mark_undeclared(assets, declarations)
    assets = _with_provenance(gate, assets, roots)
    if archive_to is not None:
        assets = _archived(gate, assets, archive_to, timestamp)

    # -- M6 ------------------------------------------------------------
    by_asset = _declarations_by_asset(assets, declarations)
    factors = {entry.id: entry.risk_factors for entry in catalog.entries if entry.risk_factors}
    assets, findings = judge(assets, by_asset, policy, ledger, factors)

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


def _archived(gate, assets, store: ArchiveStore, timestamp: str):
    """Archive each hashed skill; a skill that cannot be archived keeps its
    asset and leaves a degraded probe saying why."""
    from dataclasses import asdict, replace

    try:
        store.open()
    except OSError as exc:
        gate.ledger.unavailable("skill_archive", exc.strerror or str(exc))
        return assets
    archiver = Archiver(store, timestamp)
    user_homes = homes(gate)
    out, archived, written = [], 0, 0
    for asset in assets:
        if asset.kind is not Kind.SKILL or not asset.skill_sha256 or not asset.install_path:
            out.append(asset)
            continue
        result = archiver.archive(gate, asset.install_path, expected=asset.skill_sha256)
        if not result.ok:
            gate.ledger.probe("skill_archive", "degraded",
                              f"{asset.install_path}: {result.reason} {result.detail}".rstrip())
            out.append(asset)
            continue
        home = next((h for h in user_homes if asset.install_path.startswith(h.rstrip("/") + "/")), None)
        archiver.record(
            result.value, name=asset.name, source=home_relative(asset.install_path, home),
            provenance=asdict(asset.provenance) if asset.provenance else None,
        )
        archived += 1
        written += result.value.written
        out.append(replace(asset, archive=result.value.ref))
    try:
        archiver.close()
    except OSError as exc:
        gate.ledger.probe("skill_archive", "degraded", f"index not written: {exc.strerror or exc}")
    gate.ledger.probe("skill_archive", "ran", f"{archived} skills archived, {written} new archives")
    return tuple(out)


def _dedupe_surfaces(gate, candidates) -> list[Candidate]:
    """Config surfaces to read, each real file once.

    The config-template source and the sweep both reach `~/.claude.json`;
    reading it twice doubles its declarations and evidence. The first
    candidate is kept (registries run before the sweep, so it is the one
    with the stronger priority) and later ones contribute their sources.
    """
    from dataclasses import replace

    kept: dict[tuple[str, str], Candidate] = {}
    for candidate in candidates:
        if candidate.kind not in CONFIG_KINDS:
            continue
        stat = _surface_stat(gate, candidate, candidate.path)
        real = stat.value.real_path if stat.ok else candidate.path
        key = (candidate.kind, real)
        first = kept.get(key)
        if first is None:
            kept[key] = candidate
            continue
        sources = tuple(first.detail.get("sources") or (first.source,))
        if candidate.source not in sources:
            sources += (candidate.source,)
        aliases = tuple(first.detail.get("aliases", ())) + (candidate.path,)
        detail = {**candidate.detail, **first.detail, "sources": sources, "aliases": aliases}
        kept[key] = replace(first, detail=detail, priority=min(first.priority, candidate.priority))
    return [_at_real_path(c, real) for (_, real), c in kept.items()]


def _at_real_path(candidate: Candidate, real: str) -> Candidate:
    """Name a surface by the file itself, and keep the links that reach it.

    `CLAUDE.md -> AGENTS.md` is one file two agents load. Which path the walk
    met first must not decide the asset's identity, and the link is the
    evidence that the second agent reads it.
    """
    from dataclasses import replace

    paths = {candidate.path, *candidate.detail.get("aliases", ())}
    aliases = tuple(sorted(p for p in paths if p != real))
    if candidate.path == real and not aliases:
        return candidate
    return replace(candidate, path=real, detail={**candidate.detail, "aliases": aliases})


def _surface_stat(gate, candidate: Candidate, path: str):
    if candidate.kind == "shell_profile" and path.casefold().endswith(".ps1"):
        return gate.stat_profile(path)
    return gate.stat(path)


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
    if candidate.kind == "process":
        # The identifying proof is about the file; that it is executing is a
        # separate fact from the process table, so it counts as a second
        # channel rather than repeating the filesystem one.
        evidence += (Evidence("enumerator", Channel.RUNTIME, candidate.path,
                              "a running process executes this file", 0.9),)
    if candidate.source == "network:listening":
        evidence += (Evidence("enumerator", Channel.NETWORK, candidate.path,
                              f"listening on local model port {candidate.detail.get('port')}", 0.6),)
    elif candidate.source.startswith("network:"):
        remote = str(candidate.detail.get("remote_host") or candidate.path)
        provider = str(candidate.detail.get("provider_host") or remote)
        # A name the socket carried is direct; an address matched to a name
        # by resolution may be a shared CDN address, so it weighs less.
        proof, weight = (
            (f"connected to model provider {provider}", 0.75) if provider == remote
            else (f"connected to {remote}, an address of model provider {provider}", 0.6)
        )
        evidence += (Evidence("enumerator", Channel.NETWORK, candidate.path, proof, weight),)
    owner = candidate.detail.get("user")
    if verdict.install_root and not owner and stat.ok:
        # An installer-managed install belongs to whoever owns its files, so
        # the launcher link and a process running a release agree on it.
        owner = stat.value.owner
    return Observation(
        kind=verdict.kind,
        identity=verdict.catalog_id or candidate.path,
        path=candidate.path,
        install_root=verdict.install_root or _root_of(candidate.path),
        owner=str(owner or "system"),
        version=verdict.version,
        catalog_id=verdict.catalog_id,
        package_id=_package_id(candidate),
        content_hash=digest,
        real_path=real_path,
        inode=inode,
        modified=_modified(stat),
        liveness=Liveness.RUNNING if _is_live(candidate) else Liveness.INSTALLED,
        evidence=evidence,
        detail=detail,
    )


def _observation_from_declaration(candidate: Candidate, declaration: Declaration, gate=None) -> Observation:
    detail = {"name": declaration.name, "scope": declaration.scope,
              "declared": True, "command": declaration.command}
    detail.update(declaration.raw)
    # A skill changes when its SKILL.md does; its directory's own mtime
    # only moves when files are added or removed.
    changed_file = declaration.path
    if declaration.kind is Kind.SKILL:
        changed_file = f"{declaration.path.rstrip('/')}/SKILL.md"
    modified = _modified(_surface_stat(gate, candidate, changed_file)) if gate is not None else None
    if declaration.kind is Kind.SKILL and gate is not None:
        # The folder hash of the whole skill directory: a payload in
        # scripts/ changes it as surely as an edit to SKILL.md does. A tree
        # over the caps, or with an unreadable file, gets none (recorded by
        # the gate) rather than a hash of part of it.
        digest = gate.hash_tree(declaration.path)
        if digest.ok:
            detail["skill_sha256"] = digest.value.sha256
    if declaration.kind is not Kind.MCP_SERVER:
        detail["install_method"] = "agent_artifact"
    version = declaration.raw.get("version")
    catalog_id = declaration.raw.get("catalog_id")
    return Observation(
        kind=declaration.kind,
        identity=declaration_identity(declaration),
        # CI agents name the catalogued tool they run; carrying it lets them
        # be judged and sanctioned. It never decides the asset's identity.
        catalog_id=catalog_id if isinstance(catalog_id, str) and catalog_id else None,
        path=declaration.path,
        install_root=_root_of(declaration.path),
        version=version if isinstance(version, str) else None,
        modified=modified,
        liveness=Liveness.DECLARED_ONLY,
        evidence=(
            Evidence("extractor", Channel.CONFIG, declaration.path,
                     f"declared in {declaration.scope} scope", 0.85),
        ) + _alias_evidence(candidate, declaration),
        detail=detail,
    )


def _alias_evidence(candidate: Candidate, declaration: Declaration) -> tuple[Evidence, ...]:
    # Only where the file itself is the asset. A link to a config file says
    # nothing about each server declared inside it.
    if declaration.kind is not Kind.INSTRUCTIONS or declaration.path != candidate.path:
        return ()
    return tuple(
        Evidence("enumerator", Channel.CONFIG, alias, f"links to {declaration.path}", 0.85)
        for alias in candidate.detail.get("aliases", ())
    )


def _registered_plugins(gate, roots, declarations) -> list[tuple[Candidate, Declaration]]:
    """An installed or cached copy of a plugin is a plugin, wherever it sits.

    A marketplace's listings are not added: a large one offers thousands of
    plugins, none of them loaded from there, and what the sweep does reach
    inside them still gets their provenance.
    """
    seen = {d.path for _, d in declarations if d.kind is Kind.PLUGIN}
    out = []
    for path, provenance, installed_copy in roots:
        if not installed_copy or path in seen or not gate.stat(path).ok:
            continue
        candidate = Candidate(kind="marker_dir", path=path, source="plugin_registry")
        out.append((candidate, plugin_declaration(gate, path, "plugin", provenance.plugin or path.rsplit("/", 1)[-1])))
    return out


def _with_provenance(gate, assets: tuple[Asset, ...], roots) -> tuple[Asset, ...]:
    """Attach what the registries say to every asset inside a placed directory.

    The innermost placed directory decides. A plugin no registry places
    is `available` when a marketplace clone holds it and `unregistered`
    otherwise, and what it contains inherits that.
    """
    from dataclasses import replace

    placed = {path: provenance for path, provenance, _ in roots}
    plugins = {a.install_path: a for a in assets if a.kind is Kind.PLUGIN and a.install_path}
    for path in sorted(plugins, key=len):
        if path not in placed:
            around = _container(placed, path)
            placed[path] = _unplaced(gate, plugins[path], placed[around] if around else None)

    out = []
    for asset in assets:
        root = _container(placed, asset.install_path)
        if root is None:
            out.append(asset)
            continue
        owner = _container(plugins, asset.install_path, proper=True)
        out.append(replace(
            asset, provenance=placed[root],
            plugin_asset_id=plugins[owner].asset_id if owner else None,
        ))
    return tuple(out)


def _unplaced(gate, plugin: Asset, around: Provenance | None) -> Provenance:
    from dataclasses import replace

    if around is not None:
        if around.state != AVAILABLE:
            return around
        return replace(around, plugin=plugin.name, plugin_version=plugin.version)
    # A clone no registry lists (a host's own temporary checkout) still
    # declares itself a marketplace one or two levels up.
    parent = plugin.install_path
    for _ in range(3):
        parent = parent.rsplit("/", 1)[0]
        market = marketplace_at(gate, parent) if parent else None
        if market:
            return Provenance(AVAILABLE, marketplace=market, plugin=plugin.name, plugin_version=plugin.version)
    return Provenance(UNREGISTERED, plugin=plugin.name, plugin_version=plugin.version)


def _container(paths, path: str | None, proper: bool = False) -> str | None:
    """The nearest of `paths` that is `path` or one of its ancestors."""
    probe = path.rsplit("/", 1)[0] if path and proper else path
    while probe:
        if probe in paths:
            return probe
        probe = probe.rsplit("/", 1)[0] if "/" in probe else ""
    return None


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


#: Declarations that are a file or directory on disk: the path is the thing.
FILE_SHAPED_KINDS = frozenset({
    Kind.INSTRUCTIONS, Kind.SKILL, Kind.COMMAND, Kind.AGENT_DEFINITION,
    Kind.OUTPUT_STYLE, Kind.PLUGIN,
})


def declaration_identity(declaration: Declaration) -> str:
    """What makes one declaration this declaration and not another.

    Never the name alone: every CLAUDE.md is called CLAUDE.md, many skills
    are called `index`, and one MCP server name is routinely declared in
    several configs, each with its own launch spec.

    - an extractor-supplied `raw["identity"]` wins (hooks, CI agents);
    - file-shaped kinds are identified by their path (skill dir, file, plugin dir);
    - everything else (MCP servers, bundles, ...) by name and declaring file.

    Version, env values and other volatile data never enter the identity.
    """
    explicit = declaration.raw.get("identity")
    if explicit:
        return str(explicit)
    if declaration.kind in FILE_SHAPED_KINDS:
        return f"{declaration.kind.value}:{declaration.path}"
    return f"{declaration.kind.value}:{declaration.name}@{declaration.path}"


def _declarations_by_asset(assets: tuple[Asset, ...], declarations) -> dict[str, Declaration]:
    """Declaration for each asset, looked up by identity and never by name."""
    by_identity: dict[tuple[str, str], Declaration] = {}
    for _, declaration in declarations:
        by_identity.setdefault(
            (declaration.kind.value, declaration_identity(declaration)), declaration
        )
    out: dict[str, Declaration] = {}
    for asset in assets:
        found = by_identity.get((asset.kind.value, asset.identity))
        if found is not None:
            out[asset.asset_id] = found
    return out


def _is_live(candidate: Candidate) -> bool:
    """A process, or a socket some process holds open right now."""
    if candidate.kind == "process":
        return True
    return candidate.source.startswith("network:") and candidate.detail.get("pid") is not None


def _modified(stat) -> str | None:
    if not stat.ok:
        return None
    return datetime.fromtimestamp(stat.value.mtime, timezone.utc).isoformat(timespec="seconds")


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
