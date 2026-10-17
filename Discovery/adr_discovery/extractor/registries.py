"""Plugin registries: which marketplaces a host knows, what it installed,
and what it has switched on.

A plugin directory on disk says nothing about whether anything loads it.
Agent hosts keep that in their own bookkeeping -- a list of known
marketplaces, a list of install records, and per-scope enablement in
settings -- and only those files can tell an installed plugin from a
marketplace clone that merely contains one.

Every file is read through the gate and parsed by a real parser. A file
that is absent is normal and leaves nothing behind; a file that is present
and cannot be read leaves a coverage record, never an empty registry.
Nothing here keeps a description, an email or a URL's credentials.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from ..contracts.paths import basename, is_windows, join, logical, relative_to
from ..contracts.paths import key as path_key
from ..contracts.records import Provenance, SourceRef
from ..redact import rules as redact
from .formats import parse as parse_document

#: A large public marketplace listing runs to megabytes.
REGISTRY_LIMIT = 4 * 1024 * 1024

CLAUDE_PLUGINS = "/.claude/plugins"
CODEX_CONFIG = "/.codex/config.toml"
CODEX_CACHE = "/.codex/plugins/cache"
CURSOR_PLUGINS = "/.cursor/plugins"
#: Where each host's marketplace clone keeps its plugin listing.
MARKETPLACE_MANIFESTS: tuple[str, ...] = (
    "/.claude-plugin/marketplace.json",
    "/.agents/plugins/marketplace.json",
    "/.cursor-plugin/marketplace.json",
)

#: `git@host:owner/repo.git`, the scp-like form that `urlsplit` cannot read.
_SCP = re.compile(r"^(?:[\w.-]+@)?(?P<host>[\w.-]+\.[\w.-]+):(?!//)(?P<path>[^\s]+)$")


@dataclass(frozen=True, slots=True)
class Marketplace:
    host: str
    name: str
    source: SourceRef | None = None
    #: The clone or directory the host loads it from, when it says.
    location: str | None = None

    def __post_init__(self):
        if self.location:
            object.__setattr__(self, "location", logical(self.location).rstrip("/"))


@dataclass(frozen=True, slots=True)
class Install:
    """One install record, as the host wrote it."""

    host: str
    plugin: str
    marketplace: str
    path: str
    version: str | None = None
    scope: str | None = None
    project: str | None = None
    installed_at: str | None = None
    present: bool = True

    def __post_init__(self):
        object.__setattr__(self, "path", logical(self.path).rstrip("/"))
        if self.project:
            object.__setattr__(self, "project", logical(self.project).rstrip("/"))


@dataclass(frozen=True, slots=True)
class Toggle:
    """`enabledPlugins["<plugin>@<marketplace>"]` in one settings file."""

    host: str
    key: str
    scope: str
    project: str | None
    enabled: bool


@dataclass(frozen=True, slots=True)
class Listing:
    """A plugin a marketplace offers from inside its own clone."""

    host: str
    marketplace: str
    plugin: str
    path: str

    def __post_init__(self):
        object.__setattr__(self, "path", logical(self.path).rstrip("/"))


@dataclass(frozen=True, slots=True)
class Registries:
    marketplaces: tuple[Marketplace, ...] = ()
    installs: tuple[Install, ...] = ()
    toggles: tuple[Toggle, ...] = ()
    listings: tuple[Listing, ...] = ()
    #: Every version directory in Claude Code's plugin cache, recorded or not.
    cached: tuple[Install, ...] = ()
    #: Cache directories a host never finished writing: no manifest, or no version.
    incomplete: tuple[str, ...] = ()

    def marketplace(self, host: str, name: str) -> Marketplace | None:
        return next((m for m in self.marketplaces if m.host == host and m.name == name), None)

    def enabled(self, install: Install) -> bool | None:
        """What the host would decide for this install, or None if nothing says.

        Settings merge narrowest first: a project's local settings, then its
        shared settings, then the user's. A user-scope install has no project
        and is decided by the user's settings alone.
        """
        key = f"{install.plugin}@{install.marketplace}"
        order = (("local", install.project), ("project", install.project), ("user", None))
        for scope, project in order:
            if scope != "user" and not project:
                continue
            for toggle in self.toggles:
                if (toggle.host, toggle.key, toggle.scope, path_key(toggle.project or "")) == (
                    install.host, key, scope, path_key(project or "")
                ):
                    return toggle.enabled
        return None


def read_registries(gate, homes: tuple[str, ...]) -> Registries:
    """Every plugin registry under every home."""
    marketplaces: list[Marketplace] = []
    installs: list[Install] = []
    toggles: list[Toggle] = []
    cached: list[Install] = []
    incomplete: list[str] = []
    for home in homes:
        for part in (_claude(gate, home), _codex(gate, home), _cursor(gate, home)):
            marketplaces.extend(part.marketplaces)
            installs.extend(part.installs)
            toggles.extend(part.toggles)
            incomplete.extend(part.incomplete)
        cached.extend(
            Install("claude", plugin, market, path, version=version)
            for market, plugin, version, path in _cache_entries(gate, home + CLAUDE_PLUGINS + "/cache")
        )
    listings = tuple(
        listing for market in marketplaces if market.location
        for listing in _listings(gate, market)
    )
    found = Registries(tuple(marketplaces), tuple(installs), tuple(toggles), listings, tuple(cached),
                       tuple(incomplete))
    if marketplaces or installs or toggles or cached or incomplete:
        missing = sum(1 for i in installs if not i.present)
        gate.ledger.probe(
            "plugin_registries", "ran",
            f"{len(marketplaces)} marketplaces, {len(installs)} install records "
            f"({missing} missing on disk), {len(toggles)} enablement entries, "
            f"{len(listings)} marketplace listings, {len(cached)} cached versions"
            + (f", {len(incomplete)} incomplete cache copies" if incomplete else ""),
        )
    return found


# ------------------------------------------------------------ provenance

INSTALLED, AVAILABLE, STALE, UNREGISTERED = "installed", "available", "stale", "unregistered"
#: Broadest first: a plugin installed for the user and for one project is a user install.
_SCOPE_ORDER = ("user", "project", "local")


def plugin_roots(found: Registries) -> tuple[tuple[str, Provenance, bool], ...]:
    """(directory, provenance, is an installed copy) for everything the registries place.

    Install records that name a missing directory place nothing; they are
    counted in coverage by `read_registries`.
    """
    out: dict[str, tuple[str, Provenance, bool]] = {}
    for market in found.marketplaces:
        if market.location:
            out[path_key(market.location)] = (market.location, Provenance(
                AVAILABLE, market.host, market.name, market.source), False)
    for listing in found.listings:
        market = found.marketplace(listing.host, listing.marketplace)
        out[path_key(listing.path)] = (listing.path, Provenance(
            AVAILABLE, listing.host, listing.marketplace, market.source if market else None,
            plugin=listing.plugin), False)
    for cached in found.cached:
        out[path_key(cached.path)] = (cached.path, _provenance(found, STALE, [cached]), True)
    installed: dict[str, list[Install]] = {}
    for install in found.installs:
        if install.present:
            installed.setdefault(path_key(install.path), []).append(install)
    for path, records in installed.items():
        out[path] = (records[0].path, _provenance(found, INSTALLED, records), True)
    return tuple(out.values())


def _provenance(found: Registries, state: str, records: list[Install]) -> Provenance:
    first = records[0]
    market = found.marketplace(first.host, first.marketplace)
    # A plugin installed from a local directory has no marketplace.
    name = first.marketplace or None
    if state != INSTALLED:
        return Provenance(state, first.host, name, market.source if market else None,
                          first.plugin, first.version)
    scopes = [r.scope for r in records if r.scope]
    decided = [found.enabled(r) for r in records]
    # On anywhere is on; off only when every record is decided off.
    enabled = True if True in decided else (None if None in decided else False)
    return Provenance(
        state, first.host, name, market.source if market else None,
        first.plugin, first.version,
        install_scope=min(scopes, key=lambda s: _SCOPE_ORDER.index(s) if s in _SCOPE_ORDER else 9, default=None),
        installed_at=min((r.installed_at for r in records if r.installed_at), default=None),
        enabled=enabled,
    )


def marketplace_at(gate, directory: str) -> str | None:
    """The marketplace a clone at `directory` declares, if it is one."""
    for suffix in MARKETPLACE_MANIFESTS:
        path = directory + suffix
        if gate.stat(path).ok:
            document = _document(gate, path) or {}
            name = document.get("name")
            return name if isinstance(name, str) and name else basename(directory)
    return None


# ----------------------------------------------------------------- claude


def _claude(gate, home: str) -> Registries:
    base = home + CLAUDE_PLUGINS
    marketplaces: dict[str, Marketplace] = {}
    known = _document(gate, f"{base}/known_marketplaces.json")
    for name, body in (known or {}).items():
        if isinstance(body, dict):
            location = body.get("installLocation")
            marketplaces[str(name)] = Marketplace(
                "claude", str(name), source_ref(body.get("source"), home),
                location if isinstance(location, str) and location else None,
            )

    installs: list[Install] = []
    recorded = _document(gate, f"{base}/installed_plugins.json") or {}
    for key, records in (recorded.get("plugins") or {}).items():
        plugin, _, market = str(key).rpartition("@")
        if not plugin:
            continue
        # Version 1 kept one record per plugin; version 2 a list per scope.
        for record in records if isinstance(records, list) else [records]:
            install = _claude_install(gate, plugin, market, record)
            if install is not None:
                installs.append(install)

    toggles: list[Toggle] = []
    projects = sorted({i.project for i in installs if i.project})
    settings = [(f"{home}/.claude/settings.json", "user", None)]
    for project in projects:
        settings.append((f"{project}/.claude/settings.json", "project", project))
        settings.append((f"{project}/.claude/settings.local.json", "local", project))
    for path, scope, project in settings:
        document = _document(gate, path) or {}
        enabled = document.get("enabledPlugins")
        if isinstance(enabled, dict):
            toggles.extend(
                Toggle("claude", str(k), scope, project, v)
                for k, v in enabled.items() if isinstance(v, bool)
            )
        extra = document.get("extraKnownMarketplaces")
        if isinstance(extra, dict):
            for name, body in extra.items():
                if str(name) not in marketplaces and isinstance(body, dict):
                    marketplaces[str(name)] = Marketplace("claude", str(name), source_ref(body.get("source"), home))
    return Registries(tuple(marketplaces.values()), tuple(installs), tuple(toggles))


def _claude_install(gate, plugin: str, market: str, record) -> Install | None:
    if not isinstance(record, dict):
        return None
    path = record.get("installPath")
    if not isinstance(path, str) or not path:
        return None
    return Install(
        host="claude",
        plugin=plugin,
        marketplace=market,
        path=path.rstrip("/"),
        version=_text(record.get("version")),
        scope=_text(record.get("scope")),
        project=_text(record.get("projectPath")),
        installed_at=_text(record.get("installedAt")),
        present=gate.stat(path).ok,
    )


# ------------------------------------------------------------------ codex


def _codex(gate, home: str) -> Registries:
    config = _document(gate, home + CODEX_CONFIG, "toml") or {}
    marketplaces = []
    for name, body in (config.get("marketplaces") or {}).items():
        if isinstance(body, dict):
            local = body.get("source_type") == "local"
            source = body.get("source") if isinstance(body.get("source"), str) else None
            marketplaces.append(Marketplace(
                "codex", str(name),
                source_ref({"source": "directory" if local else body.get("source_type") or "url",
                            "path": source, "url": source}, home),
                # A local marketplace is loaded from where it sits.
                location=source if local else None,
            ))
    toggles = [
        Toggle("codex", str(key), "user", None, body["enabled"])
        for key, body in (config.get("plugins") or {}).items()
        if isinstance(body, dict) and isinstance(body.get("enabled"), bool)
    ]
    # Codex keeps no install records: what sits in its cache is installed.
    installs = [
        Install("codex", plugin, market, path, version=version, scope="user")
        for market, plugin, version, path in _cache_entries(gate, home + CODEX_CACHE)
    ]
    return Registries(tuple(marketplaces), tuple(installs), tuple(toggles))


# ----------------------------------------------------------------- cursor


def _cursor(gate, home: str) -> Registries:
    """Cursor keeps neither install records nor toggles on disk.

    Its cache holds `<marketplace>/<plugin>/<commit>` copies; a copy that
    carries its manifest is installed, and one without (Cursor leaves empty
    directories behind when a download stops) is counted, not reported.
    Marketplace clones sit at `marketplaces/<host>/<owner>/<repo>/<commit>`,
    and the cache names a marketplace `<owner>-<repo>`. Whether a plugin is
    switched on lives in the editor's own state, so `enabled` stays unknown.
    """
    base = home + CURSOR_PLUGINS
    if not gate.stat(base).ok:
        return Registries()
    marketplaces = []
    for site in _subdirs(gate, f"{base}/marketplaces"):
        if _name(site).startswith("_"):  # `_staging`: a clone in progress
            continue
        for owner in _subdirs(gate, site):
            for repo in _subdirs(gate, owner):
                clones = [c for c in _subdirs(gate, repo) if marketplace_at(gate, c)]
                marketplaces.append(Marketplace(
                    "cursor", f"{_name(owner)}-{_name(repo)}",
                    source_ref({"source": "git", "url": f"https://{_name(site)}/{_name(owner)}/{_name(repo)}"}, home),
                    location=clones[-1] if clones else None,
                ))
    installs: list[Install] = []
    incomplete: list[str] = []
    for market in _subdirs(gate, f"{base}/cache"):
        for plugin in _subdirs(gate, market):
            copies = _subdirs(gate, plugin)
            if not copies:
                incomplete.append(plugin)
            for copy in copies:
                install = _cursor_install(gate, copy, _name(plugin), _name(market), "user")
                if install is None:
                    incomplete.append(copy)
                else:
                    installs.append(install)
    for plugin in _subdirs(gate, f"{base}/local"):
        install = _cursor_install(gate, plugin, _name(plugin), "", "local")
        if install is not None:
            installs.append(install)
    return Registries(tuple(marketplaces), tuple(installs), incomplete=tuple(incomplete))


def _cursor_install(gate, path: str, plugin: str, market: str, scope: str) -> Install | None:
    manifest = path + "/.cursor-plugin/plugin.json"
    if not gate.stat(manifest).ok:
        return None
    document = _document(gate, manifest) or {}
    # The copy is named by commit; the manifest carries the release.
    version = _text(document.get("version")) or (_name(path) if scope != "local" else None)
    return Install("cursor", plugin, market, path, version=version, scope=scope)


def _name(path: str) -> str:
    return basename(path)


def _cache_entries(gate, base: str):
    """`<cache>/<marketplace>/<plugin>/<version>`, three listings deep."""
    if not gate.stat(base).ok:
        return
    for market in _subdirs(gate, base):
        for plugin in _subdirs(gate, market):
            for version in _subdirs(gate, plugin):
                yield (basename(market), basename(plugin), basename(version), version)


def _subdirs(gate, path: str) -> list[str]:
    listing = gate.list_dir(path)
    if not listing.ok:
        return []
    return sorted(e.path for e in listing.value if e.is_dir and not basename(e.path).startswith("."))


# ------------------------------------------------------------- listings


def _listings(gate, market: Marketplace) -> list[Listing]:
    # A clone may serve several hosts; read the listing its own host reads.
    own = [s for s in MARKETPLACE_MANIFESTS if f"/.{market.host}-plugin/" in s]
    for suffix in own + [s for s in MARKETPLACE_MANIFESTS if s not in own]:
        path = market.location + suffix
        if gate.stat(path).ok:
            document = _document(gate, path) or {}
            break
    else:
        return []
    # Plugins fetched from elsewhere (`url`, `git-subdir`, ...) have no copy
    # in the clone until installed, and the install record covers them then.
    out = []
    for entry in document.get("plugins") or ():
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
            continue
        source = entry.get("source")
        local = source if isinstance(source, str) else None
        if isinstance(source, dict) and source.get("source") == "local":
            local = source.get("path") if isinstance(source.get("path"), str) else None
        if local is not None:
            out.append(Listing(market.host, market.name, entry["name"], _join(market.location, local)))
    return out


def _join(root: str, relative: str) -> str:
    if is_windows(root):
        return join(root, relative.removeprefix("./").removeprefix(".\\"))
    parts = [p for p in relative.split("/") if p not in ("", ".")]
    return "/".join([root.rstrip("/"), *parts])


# ---------------------------------------------------------------- sources


def source_ref(source, home: str | None) -> SourceRef | None:
    """A marketplace or plugin source, reduced to what identifies it.

    Git remotes become `host/owner/repo`; URLs lose userinfo, query and
    fragment; local directories are reported relative to the home they sit in.
    """
    if isinstance(source, str):
        source = {"source": "url", "url": source}
    if not isinstance(source, dict):
        return None
    kind = str(source.get("source") or "unknown")
    if kind == "github" and isinstance(source.get("repo"), str):
        return SourceRef(kind, repo="github.com/" + source["repo"].strip("/").removesuffix(".git"))
    if kind in ("directory", "file", "local") and isinstance(source.get("path"), str):
        return SourceRef("directory", path=home_relative(source["path"], home))
    url = source.get("url") or source.get("repo")
    if isinstance(url, str) and url:
        repo = repo_of(url)
        stripped = redact.strip_url(url) if "://" in url else None
        return SourceRef(kind, repo=repo, url=stripped)
    return SourceRef(kind)


def repo_of(url: str) -> str | None:
    """`host/owner/repo` for a git remote in SSH, scp-like or HTTPS form."""
    url = url.strip()
    scp = _SCP.match(url)
    if scp and "://" not in url:
        host, path = scp.group("host"), scp.group("path")
    else:
        try:
            parts = urlsplit(url)
        except ValueError:
            return None
        host, path = parts.hostname, parts.path
    path = (path or "").strip("/").removesuffix(".git")
    if not host or path.count("/") < 1:
        return None
    return f"{host}/{path}"


def home_relative(path: str, home: str | None) -> str:
    relative = relative_to(path, home) if home else None
    if relative is not None:
        return "~" if relative == "." else "~/" + relative
    return logical(path)


# ---------------------------------------------------------------- reading


def _document(gate, path: str, fmt: str = "json") -> dict | None:
    if not gate.stat(path).ok:
        return None
    text = gate.read_text(path, limit=REGISTRY_LIMIT)
    if not text.ok:
        gate.ledger.probe("plugin_registries", "degraded", f"{path}: {text.reason}")
        return None
    try:
        document = parse_document(text.value, fmt)
    except ValueError as exc:
        gate.ledger.probe("plugin_registries", "degraded", f"{path}: {type(exc).__name__}")
        return None
    if not isinstance(document, dict):
        gate.ledger.probe("plugin_registries", "degraded", f"{path}: root is not a mapping")
        return None
    return document


def _text(value) -> str | None:
    if isinstance(value, bool) or value is None:
        return None
    return str(value) if isinstance(value, (str, int, float)) and str(value) else None
