"""Sanction state, from tenant policy.

Tenant-specific values come from configuration, never from code. The test
for this is to run one world against two policies and require two verdicts
-- a value reachable from code alone cannot pass it.

A policy names things two ways:

- `approved` / `forbidden`: catalog ids, for catalogued tools;
- `approved_indicators` / `forbidden_indicators`: identity indicators for
  everything else (MCP servers, skills, hooks' files, packages). These use
  the same identity kinds as an artifact feed, so one list can drive both:

    {"kind": "skill_sha256", "sha256": "<64 hex>"}      raw SKILL.md bytes
    {"kind": "file_sha256",  "sha256": "<64 hex>"}      the asset's content hash
    {"kind": "mcp_endpoint", "url": "https://..."}      exact normalized URL
    {"kind": "package", "ecosystem": "npm"|"pypi", "name": "...",
     "versions": ["1.2.3"]  |  "all_versions": true}
    {"kind": "name", "asset_kind": "mcp_server", "name": "..."}

Forbidden beats approved. "unsanctioned" is reported only for assets the
policy addresses: catalogued assets when `approved` is non-empty, and, for
approved indicators, assets of the kinds those indicators speak about
(skill_sha256: skills; mcp_endpoint and package: MCP servers; name: its
asset_kind). A file_sha256 indicator addresses no kind on its own.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from types import MappingProxyType
from urllib.parse import urlsplit, urlunsplit

from ..contracts.records import Asset, Declaration, Kind
from ..redact import rules as redact
from .risk import normalize_package_name, package_of

_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
ECOSYSTEMS = frozenset({"npm", "pypi"})
INDICATOR_KINDS = frozenset({"skill_sha256", "file_sha256", "mcp_endpoint", "package", "name"})
#: Package managers whose records are matched by `package` indicators.
MANAGER_ECOSYSTEM = MappingProxyType({
    "npm": "npm", "pnpm": "npm", "yarn": "npm", "bun": "npm",
    "pip": "pypi", "pipx": "pypi", "uv": "pypi",
})
_MCP_KINDS = frozenset({Kind.MCP_SERVER, Kind.MCP_BUNDLE})


def normalize_url(url: str) -> str:
    """Scheme and host lowercased, credentials/query/fragment dropped,
    no trailing slash. Applied to both sides of an endpoint comparison."""
    stripped = redact.strip_url(url.strip())
    try:
        parts = urlsplit(stripped)
    except ValueError:
        return stripped
    path = parts.path.rstrip("/")
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), path, "", ""))


@dataclass(frozen=True, slots=True)
class Indicator:
    kind: str
    sha256: str | None = None
    url: str | None = None
    ecosystem: str | None = None
    name: str | None = None
    versions: frozenset[str] = frozenset()
    all_versions: bool = False
    asset_kind: str | None = None

    @property
    def addresses(self) -> frozenset[Kind]:
        """The asset kinds this indicator can say something about."""
        if self.kind == "skill_sha256":
            return frozenset({Kind.SKILL})
        if self.kind in ("mcp_endpoint", "package"):
            return _MCP_KINDS
        if self.kind == "name" and self.asset_kind:
            return frozenset({Kind(self.asset_kind)})
        return frozenset()

    def matches(self, asset: Asset, declaration: Declaration | None) -> bool:
        if self.kind == "skill_sha256":
            return asset.skill_sha256 is not None and asset.skill_sha256 == self.sha256
        if self.kind == "file_sha256":
            return asset.content_hash is not None and asset.content_hash.lower() == self.sha256
        if self.kind == "mcp_endpoint":
            return (
                asset.kind in _MCP_KINDS
                and declaration is not None
                and declaration.url is not None
                and normalize_url(declaration.url) == self.url
            )
        if self.kind == "name":
            return asset.kind.value == self.asset_kind and asset.name == self.name
        if self.kind == "package":
            return self._package_matches(asset, declaration)
        return False

    def _package_matches(self, asset: Asset, declaration: Declaration | None) -> bool:
        found: tuple[str, str, str | None] | None = None
        if asset.kind in _MCP_KINDS and declaration is not None:
            found = package_of(declaration.command, declaration.args)
        if found is None and asset.package_id and ":" in asset.package_id:
            manager, _, package = asset.package_id.partition(":")
            ecosystem = MANAGER_ECOSYSTEM.get(manager)
            if ecosystem is not None:
                found = (ecosystem, normalize_package_name(ecosystem, package), asset.version)
        if found is None:
            return False
        ecosystem, name, version = found
        if ecosystem != self.ecosystem or name != self.name:
            return False
        # An unpinned launch cannot be shown to be a listed version.
        return self.all_versions or (version is not None and version in self.versions)

    @staticmethod
    def from_dict(raw: object, field: str, index: int) -> "Indicator":
        where = f"policy {field}[{index}]"
        if not isinstance(raw, dict):
            raise ValueError(f"{where} must be an object")
        kind = raw.get("kind")
        if kind not in INDICATOR_KINDS:
            raise ValueError(f"{where} has unknown kind {kind!r}; expected one of {sorted(INDICATOR_KINDS)}")

        allowed = {
            "skill_sha256": {"kind", "sha256"},
            "file_sha256": {"kind", "sha256"},
            "mcp_endpoint": {"kind", "url"},
            "package": {"kind", "ecosystem", "name", "versions", "all_versions"},
            "name": {"kind", "asset_kind", "name"},
        }[kind]
        extra = sorted(set(raw) - allowed)
        if extra:
            raise ValueError(f"{where} ({kind}) has unexpected field(s) {extra}")

        def text(key: str) -> str:
            value = raw.get(key)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{where} ({kind}) requires a non-empty string {key!r}")
            return value.strip()

        if kind in ("skill_sha256", "file_sha256"):
            digest = text("sha256")
            if not _SHA256.match(digest):
                raise ValueError(f"{where} ({kind}) sha256 must be 64 hex characters")
            return Indicator(kind, sha256=digest.lower())
        if kind == "mcp_endpoint":
            url = text("url")
            if urlsplit(url).scheme not in ("http", "https") or not urlsplit(url).hostname:
                raise ValueError(f"{where} (mcp_endpoint) url must be an absolute http(s) URL")
            return Indicator(kind, url=normalize_url(url))
        if kind == "name":
            asset_kind = text("asset_kind")
            if asset_kind not in {k.value for k in Kind}:
                raise ValueError(f"{where} (name) has unknown asset_kind {asset_kind!r}")
            return Indicator(kind, asset_kind=asset_kind, name=text("name"))

        ecosystem = text("ecosystem")
        if ecosystem not in ECOSYSTEMS:
            raise ValueError(f"{where} (package) ecosystem must be one of {sorted(ECOSYSTEMS)}")
        versions_raw = raw.get("versions")
        all_versions = raw.get("all_versions", False)
        if not isinstance(all_versions, bool):
            raise ValueError(f"{where} (package) all_versions must be true or false")
        if all_versions == (versions_raw is not None):
            raise ValueError(f"{where} (package) needs exactly one of 'versions' or 'all_versions': true")
        versions: frozenset[str] = frozenset()
        if versions_raw is not None:
            if (
                isinstance(versions_raw, str)
                or not isinstance(versions_raw, list)
                or not versions_raw
                or not all(isinstance(v, str) and v for v in versions_raw)
            ):
                raise ValueError(f"{where} (package) 'versions' must be a non-empty array of strings")
            versions = frozenset(versions_raw)
        return Indicator(
            kind,
            ecosystem=ecosystem,
            name=normalize_package_name(ecosystem, text("name")),
            versions=versions,
            all_versions=all_versions,
        )


@dataclass(frozen=True, slots=True)
class Policy:
    approved: frozenset[str] = frozenset()
    forbidden: frozenset[str] = frozenset()
    #: Domains the tenant owns. A destination outside this set is third
    #: party; there is no default, because a default would be somebody's
    #: wrong answer shipped as a constant.
    tenant_domains: frozenset[str] = frozenset()
    #: Identity indicators for assets with no catalog id (see module docs).
    approved_indicators: tuple[Indicator, ...] = ()
    forbidden_indicators: tuple[Indicator, ...] = ()

    @staticmethod
    def from_dict(raw: dict) -> "Policy":
        if not isinstance(raw, dict):
            raise ValueError("policy root must be an object")

        def string_set(field: str) -> frozenset[str]:
            value = raw.get(field) or ()
            if isinstance(value, str) or not isinstance(value, (list, tuple, set, frozenset)):
                raise ValueError(f"policy {field!r} must be an array of strings")
            if not all(isinstance(item, str) and item for item in value):
                raise ValueError(f"policy {field!r} must contain non-empty strings")
            return frozenset(value)

        def indicators(field: str) -> tuple[Indicator, ...]:
            value = raw.get(field)
            if value is None:
                return ()
            if isinstance(value, (str, dict)) or not isinstance(value, (list, tuple)):
                raise ValueError(f"policy {field!r} must be an array of indicator objects")
            return tuple(Indicator.from_dict(item, field, i) for i, item in enumerate(value))

        return Policy(
            approved=string_set("approved"),
            forbidden=string_set("forbidden"),
            tenant_domains=frozenset(domain.lower().rstrip(".") for domain in string_set("tenant_domains")),
            approved_indicators=indicators("approved_indicators"),
            forbidden_indicators=indicators("forbidden_indicators"),
        )


EMPTY = Policy()


def state_for(asset: Asset, policy: Policy, declaration: Declaration | None = None) -> str:
    """forbidden > approved > unsanctioned (only where addressed) > unknown."""
    catalog_id = asset.catalog_id
    if catalog_id is not None and catalog_id in policy.forbidden:
        return "forbidden"
    if any(i.matches(asset, declaration) for i in policy.forbidden_indicators):
        return "forbidden"
    if catalog_id is not None and catalog_id in policy.approved:
        return "approved"
    if any(i.matches(asset, declaration) for i in policy.approved_indicators):
        return "approved"
    if catalog_id is not None and policy.approved:
        return "unsanctioned"
    if any(asset.kind in i.addresses for i in policy.approved_indicators):
        return "unsanctioned"
    return "unknown"


def is_third_party(host: str, policy: Policy) -> bool:
    h = host.lower().rstrip(".")
    return not any(h == d or h.endswith("." + d) for d in policy.tenant_domains)
