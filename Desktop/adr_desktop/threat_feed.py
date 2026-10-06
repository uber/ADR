"""Strict, offline artifact intelligence. A non-match is not a safety verdict.

This module only parses data and compares explicit identities. It never reads a
subject file, resolves a package, fetches a reference, or executes feed content.
Callers own collection, private persistence, authorization, and enforcement.
"""

import hashlib
import ipaddress
import json
import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Mapping
from urllib.parse import urlsplit

BUNDLED_FEED_ID = "adr-public-artifacts"
MAX_FEED_BYTES = 512 * 1024
MAX_GENERATION_BYTES = 512 * 1024
MAX_INDICATORS = 2000
MAX_DEPTH = 8
MAX_VERSIONS = 128
KINDS = frozenset({"file_sha256", "skill_sha256", "package", "mcp_endpoint"})

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_NPM_NAME = re.compile(r"(?:@[a-z0-9-][a-z0-9._-]*/)?[a-z0-9-][a-z0-9._-]*\Z")
_PYPI_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?\Z")
_NPM_VERSION = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\Z"
)
# Only canonical release spellings are accepted. No range evaluation or
# equivalence that discards local/build/prerelease suffixes is performed.
_PYPI_VERSION = re.compile(
    r"(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*(?:(?:a|b|rc)[0-9]+)?"
    r"(?:\.post[0-9]+)?(?:\.dev[0-9]+)?(?:\+[a-z0-9]+(?:[._-][a-z0-9]+)*)?\Z"
)
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def _canonical(value):
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")


def _bounded(value, maximum):
    """Bound the JSON-shaped object before serialization or recursive work."""
    pending = [(value, 0)]
    nodes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if depth > MAX_DEPTH or nodes > 100000:
            raise ValueError("Artifact intelligence exceeds structural limits")
        if type(item) is dict:
            if len(item) > MAX_INDICATORS:
                raise ValueError("Artifact intelligence object is too large")
            for key, child in item.items():
                if not isinstance(key, str) or len(key) > maximum:
                    raise ValueError("Invalid artifact intelligence field")
                pending.append((child, depth + 1))
        elif type(item) is list:
            if len(item) > MAX_INDICATORS:
                raise ValueError("Artifact intelligence list is too large")
            pending.extend((child, depth + 1) for child in item)
        elif type(item) is str:
            if len(item) > maximum:
                raise ValueError("Artifact intelligence text is too large")
        elif type(item) not in (int, bool, type(None)):
            raise ValueError("Artifact intelligence must contain plain JSON data")
    try:
        raw = _canonical(value)
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise ValueError("Invalid artifact intelligence JSON data") from exc
    if len(raw) > maximum:
        raise ValueError("Artifact intelligence exceeds the byte limit")
    return raw


def _fields(value, required, optional=()):
    if type(value) is not dict or not required <= value.keys() or value.keys() - required - set(optional):
        raise ValueError("Unexpected or missing artifact intelligence fields")


def _text(value, limit, *, empty=False):
    if (
        not isinstance(value, str)
        or len(value) > limit
        or (not empty and not value.strip())
        or any(unicodedata.category(char).startswith("C") for char in value)
    ):
        raise ValueError("Invalid artifact intelligence text")
    return value


def _identifier(value):
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError("Invalid artifact intelligence identifier")
    return value


def _digest(value):
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError("Expected a lowercase SHA-256 digest")
    return value


def _url(value):
    """Canonicalize authority only; never decode paths or discard credentials."""
    _text(value, 2048)
    if any(char.isspace() for char in value) or not value.isascii() or "\\" in value:
        raise ValueError("Unsupported URL spelling")
    try:
        parts = urlsplit(value)
        scheme = parts.scheme.lower()
        if (
            scheme not in ("https", "http")
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or parts.query
            or parts.fragment
            or "?" in value
            or "#" in value
        ):
            raise ValueError("Expected a credential-free, queryless HTTP(S) URL")
        host = parts.hostname.lower()
        if ":" in host:
            host = f"[{ipaddress.IPv6Address(host).compressed}]"
        elif len(host) > 253 or any(not _HOST_LABEL.fullmatch(label) for label in host.split(".")):
            raise ValueError("Invalid URL host")
        port = parts.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("Invalid URL port")
        # Reject an empty explicit port instead of silently discarding it.
        if parts.netloc.endswith(":"):
            raise ValueError("Invalid URL port")
        authority = host
        if port is not None and port != (443 if scheme == "https" else 80):
            authority += f":{port}"
        path = parts.path or "/"
        if re.search(r"%(?![0-9A-Fa-f]{2})", path):
            raise ValueError("Invalid URL escape")
        return f"{scheme}://{authority}", path
    except (ValueError, UnicodeError) as exc:
        raise ValueError("Unsupported artifact intelligence URL") from exc


def normalize_endpoint(url):
    """Return an exact queryless endpoint; unsupported inputs raise ValueError."""
    origin, path = _url(url)
    return origin + path


def normalize_registry(ecosystem, url):
    """Keep private registry paths distinct; recognize PyPI's public Simple API."""
    if ecosystem not in ("npm", "pypi"):
        raise ValueError("Unsupported package ecosystem")
    origin, path = _url(url)
    path = path.rstrip("/")
    if ecosystem == "pypi" and origin == "https://pypi.org" and path == "/simple":
        path = ""
    return origin + path


def normalize_package_name(ecosystem, name):
    if not isinstance(name, str) or not 1 <= len(name) <= 214:
        raise ValueError("Invalid package name")
    if ecosystem == "npm" and _NPM_NAME.fullmatch(name):
        return name
    if ecosystem == "pypi" and _PYPI_NAME.fullmatch(name):
        return re.sub(r"[-_.]+", "-", name).lower()
    raise ValueError("Unsupported package name or ecosystem")


def _version(ecosystem, value):
    pattern = _NPM_VERSION if ecosystem == "npm" else _PYPI_VERSION
    if not isinstance(value, str) or len(value) > 128 or not pattern.fullmatch(value):
        raise ValueError("Expected an exact canonical package version")
    return value


def _target(kind, value):
    if kind in ("file_sha256", "skill_sha256"):
        _fields(value, {"sha256"})
        return {"sha256": _digest(value["sha256"])}
    if kind == "mcp_endpoint":
        _fields(value, {"url"})
        return {"url": normalize_endpoint(value["url"])}
    _fields(value, {"ecosystem", "registry", "name"}, {"versions", "all_versions"})
    ecosystem = value["ecosystem"]
    name = normalize_package_name(ecosystem, value["name"])
    registry = normalize_registry(ecosystem, value["registry"])
    result = {"ecosystem": ecosystem, "registry": registry, "name": name}
    if "all_versions" in value:
        if value["all_versions"] is not True or "versions" in value:
            raise ValueError("Declare either exact versions or explicit all_versions")
        result["all_versions"] = True
    else:
        versions = value.get("versions")
        if type(versions) is not list or not 1 <= len(versions) <= MAX_VERSIONS:
            raise ValueError("A package target requires bounded exact versions")
        normalized = [_version(ecosystem, version) for version in versions]
        if len(set(normalized)) != len(normalized):
            raise ValueError("Duplicate package versions")
        result["versions"] = sorted(normalized)
    return result


def _indicator(value):
    _fields(value, {"id", "status", "kind", "summary", "references", "target"}, {"revoked_reason"})
    identifier = _identifier(value["id"])
    status, kind = value["status"], value["kind"]
    if status not in ("active", "revoked") or not isinstance(kind, str) or kind not in KINDS:
        raise ValueError("Unsupported indicator status or kind")
    references = value["references"]
    if type(references) is not list or len(references) > 8:
        raise ValueError("Expected a bounded list of inert reference URLs")
    normalized_references = [normalize_endpoint(reference) for reference in references]
    if any(not reference.startswith("https://") for reference in normalized_references):
        raise ValueError("References must use HTTPS")
    if len(set(normalized_references)) != len(normalized_references):
        raise ValueError("Duplicate reference URLs")
    result = {
        "id": identifier,
        "status": status,
        "kind": kind,
        "summary": _text(value["summary"], 512),
        "references": sorted(normalized_references),
        "target": _target(kind, value["target"]),
    }
    if status == "revoked":
        result["revoked_reason"] = _text(value.get("revoked_reason"), 512)
    elif "revoked_reason" in value:
        raise ValueError("Only revoked indicators may have a revocation reason")
    return result


def validate_feed(obj):
    """Return an independent normalized feed, or reject the complete input."""
    _bounded(obj, MAX_FEED_BYTES)
    _fields(obj, {"schema_version", "feed_id", "revision", "published_at", "indicators"})
    if type(obj["schema_version"]) is not int or obj["schema_version"] != 1:
        raise ValueError("Unsupported artifact intelligence schema")
    if type(obj["revision"]) is not int or not 0 <= obj["revision"] <= 2**63 - 1:
        raise ValueError("Invalid feed revision")
    published = _text(obj["published_at"], 32)
    try:
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", published):
            raise ValueError("Expected an RFC3339 UTC publication timestamp")
        datetime.fromisoformat(published.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, OverflowError) as exc:
        raise ValueError("Invalid publication timestamp") from exc
    records = obj["indicators"]
    if type(records) is not list or len(records) > MAX_INDICATORS:
        raise ValueError("Too many artifact intelligence indicators")
    normalized = [_indicator(record) for record in records]
    if len({record["id"] for record in normalized}) != len(normalized):
        raise ValueError("Duplicate indicator IDs")
    return {
        "schema_version": 1,
        "feed_id": _identifier(obj["feed_id"]),
        "revision": obj["revision"],
        "published_at": published,
        "indicators": sorted(normalized, key=lambda record: record["id"]),
    }


def parse_feed_json(raw):
    """Strict bounded UTF-8 JSON; duplicate keys and nonfinite values are errors."""
    if not isinstance(raw, (str, bytes)):
        raise ValueError("Expected JSON text or UTF-8 bytes")
    try:
        encoded = raw.encode("utf-8") if isinstance(raw, str) else raw
        if len(encoded) > MAX_FEED_BYTES:
            raise ValueError("Artifact intelligence exceeds the byte limit")

        def pairs(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise ValueError("Duplicate JSON keys")
                result[key] = value
            return result

        def reject_constant(_):
            raise ValueError("Nonfinite JSON values are unsupported")

        obj = json.loads(
            encoded.decode("utf-8"), object_pairs_hook=pairs, parse_constant=reject_constant,
        )
        return validate_feed(obj)
    except (TypeError, UnicodeError, RecursionError, OverflowError) as exc:
        raise ValueError("Invalid artifact intelligence JSON") from exc


def compose_generation(bundled, custom=None):
    """Add owner indicators without permitting replacement of bundled records."""
    baseline = validate_feed(bundled)
    if baseline["feed_id"] != BUNDLED_FEED_ID:
        raise ValueError("The baseline must use the bundled feed namespace")
    feeds = [baseline]
    if custom is not None:
        addition = validate_feed(custom)
        if addition["feed_id"] == BUNDLED_FEED_ID:
            raise ValueError("Custom intelligence cannot impersonate the bundled feed")
        feeds.append(addition)
    if sum(len(feed["indicators"]) for feed in feeds) > MAX_INDICATORS:
        raise ValueError("Too many combined artifact intelligence indicators")
    result = {"schema_version": 1, "feeds": feeds}
    result["digest"] = hashlib.sha256(_canonical(result)).hexdigest()
    _bounded(result, MAX_GENERATION_BYTES)
    return result


def validate_generation(obj):
    """Validate the entire policy-embedded generation and its canonical digest."""
    _bounded(obj, MAX_GENERATION_BYTES)
    _fields(obj, {"schema_version", "feeds", "digest"})
    if type(obj["schema_version"]) is not int or obj["schema_version"] != 1:
        raise ValueError("Unsupported artifact intelligence generation")
    feeds = obj["feeds"]
    if type(feeds) is not list or not 1 <= len(feeds) <= 2:
        raise ValueError("Expected bundled intelligence and at most one custom feed")
    digest = _digest(obj["digest"])
    normalized = compose_generation(feeds[0], feeds[1] if len(feeds) == 2 else None)
    if digest != normalized["digest"]:
        raise ValueError("Artifact intelligence generation digest does not match")
    return normalized


def _subject(value):
    if type(value) is not dict:
        raise ValueError("Unsupported artifact subject")
    kind = value.get("kind")
    if kind in ("file_sha256", "skill_sha256"):
        return kind, {"sha256": _digest(value.get("sha256"))}
    if kind == "mcp_endpoint":
        return kind, {"url": normalize_endpoint(value.get("url"))}
    if kind == "package":
        ecosystem = value.get("ecosystem")
        version = value.get("version")
        return kind, {
            "ecosystem": ecosystem,
            "registry": normalize_registry(ecosystem, value.get("registry")),
            "name": normalize_package_name(ecosystem, value.get("name")),
            "version": _version(ecosystem, version) if version is not None else None,
        }
    raise ValueError("Unsupported artifact subject")


def _target_display(kind, target):
    if kind in ("file_sha256", "skill_sha256"):
        return f"sha256:{target['sha256']}"
    if kind == "mcp_endpoint":
        return target["url"]
    versions = "all versions" if target.get("all_versions") else ", ".join(target["versions"])
    display = f"{target['ecosystem']}:{target['name']} ({versions}) at {target['registry']}"
    return display if len(display) <= 768 else display[:767] + "…"


@dataclass(frozen=True, slots=True)
class _Match:
    position: int
    indicator_id: str
    feed_id: str
    kind: str
    summary: str
    references: tuple[str, ...]
    target_display: str
    generation_digest: str

    def row(self):
        return {
            "indicator_id": self.indicator_id,
            "source_id": self.feed_id,
            "feed_id": self.feed_id,
            "kind": self.kind,
            "summary": self.summary,
            "references": list(self.references),
            "target_display": self.target_display,
            "generation_digest": self.generation_digest,
        }


@dataclass(frozen=True, slots=True)
class CompiledGeneration:
    """Validated immutable indexes; reuse one instance for a hook or local scan."""

    digest: str
    _index: Mapping[tuple, tuple[_Match, ...]]

    def catalog(self):
        """Return one independent safe row per active qualified indicator ID."""
        unique = {}
        for matches in self._index.values():
            for match in matches:
                unique.setdefault(match.indicator_id, match)
        return {
            match.indicator_id: match.row()
            for match in sorted(unique.values(), key=lambda item: item.position)
        }

    def match(self, subject):
        """Return independent match rows, never any unrecognized subject fields."""
        try:
            kind, identity = _subject(subject)
        except (ValueError, TypeError, KeyError):
            return []
        if kind == "package":
            prefix = (kind, identity["ecosystem"], identity["registry"], identity["name"])
            rows = self._index.get((*prefix, identity["version"]), ())
            if identity["version"] is not None:
                rows += self._index.get((*prefix, None), ())
        else:
            rows = self._index.get((kind, identity["url" if kind == "mcp_endpoint" else "sha256"]), ())
        return [row.row() for row in sorted(rows, key=lambda item: item.position)]


def compile_generation(generation):
    """Validate/digest-check once, then index exact identities without I/O."""
    checked = validate_generation(generation)
    index = {}
    position = 0
    for feed in checked["feeds"]:
        for record in feed["indicators"]:
            if record["status"] != "active":
                continue
            kind, target = record["kind"], record["target"]
            match = _Match(
                position, f"{feed['feed_id']}/{record['id']}", feed["feed_id"], kind,
                record["summary"], tuple(record["references"]), _target_display(kind, target),
                checked["digest"],
            )
            position += 1
            if kind == "package":
                prefix = (kind, target["ecosystem"], target["registry"], target["name"])
                keys = [
                    (*prefix, version)
                    for version in ([None] if target.get("all_versions") else target["versions"])
                ]
            else:
                keys = [(kind, target["url" if kind == "mcp_endpoint" else "sha256"])]
            for key in keys:
                index.setdefault(key, []).append(match)
    return CompiledGeneration(
        checked["digest"], MappingProxyType({key: tuple(matches) for key, matches in index.items()}),
    )


def match_subject(generation, subject):
    """One-off convenience wrapper. Compile once for multiple subject lookups."""
    return compile_generation(generation).match(subject)


def generation_summary(generation):
    """Report actual active coverage, never a claim that unlisted items are safe."""
    checked = validate_generation(generation)
    counts = dict.fromkeys(
        ("file_sha256", "skill_sha256", "npm", "pypi", "mcp_endpoint", "package_versions", "total"), 0,
    )
    feeds = []
    revoked = 0
    for feed in checked["feeds"]:
        active = 0
        feed_revoked = 0
        for record in feed["indicators"]:
            if record["status"] == "revoked":
                revoked += 1
                feed_revoked += 1
                continue
            active += 1
            counts["total"] += 1
            kind, target = record["kind"], record["target"]
            counts[target["ecosystem"] if kind == "package" else kind] += 1
            if kind == "package":
                counts["package_versions"] += len(target.get("versions", []))
        feeds.append({
            "feed_id": feed["feed_id"],
            "revision": feed["revision"],
            "published_at": feed["published_at"],
            "active": active,
            "revoked": feed_revoked,
        })
    return {**counts, "revoked": revoked, "digest": checked["digest"], "feeds": feeds}


def load_bundled_feed():
    """Load only the application-owned baseline, never a user-specified path."""
    path = Path(__file__).parent / "data" / "malicious_artifacts.json"
    with path.open("rb") as handle:
        return parse_feed_json(handle.read(MAX_FEED_BYTES + 1))
