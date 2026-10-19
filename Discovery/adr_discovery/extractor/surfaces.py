"""Directory-shaped declarations.

Skills, commands, agent definitions, output styles and plugins are not
records inside a config file -- they are files in a structure a host
application knows how to load. The unit of extraction is therefore a
directory, and the same per-record isolation applies: one unreadable skill
never removes its siblings, and the count reported is the count on disk.

Nothing here reads a body. A skill file contributes its path, its name and
whatever operational metadata its frontmatter declares; the prose beneath
is business context and stays on the machine (C2).
"""

from __future__ import annotations

from types import MappingProxyType

from ..contracts.records import Declaration, Kind
from .formats import parse as parse_document
from .formats.frontmatter import NoFrontmatter, parse_with_notes
from .isolate import per_record

#: marker directory name -> (kind, file suffix, whether the entry is a dir)
SURFACES: tuple[tuple[str, Kind, tuple[str, ...], bool], ...] = (
    ("skills", Kind.SKILL, (".md",), True),
    ("commands", Kind.COMMAND, (".md", ".toml"), False),
    ("prompts", Kind.COMMAND, (".md",), False),
    ("agents", Kind.AGENT_DEFINITION, (".md",), False),
    ("output-styles", Kind.OUTPUT_STYLE, (".md",), False),
    ("plugins", Kind.PLUGIN, (".json",), True),
)

SURFACE_NAMES = frozenset(name for name, _, _, _ in SURFACES)
ENTRY_CAP = 500
#: A plugin manifest is a few hundred bytes; anything near this is not one.
MANIFEST_LIMIT = 64 * 1024


def surface_for(path: str):
    """Which surface, if any, this marker directory is."""
    name = path.rstrip("/").rsplit("/", 1)[-1]
    for surface, kind, suffixes, nested in SURFACES:
        if name == surface:
            return kind, suffixes, nested
    return None


def extract_surface(gate, candidate, scope: str):
    """One directory of declarations."""
    surface = surface_for(candidate.path)
    if surface is None:
        return None
    kind, suffixes, nested = surface

    listing = gate.list_dir(candidate.path)
    if not listing.ok:
        return None

    entries = [e for e in listing.value if _is_member(e, suffixes, nested)]
    if nested:
        # A directory without the manifest is not a member, not a failed
        # read: `plugins/` also holds `cache/`, `data/`, marketplace clones.
        entries = [e for e in entries if _manifest_of(gate, e.path, kind)]
    skipped: list[str] = []
    result = per_record(
        entries,
        lambda index, entry: _declaration(gate, entry, kind, scope, nested, skipped),
        candidate.path,
        cap=ENTRY_CAP,
    )
    if skipped:
        # A coverage note, not an error: the record is intact, only keys the
        # allowlist did not need (and a plain parser cannot read) were passed over.
        names = ", ".join(sorted(set(skipped))[:8])
        gate.ledger.probe(
            "frontmatter", "ran",
            f"{candidate.path}: {len(skipped)} unreadable key(s) skipped ({names})",
        )
    return result


def _is_member(entry, suffixes: tuple[str, ...], nested: bool) -> bool:
    name = entry.path.rsplit("/", 1)[-1]
    if name.startswith("."):
        return False
    if nested:
        # A linked skill or plugin directory (`ln -s ~/src/review
        # ~/.claude/skills/review`) loads like a real one. The manifest
        # check that follows drops links to files and dangling links.
        return entry.is_dir or entry.is_symlink
    return any(name.endswith(s) for s in suffixes if s)


#: A directory is only a member of its surface if it carries the manifest
#: the host application loads. Without this, `~/.claude/plugins/cache` and
#: every marketplace listing under it become "plugins" -- which is how one
#: endpoint reported 191 assets, most of them internal bookkeeping.
MANIFESTS = MappingProxyType({
    Kind.SKILL: ("/SKILL.md",),
    Kind.PLUGIN: ("/.claude-plugin/plugin.json", "/.codex-plugin/plugin.json", "/.cursor-plugin/plugin.json",
                  "/plugin.json"),
})


def _declaration(gate, entry, kind: Kind, scope: str, nested: bool, skipped: list[str]) -> Declaration:
    name = entry.path.rsplit("/", 1)[-1]
    body_path = entry.path

    if nested:
        body_path = _manifest_of(gate, entry.path, kind)

    if kind is Kind.PLUGIN and nested:
        return _plugin(gate, entry.path, body_path, scope)

    metadata: dict[str, object] = {}
    if body_path.endswith(".md"):
        raw = gate.read_text(body_path, limit=64 * 1024)
        if raw.ok:
            try:
                metadata, notes = parse_with_notes(raw.value)
                skipped.extend(notes)
            except NoFrontmatter:
                metadata = {}

    declared_name = str(metadata.get("name") or name.removesuffix(".md"))
    tools = metadata.get("allowed-tools") or metadata.get("allowed_tools") or metadata.get("tools")
    model = metadata.get("model")
    raw: dict[str, object] = {
        "surface": kind.value,
        # What it is permitted to touch, which is the whole reason a
        # skill is inventory and not documentation.
        "allowed_tools": _as_tuple(tools),
        "model": model if isinstance(model, str) and model else None,
    }
    version = _as_version(metadata.get("version"))
    if version:
        raw["version"] = version

    return Declaration(
        kind=kind,
        name=declared_name,
        path=entry.path,
        scope=scope,
        raw=raw,
    )


def plugin_declaration(gate, path: str, scope: str, fallback: str) -> Declaration:
    """A plugin directory a registry names, whether or not a surface reached it.

    Installed plugins live in a host's cache, where no `plugins/` directory
    holds them. Without a manifest the registry's name for it stands.
    """
    manifest = _manifest_of(gate, path, Kind.PLUGIN)
    if manifest is None:
        return Declaration(kind=Kind.PLUGIN, name=fallback, path=path, scope=scope,
                           raw={"surface": Kind.PLUGIN.value})
    return _plugin(gate, path, manifest, scope)


def _plugin(gate, path: str, manifest: str, scope: str) -> Declaration:
    """A plugin directory, named and versioned by its manifest.

    Only `name`, `version` and the author's name are read. Descriptions,
    keywords, homepages and author emails stay on the machine. A manifest
    that cannot be read leaves the plugin in the inventory, flagged, with the
    reason in coverage: the directory is still there and still loads.
    """
    raw: dict[str, object] = {"surface": Kind.PLUGIN.value}
    name = path.rsplit("/", 1)[-1]
    text = gate.read_text(manifest, limit=MANIFEST_LIMIT)
    document: object = None
    if not text.ok:
        reason = text.reason
    else:
        try:
            document = parse_document(text.value, "json")
            reason = "" if isinstance(document, dict) else "manifest root is not an object"
        except ValueError as exc:
            reason = f"{type(exc).__name__}: {exc}"
    if reason:
        gate.ledger.probe("plugin_manifest", "degraded", f"{manifest}: {reason}")
        raw["flags"] = ("malformed",)
        return Declaration(kind=Kind.PLUGIN, name=name, path=path, scope=scope, raw=raw)

    declared = document.get("name")
    version = _as_version(document.get("version"))
    if version:
        raw["version"] = version
    author = document.get("author")
    author = author.get("name") if isinstance(author, dict) else author
    if isinstance(author, str) and author.strip():
        raw["vendor"] = author.strip()
    return Declaration(
        kind=Kind.PLUGIN,
        name=declared if isinstance(declared, str) and declared else name,
        path=path,
        scope=scope,
        raw=raw,
    )


def _manifest_of(gate, path: str, kind: Kind) -> str | None:
    for suffix in MANIFESTS.get(kind, ()):
        if gate.stat(path + suffix).ok:
            return path + suffix
    return None


def _as_version(value) -> str | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (str, int, float)):
        return str(value).strip() or None
    return None


def _as_tuple(value) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return tuple(part.strip() for part in value.split(",") if part.strip())
    if isinstance(value, (list, tuple)):
        return tuple(str(v) for v in value)
    return ()
