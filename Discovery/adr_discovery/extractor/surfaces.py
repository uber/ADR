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
from .formats.frontmatter import NoFrontmatter
from .formats.frontmatter import parse as parse_frontmatter
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
    return per_record(
        entries,
        lambda index, entry: _declaration(gate, entry, kind, scope, nested),
        candidate.path,
        cap=ENTRY_CAP,
    )


def _is_member(entry, suffixes: tuple[str, ...], nested: bool) -> bool:
    name = entry.path.rsplit("/", 1)[-1]
    if name.startswith("."):
        return False
    if nested:
        return entry.is_dir
    return any(name.endswith(s) for s in suffixes if s)


#: A directory is only a member of its surface if it carries the manifest
#: the host application loads. Without this, `~/.claude/plugins/cache` and
#: every marketplace listing under it become "plugins" -- which is how one
#: endpoint reported 191 assets, most of them internal bookkeeping.
MANIFESTS = MappingProxyType({
    Kind.SKILL: ("/SKILL.md",),
    Kind.PLUGIN: ("/.claude-plugin/plugin.json", "/plugin.json"),
})


def _declaration(gate, entry, kind: Kind, scope: str, nested: bool) -> Declaration:
    name = entry.path.rsplit("/", 1)[-1]
    body_path = entry.path

    if nested:
        body_path = _manifest_of(gate, entry.path, kind, name)

    metadata: dict[str, object] = {}
    if body_path.endswith(".md"):
        raw = gate.read_text(body_path, limit=64 * 1024)
        if raw.ok:
            try:
                metadata = parse_frontmatter(raw.value)
            except NoFrontmatter:
                metadata = {}

    declared_name = str(metadata.get("name") or name.removesuffix(".md"))
    tools = metadata.get("allowed-tools") or metadata.get("allowed_tools") or metadata.get("tools")

    return Declaration(
        kind=kind,
        name=declared_name,
        path=entry.path,
        scope=scope,
        raw={
            "surface": kind.value,
            # What it is permitted to touch, which is the whole reason a
            # skill is inventory and not documentation.
            "allowed_tools": _as_tuple(tools),
            "model": metadata.get("model"),
        },
    )


def _manifest_of(gate, path: str, kind: Kind, name: str) -> str:
    for suffix in MANIFESTS.get(kind, ()):
        if gate.stat(path + suffix).ok:
            return path + suffix
    raise FileNotFoundError(
        f"{name}: no {' or '.join(MANIFESTS.get(kind, ('manifest',)))} -- not a {kind.value}"
    )


def _as_tuple(value) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return tuple(part.strip() for part in value.split(",") if part.strip())
    if isinstance(value, (list, tuple)):
        return tuple(str(v) for v in value)
    return ()
