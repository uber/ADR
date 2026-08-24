"""Priority roots -- one definition.

There were five copies of this tuple, in five probe files, none of which
reported that it had a boundary. Roots now *order* the sweep so the common
case stays fast; they no longer decide what exists.
"""

from __future__ import annotations

from ..contracts.records import Priority

#: (template, priority). `~` is expanded per discovered home, not per the
#: user running the scan -- the owner of an asset is a person, never whoever
#: happened to launch the collector.
ROOT_TEMPLATES: tuple[tuple[str, Priority], ...] = (
    ("~", Priority.HOME),
    ("~/Projects", Priority.CODE_ROOT),
    ("~/src", Priority.CODE_ROOT),
    ("~/code", Priority.CODE_ROOT),
    ("~/work", Priority.CODE_ROOT),
    ("~/dev", Priority.CODE_ROOT),
    ("~/git", Priority.CODE_ROOT),
    ("~/repos", Priority.CODE_ROOT),
    ("/opt", Priority.SYSTEM),
    ("/srv", Priority.SYSTEM),
    ("/usr/local", Priority.SYSTEM),
    ("/workspace", Priority.SYSTEM),
    ("/Users", Priority.BREADTH),
    ("/home", Priority.BREADTH),
)

#: Scope is policy, not a constant. Whether a dependency cache is in scope is
#: a real question with a defensible answer either way, so it lives here with
#: a stated default rather than in a tuple nobody can see.
DEPENDENCY_CACHES: tuple[str, ...] = (
    "node_modules", ".venv", "venv", "site-packages", "go/pkg/mod",
    ".cargo/registry", "vendor", ".gradle", ".m2",
)

SKIP_ALWAYS: tuple[str, ...] = (
    ".git/objects", ".Trash", "Library/Caches", ".cache", "__pycache__",
    "/.npm/", "/.local/share/pipx/", "/.cargo/registry/", "/.gradle/", "/.m2/",
)


def homes(gate) -> tuple[str, ...]:
    """Every home on the machine, not just the caller's.

    Where homes live is a platform question and is answered by M1's
    provider, not by a tuple here -- which is the same rule that removed
    the five copies of PROJECT_ROOTS.
    """
    found: list[str] = []
    for base in gate.providers.home_roots():
        listing = gate.list_dir(base)
        if not listing.ok:
            continue
        for entry in listing.value:
            if entry.is_dir and not entry.path.rsplit("/", 1)[-1].startswith("."):
                found.append(entry.path)
    if not found:
        home = gate.env.get("HOME")
        if home:
            found.append(home)
    return tuple(found)


def ordered_roots(gate) -> tuple[tuple[str, Priority], ...]:
    """Roots in sweep order: home first, then code roots, then breadth.

    Order is asserted by U2-06, because a budget exhausted late must still
    have covered the likely places.
    """
    out: list[tuple[str, Priority]] = []
    seen: set[str] = set()
    for home in homes(gate):
        for template, priority in ROOT_TEMPLATES:
            if not template.startswith("~"):
                continue
            path = home + template[1:]
            if path not in seen:
                seen.add(path)
                out.append((path, priority))
    for template, priority in ROOT_TEMPLATES:
        if template.startswith("~") or template in seen:
            continue
        seen.add(template)
        out.append((template, priority))
    out.sort(key=lambda pair: pair[1])
    return tuple(out)


def in_scope(path: str, include_dependency_caches: bool = False) -> bool:
    if any(seg in path for seg in SKIP_ALWAYS):
        return False
    return include_dependency_caches or not any(seg in path for seg in DEPENDENCY_CACHES)
