"""Executables on disk.

The registries answer for everything a package manager installed, and the
sweep answers for everything a marker locates. Neither answers for a bare
executable: a tarball unpacked into /opt, an AppImage in Downloads, a
binary copied out of a container. Those have no package record and sit
beside no marker, and without this source they are invisible.

Bounded on purpose. Only bin-shaped directories are read, one level deep,
and the shared entry ceiling applies -- this must not become a second
filesystem sweep wearing a different name.
"""

from __future__ import annotations

from ...contracts.records import Candidate, Priority
from ..markers import BUNDLE_SUFFIXES

#: Directories that hold executables by convention, plus whatever PATH says.
BIN_ROOTS: tuple[str, ...] = (
    "/usr/local/bin", "/usr/bin", "/bin", "/opt/homebrew/bin", "/opt/local/bin",
    "/snap/bin", "~/.local/bin", "~/bin", "~/.cargo/bin", "~/go/bin",
    "~/.npm-global/bin", "~/.bun/bin", "~/.deno/bin",
)

MAX_PER_ROOT = 2_000


def from_binaries(gate, homes: tuple[str, ...]) -> tuple[Candidate, ...]:
    out: list[Candidate] = []
    seen: set[str] = set()

    for root in _roots(gate, homes):
        listing = gate.list_dir(root)
        if not listing.ok:
            continue
        kept = 0
        for entry in listing.value:
            if kept >= MAX_PER_ROOT:
                gate.ledger.truncate(root, kept, len(listing.value))
                break
            if not (entry.is_exec or entry.path.endswith(BUNDLE_SUFFIXES)):
                continue
            if entry.path in seen:
                continue
            seen.add(entry.path)
            kept += 1
            out.append(
                Candidate(
                    kind="binary",
                    path=entry.path,
                    source="binaries",
                    priority=Priority.HOME,
                    detail={"name": entry.path.rsplit("/", 1)[-1], "symlink": entry.is_symlink},
                )
            )
    return tuple(out)


def _roots(gate, homes: tuple[str, ...]) -> list[str]:
    roots: list[str] = []
    for template in BIN_ROOTS:
        if template.startswith("~"):
            roots.extend(home + template[1:] for home in homes)
        else:
            roots.append(template)
    for entry in (gate.env.get("PATH") or "").split(":"):
        if entry and entry not in roots:
            roots.append(entry)
    return roots
