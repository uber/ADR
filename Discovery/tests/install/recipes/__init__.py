"""Fourteen recipe families, one per way something reaches a machine.

A family is the unit of reuse: adding a tool that installs the way an existing
tool installs is a manifest edit with no code at all. That property is what
keeps a 120-entry inventory cheap to grow, and it is why the family is derived
from the entry's shape rather than declared beside it.

Three families are implemented: ``declare-mcp``, ``artifact`` and
``npm-global``. Between them they cover 60 of Linux's 105 entries with no
vendor installer, no GUI session and no model downloads - and they are the two
categories where the collector does the most inference, so the cheapest half of
the manifest exercises the most interesting logic.

The other eleven declare themselves and record ``unimplemented``. That is a
deliberate status: it keeps those entries out of the denominator, and it keeps
them loud. A harness that silently omitted them would report a recall computed
over whatever happened to work.
"""

from typing import Dict, Type

from .base import Outcome, Recipe, Unimplemented
from .artifact import ArtifactRecipe
from .declare_mcp import DeclareMcpRecipe
from .npm_global import NpmGlobalRecipe

#: Families with no implementation yet, and the phase that will bring each in.
#: Named individually rather than defaulted, so adding a family to the manifest
#: without a recipe fails loudly instead of inheriting a stub.
PENDING = {
    "app-installer": "P2/P3 - 16 vendors, 16 sets of silent flags",
    "service": "P2 - starts a listener and pulls a model",
    "channel-variant": "P2 - second installs, after the first ones",
    "vscode-ext": "P2 - depends on app-installer",
    "scheduler": "P2 - launchd, cron, systemd, schtasks",
    "identity": "P3 - baked into the image, not scripted",
    "baseline-prereq": "P1 - already in the golden image, verified only",
    "runtime-state": "P2 - processes must stay alive across the scan",
    "vendor-binary": "P2 - download, chmod, place on PATH",
    "non-ai-app": "P2 - reuses app-installer / vscode-ext",
    "pipx": "P2 - one command",
}

REGISTRY: Dict[str, Type[Recipe]] = {
    "declare-mcp": DeclareMcpRecipe,
    "artifact": ArtifactRecipe,
    "npm-global": NpmGlobalRecipe,
}


def for_family(family: str) -> Recipe:
    """The recipe that executes this family, or one that records why it cannot."""
    implementation = REGISTRY.get(family)
    if implementation is None:
        return Unimplemented(family, PENDING.get(family, "no recipe registered"))
    return implementation()


__all__ = ["Outcome", "Recipe", "REGISTRY", "PENDING", "for_family"]
