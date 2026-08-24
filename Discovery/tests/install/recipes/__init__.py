"""Fourteen families, and which of them exist yet.

Adding a tool that uses an existing family is a manifest edit with no code.
The families still marked pending need a real guest to develop against, so
they report ``unavailable`` with a reason rather than pretending to install:
a family that silently no-ops would shrink the denominator and flatter every
recall number after it.
"""

from __future__ import annotations

import posixpath
import shlex
from typing import Dict

from ...manifest import Entry
from ...provision.driver import Driver
from ..bodies import body_for
from ..runner import FAILED, INSTALLED, UNAVAILABLE, Outcome, Recipe

#: Families that need a guest with vendors, GUIs or model weights on it.
PENDING = {
    "app-installer": "per-vendor silent flags; needs a desktop session",
    "vscode-ext": "depends on app-installer",
    "service": "starts a listener and pulls a model",
    "channel-variant": "second install via nvm/fnm/usr-merge",
    "scheduler": "launchd / cron / systemd / schtasks",
    "identity": "sign-in is baked into the golden image, never scripted",
    "runtime-state": "processes must outlive the run",
    "non-ai-app": "reuses app-installer",
    "vendor-binary": "vendor download URLs drift",
    "pipx": "needs pipx on the guest",
}


def npm_global(driver: Driver, entry: Entry, platform: str) -> Outcome:
    """One command, and the version is pinned or the field is unscoreable."""
    block = entry.install
    package, version = block.get("package"), block.get("version")
    if not package:
        return Outcome(entry.id, FAILED, reason="npm-global entry with no package")
    if not version:
        return Outcome(entry.id, FAILED, reason="unpinned install; version would be unscoreable")

    result = driver.run(["npm", "install", "-g", f"{package}@{version}"])
    if not result.ok:
        return Outcome(entry.id, FAILED, reason=f"npm exited {result.returncode}")

    binary = block.get("binary") or package.rsplit("/", 1)[-1]
    return Outcome(entry.id, INSTALLED, catalog_id=entry.catalog_id, version=version,
                   method="npm", path=posixpath.join("/usr/local/bin", binary))


def declare_mcp(driver: Driver, entry: Entry, platform: str) -> Outcome:
    """A config write. No package manager, no network, no GUI."""
    path = entry.path_for(platform)
    if not path:
        return Outcome(entry.id, UNAVAILABLE, reason=f"no declaration site on {platform}")
    _write(driver, path, body_for(entry))
    return Outcome(entry.id, INSTALLED, method="declare", path=path)


def artifact(driver: Driver, entry: Entry, platform: str) -> Outcome:
    """A file, a directory or a symlink the collector must notice."""
    path = entry.path_for(platform)
    if not path:
        return Outcome(entry.id, UNAVAILABLE, reason=f"no path on {platform}")
    block = entry.create
    if block.get("symlink_to"):
        driver.run(["ln", "-sfn", str(block["symlink_to"]), path])
        return Outcome(entry.id, INSTALLED, method="symlink", path=path)
    _write(driver, path, body_for(entry))
    return Outcome(entry.id, INSTALLED, method="artifact", path=path)


def baseline_prereq(driver: Driver, entry: Entry, platform: str) -> Outcome:
    """Already in the golden image. Verified, never installed.

    Still scored, because "the prerequisites are not AI tools" is exactly the
    claim that quietly stops being true.
    """
    check = entry.verify or f"command -v {entry.name}"
    result = driver.run(["sh", "-lc", check])
    if not result.ok:
        return Outcome(entry.id, FAILED, reason=f"prerequisite missing: {check}")
    return Outcome(entry.id, INSTALLED, catalog_id=entry.catalog_id, method="preinstalled")


def _write(driver: Driver, path: str, body: str) -> None:
    parent = posixpath.dirname(path)
    if parent:
        driver.run(["mkdir", "-p", parent])
    driver.run(["sh", "-lc", f"cat > {shlex.quote(path)} <<'ADR_EOF'\n{body}\nADR_EOF"])


def _pending(family: str) -> Recipe:
    reason = PENDING[family]

    def recipe(driver: Driver, entry: Entry, platform: str) -> Outcome:
        return Outcome(entry.id, UNAVAILABLE, reason=f"recipe pending — {reason}")

    recipe.__name__ = f"pending_{family.replace('-', '_')}"
    recipe.__doc__ = f"Not built yet: {reason}."
    return recipe


REGISTRY: Dict[str, Recipe] = {
    "npm-global": npm_global,
    "declare-mcp": declare_mcp,
    "artifact": artifact,
    "baseline-prereq": baseline_prereq,
}
REGISTRY.update({family: _pending(family) for family in PENDING})

#: The families a run can actually execute today, named so a reader does not
#: have to diff REGISTRY against PENDING to find out.
BUILT = tuple(sorted(set(REGISTRY) - set(PENDING)))

__all__ = ["BUILT", "PENDING", "REGISTRY", "artifact", "baseline_prereq", "declare_mcp", "npm_global"]
