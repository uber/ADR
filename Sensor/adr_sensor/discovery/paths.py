"""Canonical install roots and install-method inference.

Shared by the probes because ``asset_id`` depends on the install root, and an
install root that changes on every upgrade would destroy the diff that is the
module's actual output.
"""

from typing import Optional

from .env import DiscoveryEnv

#: Package-manager markers whose *next* path component is part of the root.
ROOT_MARKERS = ("Cellar", "node_modules", "pipx", "Programs", "venvs")


def owner_of(path: str, env: DiscoveryEnv) -> str:
    """Attribute a path to a user, so two profiles never merge into one asset."""
    parts = [part for part in str(path).replace("\\", "/").split("/") if part]
    if len(parts) >= 2 and parts[0] in ("Users", "home"):
        return parts[1]
    return env.user


def install_root(path: Optional[str]) -> Optional[str]:
    """Canonical install root, with content-addressed store hashes collapsed.

    A Nix store path embeds a hash that changes on every rebuild. Letting it
    into the asset identity would make each upgrade look like an uninstall
    followed by a fresh install.
    """
    if not path:
        return None
    parts = [part for part in str(path).split("/") if part]
    if len(parts) >= 3 and parts[0] == "nix" and parts[1] == "store":
        return "nix:" + parts[2].split("-", 1)[-1]
    for marker in ROOT_MARKERS:
        if marker in parts:
            index = parts.index(marker)
            return "/" + "/".join(parts[: index + 2])
    return "/" + "/".join(parts[:-1]) if len(parts) > 1 else "/"


def install_method(path: Optional[str]) -> str:
    if not path:
        return "unknown"
    lowered = str(path).lower()
    if "/nix/store/" in lowered:
        return "nix"
    if "cellar" in lowered or "/homebrew/" in lowered:
        return "brew"
    if "node_modules" in lowered:
        return "npm"
    if "pipx" in lowered:
        return "pipx"
    if lowered.endswith(".appimage"):
        return "appimage"
    return "unknown"
