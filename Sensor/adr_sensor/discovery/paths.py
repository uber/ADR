"""Canonical install roots and install-method inference.

Shared by the probes because ``asset_id`` depends on the install root, and an
install root that changes on every upgrade would destroy the diff that is the
module's actual output.
"""

import posixpath
import re
from typing import Optional

from .env import DiscoveryEnv

#: Package-manager markers whose *next* path component is part of the root.
ROOT_MARKERS = ("Cellar", "node_modules", "pipx", "Programs", "venvs")


#: Path roots that belong to the machine rather than to a person.
SYSTEM_PREFIXES = ("/usr/", "/opt/", "/bin/", "/sbin/", "/Applications/", "/Library/",
                   "/var/", "/etc/", "/nix/", "/snap/", "/Program Files")


def is_descendant(path: str, base: str) -> bool:
    """True when ``path`` is ``base`` or sits inside it.

    A raw prefix test says /dev/application lives under /dev/app, which quietly
    extends one project's approvals to another project that merely shares the
    first few letters of its name.
    """
    if not path or not base:
        return False
    left = posixpath.normpath(str(path)).rstrip("/")
    right = posixpath.normpath(str(base)).rstrip("/")
    return left == right or left.startswith(right + "/")


def owner_of(path: str, env: DiscoveryEnv) -> str:
    """Attribute a path to a user, so two profiles never merge into one asset.

    A system-wide install belongs to nobody in particular; attributing it to
    whoever happened to run the scan invents an owner and splits the fleet view.
    """
    text = str(path).replace("\\", "/")
    parts = [part for part in text.split("/") if part]
    if len(parts) >= 2 and parts[0] in ("Users", "home"):
        return parts[1]
    if any(text.startswith(prefix) for prefix in SYSTEM_PREFIXES):
        return "system"
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
        # A store path is <hash>-<name>-<version>. Both the hash and the version
        # change on upgrade, and letting either into the identity turns every
        # upgrade into an uninstall followed by a fresh install.
        name = parts[2].split("-", 1)[-1]
        return "nix:" + re.sub(r"-\d[\w.+]*$", "", name)
    for marker in ROOT_MARKERS:
        if marker in parts:
            index = parts.index(marker)
            return "/" + "/".join(parts[: index + 2])
    return "/" + "/".join(parts[:-1]) if len(parts) > 1 else "/"


#: Path markers that identify how something was installed, most specific first.
#: Order matters: a uv tool lives under ~/.local, and a pipx venv under it too,
#: so the generic "native installer" rule has to come last.
METHOD_MARKERS = (
    ("/nix/store/", "nix"),
    ("/cellar/", "brew"),
    ("/homebrew/", "brew"),
    ("/node_modules/", "npm"),
    ("/pipx/", "pipx"),
    ("/uv/tools/", "uv"),
    ("/go/bin/", "go"),
    ("/go/pkg/", "go"),
    ("/.cargo/bin/", "cargo"),
    ("/mise/installs/", "mise"),
    ("/.asdf/installs/", "asdf"),
    ("/applications/", "dmg"),
    ("/programs/", "msi"),
)


def install_method(path: Optional[str], home: Optional[str] = None) -> str:
    """Infer the install channel from where something lives.

    Channel drives remediation - a wrong answer sends the fix to the wrong
    package manager - so the ordering above is part of the contract.
    """
    if not path:
        return "unknown"
    lowered = str(path).lower()
    if lowered.endswith(".appimage"):
        return "appimage"
    for marker, method in METHOD_MARKERS:
        if marker in lowered:
            return method
    if home:
        prefix = home.lower().rstrip("/")
        if lowered.startswith(prefix + "/.local/bin/") or lowered.startswith(prefix + "/.local/share/"):
            return "native"
    return "unknown"
