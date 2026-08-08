"""
Windows app-data roots resolved from the environment.

On roaming-profile and redirected-folder setups — common on managed enterprise
Windows fleets — ``%APPDATA%`` and ``%LOCALAPPDATA%`` point outside the user
profile, so a profile-relative ``~/AppData/...`` guess finds nothing. The
environment is therefore consulted first and the conventional profile-relative
location is only a fallback, matching how the opencode parser and the observer
already honor ``XDG_DATA_HOME`` / ``XDG_CACHE_HOME``.
"""

import os
from pathlib import Path


def windows_appdata() -> Path:
    """Return the Windows roaming app-data root (``%APPDATA%``)."""
    return Path(os.environ.get("APPDATA") or Path.home() / "AppData/Roaming")


def windows_local_appdata() -> Path:
    """Return the Windows local app-data root (``%LOCALAPPDATA%``)."""
    return Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData/Local")
