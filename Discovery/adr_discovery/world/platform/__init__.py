"""Platform selection. The only place an OS difference may exist."""

from __future__ import annotations

import sys

from .base import FixtureProviders as FixtureProviders
from .base import NullProviders, Providers


def for_host() -> Providers:
    if sys.platform == "darwin":
        from .darwin import DarwinProviders

        return DarwinProviders()
    if sys.platform.startswith("linux"):
        from .linux import LinuxProviders

        return LinuxProviders()
    if sys.platform.startswith("win"):
        from .windows import WindowsProviders

        return WindowsProviders()
    return NullProviders()
