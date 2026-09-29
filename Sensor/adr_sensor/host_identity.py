"""Identity of the host the sensor runs on, resolved once per process.

Every component (session events, system configuration, OTLP resources and
runtime logs) takes identity from here so a run reports one consistent value.
Identity comes from the operating system, never from environment variables
such as ``USER``, which callers and deployment tooling can set to anything.
"""

import functools
import os
import platform
import socket
import sys
from typing import Optional

UNKNOWN_USER = "unknown_user"
UNKNOWN_HOSTNAME = "unknown_hostname"


@functools.lru_cache(maxsize=None)
def username() -> str:
    """Return the account the sensor process runs as."""
    try:
        if sys.platform == "win32":
            # GetUserNameW: the account of the current process token.
            name = os.getlogin()
        else:
            import pwd

            name = pwd.getpwuid(os.geteuid()).pw_name
    except Exception:
        name = ""
    return name or UNKNOWN_USER


@functools.lru_cache(maxsize=None)
def hostname() -> str:
    """Return the machine's host name."""
    try:
        name = socket.gethostname()
    except Exception:
        name = ""
    return name or UNKNOWN_HOSTNAME


@functools.lru_cache(maxsize=None)
def host_os() -> Optional[str]:
    """Return the operating system as ``platform.system()`` names it (Darwin, Linux, Windows, ...)."""
    try:
        return platform.system() or None
    except Exception:
        return None
