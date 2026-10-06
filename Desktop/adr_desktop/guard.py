"""Install a stable, bounded hook guardian outside the relocatable application bundle."""

import os
import subprocess
import tempfile
from pathlib import Path

from .config import atomic_json, command_prefix, read_private_json

GUARD_VERSION = 7


def _atomic_bytes(path: Path, value: bytes, mode: int):
    if path.is_symlink():
        raise ValueError("Refusing to replace a symbolic link")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix=".adr-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def publish_target(state_dir: Path, prefix=None):
    prefix = prefix or command_prefix()
    if not prefix or not Path(prefix[0]).is_absolute() or any("\0" in arg or not arg for arg in prefix):
        raise ValueError("Invalid hook core command")
    raw = b"".join(argument.encode("utf-8") + b"\0" for argument in prefix)
    if len(raw) > 16384 or len(prefix) > 20:
        raise ValueError("Hook core command is too large")
    _atomic_bytes(state_dir / "bridge-argv.bin", raw, 0o600)


def install_guard(state_dir: Path) -> Path:
    if os.name == "nt":
        raise ValueError("The standalone hook guardian is not available for native Windows yet")
    target = state_dir / "bin" / "adr-hook"
    bundled = Path(__file__).parent / "bin" / "adr-hook"
    if bundled.is_file():
        _atomic_bytes(target, bundled.read_bytes(), 0o700)
        atomic_json(state_dir / "guard-version.json", {"version": GUARD_VERSION})
        return target
    compiler = next((path for path in ("/usr/bin/cc", "/usr/bin/gcc") if Path(path).is_file()), None)
    if not compiler:
        raise ValueError("Use the packaged app, or install a C compiler before connecting hooks")
    source = Path(__file__).parent / "native" / "hook_bridge.c"
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory(prefix="guard-", dir=target.parent) as temporary:
        output = Path(temporary) / "adr-hook"
        subprocess.run(
            [compiler, "-std=c11", "-O2", "-Wall", "-Wextra", str(source), "-o", str(output)],
            check=True,
            capture_output=True,
            timeout=30,
        )
        _atomic_bytes(target, output.read_bytes(), 0o700)
    atomic_json(state_dir / "guard-version.json", {"version": GUARD_VERSION})
    return target


def upgrade_guard(state_dir: Path) -> bool:
    """Refresh an existing managed guardian, never install or enable an agent plugin."""
    if not (state_dir / "bin" / "adr-hook").is_file():
        return False
    try:
        version = read_private_json(state_dir / "guard-version.json", maximum=4096).get("version")
    except (OSError, ValueError):
        return False
    if not isinstance(version, int) or isinstance(version, bool) or not 1 <= version < GUARD_VERSION:
        return False
    install_guard(state_dir)
    return True
