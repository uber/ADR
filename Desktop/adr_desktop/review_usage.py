"""Opt-in Claude status-line bridge. Preserve the person's existing command."""

import os
import shlex
import signal
import stat
import subprocess
import sys
from pathlib import Path

from .config import atomic_json, command_prefix, read_private_json, strict_json

LIMIT = 256 * 1024


def target_path():
    root = Path(os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude").expanduser().absolute()
    return root / "settings.json"


def read_settings(path):
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError("Claude settings use a symlink; connect usage reporting manually")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None, {}
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or (hasattr(os, "getuid") and info.st_uid != os.getuid()):
            raise ValueError("Claude settings must be a regular file owned by you")
        raw = handle.read(LIMIT + 1)
    data = strict_json(raw, max_bytes=LIMIT)
    if not isinstance(data, dict):
        raise ValueError("Claude settings must contain a JSON object")
    return raw, data


def connection_status(state_dir):
    try:
        receipt = read_private_json(state_dir / "review-statusline.json", maximum=LIMIT)
        _, config = read_settings(Path(receipt["path"]))
        return config.get("statusLine") == receipt["installed"]
    except (OSError, ValueError, KeyError, TypeError):
        return False


def connect(state_dir, *, enabled):
    if os.name == "nt":
        raise ValueError("Automatic status-line setup is currently supported on macOS and Linux")
    path = target_path()
    receipt_path = state_dir / "review-statusline.json"
    raw, config = read_settings(path)
    receipt = read_private_json(receipt_path, maximum=LIMIT) if receipt_path.exists() else None
    if not enabled and receipt is None:
        return {"connected": False, "path": str(path)}
    current = config.get("statusLine")
    if receipt and current == receipt.get("installed") and str(path) == receipt.get("path"):
        previous = receipt.get("previous")
    elif receipt and not enabled:
        raise ValueError("The status line changed outside ADR; it was left untouched")
    else:
        previous = current
        if isinstance(previous, dict) and "review-statusline" in str(previous.get("command", "")):
            raise ValueError("Another ADR usage bridge is installed; disconnect it before changing profiles")
    if previous is not None and (
        not isinstance(previous, dict)
        or previous.get("type") != "command"
        or not isinstance(previous.get("command"), str)
    ):
        raise ValueError("The existing Claude status line has an unsupported shape; it was kept")
    installed = {
        **(previous or {}),
        "type": "command",
        "command": shlex.join([*command_prefix(), "review-statusline", "--state-dir", str(state_dir)]),
    }
    updated = {**config}
    if enabled:
        updated["statusLine"] = installed
    elif previous is None:
        updated.pop("statusLine", None)
    else:
        updated["statusLine"] = previous
    if read_settings(path)[0] != raw:
        raise ValueError("Claude settings changed during setup; try again")
    if enabled:
        # Save recovery information before pointing Claude at the bridge.
        atomic_json(receipt_path, {"path": str(path), "previous": previous, "installed": installed})
    atomic_json(path, updated)
    return {"connected": enabled, "path": str(path)}


def report_usage(state_dir, raw):
    from .local_client import request

    payload = strict_json(raw, max_bytes=LIMIT)
    limits = payload.get("rate_limits", {})
    selected = {
        kind: {key: limits[kind].get(key) for key in ("used_percentage", "resets_at")}
        for kind in ("five_hour", "seven_day")
        if isinstance(limits, dict) and isinstance(limits.get(kind), dict)
    }
    if not selected:
        return
    auth = read_private_json(state_dir / "hook-access.json", maximum=16384)
    request(
        state_dir,
        "POST",
        "/api/hooks/review-usage",
        token=auth["token"],
        payload={"rate_limits": selected},
        timeout=0.5,
    )


def status_line(state_dir):
    raw = sys.stdin.buffer.read(LIMIT + 1)
    if len(raw) > LIMIT:
        return 0
    try:
        report_usage(state_dir, raw)
    except Exception:
        pass
    try:
        receipt = read_private_json(state_dir / "review-statusline.json", maximum=LIMIT)
        previous = receipt.get("previous")
        if not previous:
            print("ADR · usage reporting")
            return 0
        # This is the owner's already configured status-line command, never a
        # command from the event, model output, or API. Preserve its stdin/stdout.
        process = subprocess.Popen(
            ["/bin/sh", "-c", previous["command"]],
            stdin=subprocess.PIPE,
            stdout=sys.stdout,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        try:
            process.communicate(raw, timeout=2)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=1)
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired):
        pass
    return 0
