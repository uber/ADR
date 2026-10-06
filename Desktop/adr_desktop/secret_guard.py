"""Bounded credential-pattern checks. Findings contain types, never matched values."""

import os
import re
import stat
from pathlib import Path

from .config import MAX_JSON_BYTES, canonical

PATTERNS = (
    ("GitHub token", re.compile(rb"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b")),
    ("AWS access key", re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    (
        "AWS secret key",
        re.compile(
            rb"""(?i)\b(?:aws_secret_access_key|secret_access_key)["']?\s*[:=]\s*["']?[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])"""
        ),
    ),
    ("Google API key", re.compile(rb"\bAIza[A-Za-z0-9_-]{35}\b")),
    ("Google OAuth token", re.compile(rb"\bya29\.[A-Za-z0-9_-]{20,4096}")),
    ("Private key", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----")),
    ("API secret key", re.compile(rb"\bsk-(?:proj-|svcacct-|ant-api[0-9]{2}-)?[A-Za-z0-9_-]{20,512}\b")),
    (
        "Google service account",
        re.compile(rb"""(?s)"type"\s*:\s*"service_account".{0,8192}"private_key"\s*:"""),
    ),
)
KINDS = frozenset(name for name, _ in PATTERNS) | {"Saved credential"}
_PROMPT_ASSIGNMENT = re.compile(
    r"""(?im)\b(?:[A-Za-z][A-Za-z0-9_]{0,48}_)?"""
    r"""(?:password|passwd|pwd|api[_ -]?key|access[_ -]?token|secret[_ -]?key|client[_ -]?secret)"""
    r"""["']?(?:\s+is\s+|\s*[:=]\s*)(?P<value>"[^"\r\n]{1,4096}"|'[^'\r\n]{1,4096}'|[^\s,;]{1,4096})"""
)
_PLACEHOLDERS = frozenset({
    "redacted", "your-password", "your_password", "your_token", "your_api_key",
})
_DESCRIPTIONS = frozenset({
    "none", "null", "required", "optional", "invalid", "in", "not", "stored", "available",
})


def detect_prompt_credentials(text: str) -> list[str]:
    """High-confidence formats plus explicit assignments; never return matched values."""
    kinds = detect_credentials(text)
    for match in _PROMPT_ASSIGNMENT.finditer(text):
        value = match["value"].strip("\"'")
        if (
            value.lower() in _PLACEHOLDERS or value.startswith(("$", "<", "[", "{", "*"))
            or (not match["value"].startswith(("'", '"')) and value.lower() in _DESCRIPTIONS)
            or any(
                marker in value for marker in ("os.environ", "getenv(", "process.env", "adr://", "…", "...")
            )
        ):
            continue
        kinds.append("Possible password or key")
        break
    return sorted(set(kinds))


VAULT_MESSAGE = (
    "ADR withheld a possible credential. Open ADR's Credential vault to configure safe service access. "
    "Use an allowed credential alias through ADR, never the secret value. "
    "Do not ask the user to paste the credential into this conversation."
)


def detect_credentials(value: str | bytes | dict | list) -> list[str]:
    raw = (
        value
        if isinstance(value, bytes)
        else (value.encode("utf-8") if isinstance(value, str) else canonical(value).encode("utf-8"))
    )
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError("The content exceeds the credential-check limit")
    return [name for name, pattern in PATTERNS if pattern.search(raw)]


def check_file(path: Path) -> list[str]:
    """Read a regular file at most once; never follow a last-moment symlink or block on a FIFO."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return []
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if stat.S_ISDIR(info.st_mode):
            return []
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_JSON_BYTES:
            raise ValueError("This file cannot be checked safely")
        raw = handle.read(MAX_JSON_BYTES + 1)
    return detect_credentials(raw)
