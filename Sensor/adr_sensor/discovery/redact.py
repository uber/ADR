"""Redaction, applied in the collector before a snapshot is ever written.

Command lines are the highest-risk field in the module: a prompt can sit in an
argv and a token can be passed as a flag. Redaction therefore runs here rather
than centrally, so the risky text never leaves the endpoint at all.
"""

import re
from typing import Dict, Iterable, List, Optional, Tuple

#: Flags whose *value* is free text or secret material. The flag name is kept,
#: because the name is what carries the risk signal; the value never is.
VALUE_BEARING_FLAGS = frozenset({
    "-p", "--prompt", "--message", "-m", "--query", "--input", "--system-prompt",
    "--api-key", "--token", "--password", "--secret", "--header", "--auth",
})

#: Paths no probe may read from or report. Enforced centrally so that a new
#: probe cannot opt out of it by accident.
DENY_PATH_PARTS = (
    "/documents/", "/desktop/", "/pictures/", "/movies/", "/music/",
    "/library/mail/", "/appdata/roaming/microsoft/outlook/", "/.ssh/",
)

_CONTROL = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]|[\x00-\x1f\x7f]")
_SECRETISH = re.compile(
    r"(sk-[A-Za-z0-9\-_]{8,}"
    r"|ghp_[A-Za-z0-9]{8,}"
    r"|gho_[A-Za-z0-9]{8,}"
    r"|xox[baprs]-[A-Za-z0-9\-]{8,}"
    r"|AKIA[0-9A-Z]{12,}"
    r"|AIza[A-Za-z0-9\-_]{20,})"
)


def is_denied(path: str) -> bool:
    """True when a path falls inside the personal-content deny-list."""
    lowered = "/" + str(path).replace("\\", "/").strip("/").lower() + "/"
    return any(part in lowered for part in DENY_PATH_PARTS)


def sanitize(text: str) -> str:
    """Strip control characters and ANSI escapes so output cannot inject.

    A server name containing a newline would otherwise break a JSONL line
    downstream, which is log injection with extra steps.
    """
    if not isinstance(text, str):
        return text
    return _CONTROL.sub("", text)


def redact_secretish(text: str) -> str:
    """Mask anything key-shaped, wherever in the output it turns up."""
    if not isinstance(text, str):
        return text
    return _SECRETISH.sub("[REDACTED]", sanitize(text))


def redact_argv(argv: Iterable[str]) -> List[str]:
    """Keep argv[0] and flag names; drop every free-text or secret value."""
    items = [str(item) for item in argv]
    if not items:
        return []
    out = [sanitize(items[0])]
    drop_next = False
    for token in items[1:]:
        if drop_next:
            out.append("[REDACTED]")
            drop_next = False
            continue
        clean = sanitize(token)
        if clean.startswith("-"):
            name, separator, _ = clean.partition("=")
            if name in VALUE_BEARING_FLAGS:
                out.append(name + "=[REDACTED]" if separator else name)
                drop_next = not separator
            else:
                out.append(redact_secretish(clean))
            continue
        out.append(redact_secretish(clean))
    return out


def redact_url(url: str) -> str:
    """Drop query strings, fragments and userinfo; keep scheme, host and path."""
    clean = sanitize(str(url)).split("#", 1)[0].split("?", 1)[0]
    if "://" in clean:
        scheme, rest = clean.split("://", 1)
        head, slash, tail = rest.partition("/")
        if "@" in head:
            head = head.split("@", 1)[1]
        clean = scheme + "://" + head + slash + tail
    return clean


def redact_env_block(env: Optional[Dict[str, str]]) -> Tuple[List[str], List[str]]:
    """Return (variable names, provider kinds). Values are never returned."""
    if not env:
        return [], []
    names = sorted(sanitize(str(key)) for key in env.keys())
    kinds = sorted({kind for kind in (_key_kind(name) for name in names) if kind})
    return names, kinds


def _key_kind(name: str) -> Optional[str]:
    upper = name.upper()
    if not any(word in upper for word in ("KEY", "TOKEN", "SECRET", "PASSWORD")):
        return None
    for needle, kind in (
        ("ANTHROPIC", "anthropic"), ("OPENAI", "openai"), ("GEMINI", "google"),
        ("GOOGLE", "google"), ("MISTRAL", "mistral"), ("COHERE", "cohere"),
        ("GITHUB", "github"), ("AWS", "aws"), ("SLACK", "slack"), ("JIRA", "atlassian"),
    ):
        if needle in upper:
            return kind
    return "other"
