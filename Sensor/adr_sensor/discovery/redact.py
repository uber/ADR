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
#: Shapes that are secret wherever they appear. Vendor prefixes are the easy
#: half; the second half catches credentials that carry no vendor marking at
#: all - a JWT, a bearer header, a PEM block - which is what a probe added
#: tomorrow is most likely to let through.
_SECRETISH = re.compile(
    r"(sk-[A-Za-z0-9\-_]{8,}"
    r"|sk_live_[A-Za-z0-9]{8,}"
    r"|ghp_[A-Za-z0-9]{8,}"
    r"|gho_[A-Za-z0-9]{8,}"
    r"|ghs_[A-Za-z0-9]{8,}"
    r"|github_pat_[A-Za-z0-9_]{16,}"
    r"|glpat-[A-Za-z0-9\-_]{8,}"
    r"|npm_[A-Za-z0-9]{16,}"
    r"|xox[baprs]-[A-Za-z0-9\-]{8,}"
    r"|AKIA[0-9A-Z]{12,}"
    r"|ASIA[0-9A-Z]{12,}"
    r"|AIza[A-Za-z0-9\-_]{20,}"
    r"|ya29\.[A-Za-z0-9\-_]{16,}"
    r"|eyJ[A-Za-z0-9\-_]{8,}\.[A-Za-z0-9\-_]{8,}\.[A-Za-z0-9\-_]{8,}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"
    r"|(?i:bearer)\s+[A-Za-z0-9\-._~+/]{16,}=*"
    r"|(?i:(?:api[_-]?key|token|secret|password|passwd|pwd)\s*[:=]\s*)"
    r"[\"\']?[A-Za-z0-9\-._~+/]{12,}=*)"
)

#: A flag whose *name* says it carries a credential, whatever its spelling.
#: Matched against a normalized name, so --api_key and --api-key are one thing.
_SECRET_FLAG = re.compile(r"^-{1,2}[a-z0-9-]*(key|token|secret|password|passwd|credential|auth)",
                          re.IGNORECASE)

#: Separators a flag may use to carry its value inline.
_INLINE_SEPARATORS = ("=", ":")


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


def split_flag(token: str):
    """Split ``--name=value`` or ``--name:value`` into its parts.

    Both separators are in common use, and a flag that carries its value inline
    must not be mistaken for a bare flag: doing so leaks the value *and* leaves
    the parser one token out of step, so the next real flag is eaten as a value
    and its value walks out in the clear.
    """
    for separator in _INLINE_SEPARATORS:
        if separator in token:
            name, _, value = token.partition(separator)
            if name.startswith("-"):
                return name, separator, value
    return token, "", ""


def normalize_flag(name: str) -> str:
    """Compare flag names on their letters, not on their punctuation."""
    return name.replace("_", "-").lower()


def is_secret_flag(name: str) -> bool:
    normalized = normalize_flag(name)
    return normalized in VALUE_BEARING_FLAGS or bool(_SECRET_FLAG.match(normalized))


def redact_argv(argv: Iterable[str]) -> List[str]:
    """Keep argv[0] and flag names; drop every free-text or secret value."""
    items = [str(item) for item in argv]
    if not items:
        return []
    out = [sanitize(items[0])]
    drop_next = False
    for token in items[1:]:
        clean = sanitize(token)
        if drop_next:
            # A flag never doubles as another flag's value. If one turns up
            # where a value was expected, the value was simply absent.
            if clean.startswith("-"):
                drop_next = False
            else:
                out.append("[REDACTED]")
                drop_next = False
                continue
        if clean.startswith("-"):
            name, separator, _ = split_flag(clean)
            if is_secret_flag(name):
                out.append(name + separator + "[REDACTED]" if separator else name)
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
