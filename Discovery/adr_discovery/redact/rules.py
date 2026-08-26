"""C2 -- redaction, applied at collection.

Imported by whoever touches risky text, never run as a pass at the end: a
final filter is something a stage added tomorrow can be placed behind.

Both directions are enforced here. Leaking a value is the obvious failure;
dropping a *name* is the quiet one, because a lost flag name is a
permission bypass nobody detects. Functions below therefore keep names and
shapes deliberately, and remove only values.
"""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

#: Flags whose *operand* is secret. The flag name survives; the value does not.
#: `--dangerously-skip-permissions` is deliberately absent -- it takes no
#: operand and its presence is exactly the signal M6 needs.
CREDENTIAL_FLAGS: frozenset[str] = frozenset(
    {
        "--api-key", "--auth", "--header", "--input", "--message", "--password",
        "--prompt", "--query", "--secret", "--system-prompt", "--token",
        "-m", "-p", "-H",
    }
)

#: Environment variable names whose presence implies a credential of a kind.
CREDENTIAL_ENV_PREFIXES: tuple[tuple[str, str], ...] = (
    ("ANTHROPIC_", "anthropic"),
    ("OPENAI_", "openai"),
    ("GOOGLE_", "google"),
    ("GEMINI_", "google"),
    ("AWS_", "aws"),
    ("AZURE_", "azure"),
    ("GITHUB_", "github"),
    ("GITLAB_", "gitlab"),
    ("HF_", "huggingface"),
    ("MISTRAL_", "mistral"),
    ("COHERE_", "cohere"),
)

#: Denied wherever access happens, so a stage added tomorrow inherits it
#: without containing a rule of its own. Enforced in M1 on the *resolved*
#: target, which is why a symlink into one of these is refused too.
PERSONAL_PATH_SEGMENTS: tuple[str, ...] = (
    "/.ssh/", "/.gnupg/", "/Documents/", "/Desktop/", "/Pictures/",
    "/Music/", "/Movies/", "/Library/Mail/", "/Library/Messages/",
    "/AppData/Local/Microsoft/Outlook/",
)

REDACTED = "<redacted>"


def strip_url(url: str) -> str:
    """Keep scheme, host, port and path. Drop userinfo, query and fragment.

    A real parser, not a split: a URL split before the port loses the port,
    and a URL split on '@' loses a host that contains one.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return REDACTED
    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"
    return urlunsplit((parts.scheme, host, parts.path, "", ""))


def env_names(env: dict[str, object] | None) -> tuple[str, ...]:
    """Names survive, values never appear. Order is stable for identity."""
    if not env:
        return ()
    return tuple(sorted(str(k) for k in env))


def credential_kinds(names: tuple[str, ...]) -> tuple[str, ...]:
    """Report *that* a credential is reachable, never which one it is."""
    kinds: set[str] = set()
    for name in names:
        upper = name.upper()
        for prefix, kind in CREDENTIAL_ENV_PREFIXES:
            if upper.startswith(prefix) and (
                "KEY" in upper or "TOKEN" in upper or "SECRET" in upper or "PASSWORD" in upper
            ):
                kinds.add(kind)
    return tuple(sorted(kinds))


def scrub_argv(argv: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    """Keep every flag name and every non-secret operand.

    Values of credential-bearing flags are replaced, in both the separated
    (`--token X`) and joined (`--token=X`) forms.
    """
    out: list[str] = []
    expect_value = False
    for arg in argv:
        if expect_value:
            out.append(REDACTED)
            expect_value = False
            continue
        if "=" in arg and arg.startswith("-"):
            flag, _, _ = arg.partition("=")
            if flag in CREDENTIAL_FLAGS:
                out.append(f"{flag}={REDACTED}")
                continue
            out.append(arg)
            continue
        out.append(arg)
        if arg in CREDENTIAL_FLAGS:
            expect_value = True
    return tuple(out)


def is_personal(resolved_path: str) -> bool:
    """Decided on the resolved target, never on the path handed in."""
    probe = resolved_path.replace("\\", "/")
    if not probe.endswith("/"):
        probe += "/"
    return any(seg in probe for seg in PERSONAL_PATH_SEGMENTS)


def explain() -> tuple[str, ...]:
    """What `--dry-run --explain` prints. An explain that under-reports is
    worse than none, so this is generated from the same constants the
    functions above use rather than written out separately."""
    return (
        "paths, metadata, hashes and allowlisted config keys -- never file contents",
        f"environment variable names only ({len(CREDENTIAL_ENV_PREFIXES)} prefixes mapped to credential kinds)",
        f"argv with the operands of {len(CREDENTIAL_FLAGS)} credential-bearing flags replaced",
        "URLs with userinfo, query and fragment removed",
        f"no access at all under {len(PERSONAL_PATH_SEGMENTS)} personal path segments",
    )
