"""Risk facts per asset.

Pinning is the highest-yield verdict in the module and the easiest to get
wrong, because it has to read the *specification* rather than look for an
`@`, and parse options before choosing an operand. A volume mount is not an
image; a registry URL is not a package.
"""

from __future__ import annotations

import re
from types import MappingProxyType

from ..redact import rules as redact

#: runner -> flags that consume the next argument. Anything not listed and
#: starting with '-' is a switch; the first bare word after the options is
#: the operand. This table is the whole difference between reading a
#: specification and pattern-matching one.
VALUE_FLAGS = MappingProxyType({
    "npx": frozenset({"--package", "-p", "--call", "-c", "--node-options"}),
    "bunx": frozenset({"--package"}),
    "uvx": frozenset({"--from", "--with", "--python", "-p", "--index-url"}),
    "pipx": frozenset({"--spec", "--python", "--index-url", "--pip-args"}),
    "pip": frozenset({"--index-url", "-i", "--extra-index-url", "--find-links", "-f",
                      "--target", "-t", "--requirement", "-r"}),
    "docker": frozenset({"-v", "--volume", "-e", "--env", "-p", "--publish", "--name",
                         "--network", "--mount", "-w", "--workdir", "--user", "-u",
                         "--entrypoint", "--label", "-l"}),
    "podman": frozenset({"-v", "--volume", "-e", "--env", "-p", "--publish", "--name"}),
})

#: Subcommands that must be skipped before the operand is read.
SUBCOMMANDS = MappingProxyType({
    "docker": frozenset({"run", "create", "start", "exec"}),
    "podman": frozenset({"run", "create"}),
    "pip": frozenset({"install"}),
    "pipx": frozenset({"run", "install"}),
    "uv": frozenset({"tool", "run", "pip"}),
})

#: Runners that resolve a package at launch time -- the shapes where a
#: missing version means "whatever upstream published this morning".
EPHEMERAL_RUNNERS = frozenset({"npx", "bunx", "uvx", "pipx", "pip"})
CONTAINER_RUNNERS = frozenset({"docker", "podman"})

_NPM_PINNED = re.compile(r"^(@[^/]+/)?[^@/]+@[^@]+$")
_DIGEST = re.compile(r"@sha256:[0-9a-f]{8,}$")
_TAGGED = re.compile(r":[^/:]+$")


def operand_of(command: str | None, args: tuple[str, ...]) -> tuple[str | None, str]:
    """The thing being run, having parsed the options first."""
    runner = (command or "").rsplit("/", 1)[-1]
    value_flags = VALUE_FLAGS.get(runner, frozenset())
    subcommands = SUBCOMMANDS.get(runner, frozenset())

    i = 0
    seen_subcommand = not subcommands
    while i < len(args):
        arg = args[i]
        if arg.startswith("-"):
            flag = arg.split("=", 1)[0]
            if flag in value_flags and "=" not in arg:
                i += 2
                continue
            i += 1
            continue
        if not seen_subcommand and arg in subcommands:
            seen_subcommand = True
            i += 1
            continue
        return arg, runner
    return None, runner


def pinning(command: str | None, args: tuple[str, ...]) -> tuple[bool | None, tuple[str, ...]]:
    """(pinned, factors). `None` means the shape carries no pinning question."""
    operand, runner = operand_of(command, args)
    if operand is None:
        return None, ()

    if runner in CONTAINER_RUNNERS:
        if _DIGEST.search(operand):
            return True, ()
        if _TAGGED.search(operand) and not operand.endswith(":latest"):
            return False, ("unpinned_supply_chain",)
        return False, ("unpinned_supply_chain",)

    if runner in EPHEMERAL_RUNNERS:
        if _NPM_PINNED.match(operand) or "==" in operand or operand.count("@") >= 1 and not operand.startswith("@"):
            return True, ()
        return False, ("unpinned_supply_chain",)

    return None, ()


def credential_reach(env_names: tuple[str, ...], env_declared: bool) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Which secrets could be touched, by name and kind, never by value.

    The absence of an env block means the process inherits the parent
    environment -- which is *all* of them, not none. Reading absence as
    "no credentials" is the safe-looking answer and the wrong one.
    """
    if not env_declared:
        return ("<inherits parent environment>",), ("inherited",)
    return env_names, redact.credential_kinds(env_names)


def unattended(argv: tuple[str, ...]) -> bool:
    """The flag comes from the agent's own launch, never from the scheduler
    that started it: `-p` with `--dangerously-skip-permissions` is the
    finding whether cron, a timer or a person typed it."""
    flags = set(argv)
    headless = bool(flags & {"-p", "--print", "--headless", "--non-interactive", "--yes", "-y"})
    bypass = bool(
        flags & {"--dangerously-skip-permissions", "--yolo", "--auto-approve", "--no-confirm"}
    )
    return headless and bypass or bypass


def transport_of(declaration_raw: dict, url: str | None) -> tuple[str | None, tuple[str, ...]]:
    transport = str(declaration_raw.get("transport") or ("http" if url else "stdio"))
    factors: list[str] = []
    if url and url.startswith("http://"):
        factors.append("plaintext_transport")
    if transport == "sse":
        factors.append("deprecated_transport")
    return transport, tuple(factors)
