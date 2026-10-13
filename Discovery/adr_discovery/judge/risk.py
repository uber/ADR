"""Risk facts per asset.

Pinning is the highest-yield verdict in the module and the easiest to get
wrong, because it has to read the *specification* rather than look for an
`@`, and parse options before choosing an operand. A volume mount is not an
image; a registry URL is not a package.
"""

from __future__ import annotations

import re
import shlex
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


def canonical_launch(command: str | None, args: tuple[str, ...]) -> tuple[str, tuple[str, ...]]:
    """(runner, args) with package-runner spellings folded onto one name.

    `pnpm dlx`, `yarn dlx` and `npm exec` behave like `npx`; `bun x` like
    `bunx`; `uv tool run` like `uvx`. Anything else is returned as given.
    """
    runner = (command or "").rsplit("/", 1)[-1]
    head = args[:1]
    if (runner in ("pnpm", "yarn") and head == ("dlx",)) or (runner == "npm" and head == ("exec",)):
        return "npx", args[1:]
    if runner == "bun" and head == ("x",):
        return "bunx", args[1:]
    if runner == "uv" and args[:2] == ("tool", "run"):
        return "uvx", args[2:]
    return runner, args


def operand_of(command: str | None, args: tuple[str, ...]) -> tuple[str | None, str]:
    """The thing being run, having parsed the options first."""
    runner, args = canonical_launch(command, args)
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


def split_line(command: str | None, args: tuple[str, ...]) -> tuple[str | None, tuple[str, ...]]:
    """A whole command line in `command` is read the way a shell would.

    Raises ValueError for an unterminated quote; an empty line gives (None, ()).
    """
    if command and not args and any(ch.isspace() for ch in command.strip()):
        parts = shlex.split(command)
        return (parts[0], tuple(parts[1:])) if parts else (None, ())
    return command, args


def pinning(command: str | None, args: tuple[str, ...]) -> tuple[bool | None, tuple[str, ...]]:
    """(pinned, factors). `None` means the shape carries no pinning question."""
    try:
        command, args = split_line(command, args)
    except ValueError:
        return None, ()
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


def launch_shape(command: str | None, args: tuple[str, ...]) -> str:
    """What kind of launch this is, so only a truly unreadable one is degraded.

    package_runner  npx / uvx / pipx / bunx / pnpm dlx ... with an operand
    container       docker / podman run with an image operand
    local           an absolute, relative or PATH-resolved program:
                    `/opt/x/bin/server`, `python -m mod`, `node server.js`
    none            nothing to launch (a url-only server)
    unknown         a runner with no operand, an empty or unsplittable
                    command line -- the only shape worth a degraded probe
    """
    if command is None or not command.strip():
        return "none"
    try:
        command, args = split_line(command, args)
    except ValueError:
        return "unknown"
    if command is None:
        return "unknown"
    runner, _ = canonical_launch(command, args)
    if runner in EPHEMERAL_RUNNERS or runner in CONTAINER_RUNNERS:
        operand, _ = operand_of(command, args)
        if operand is None:
            return "unknown"
        return "container" if runner in CONTAINER_RUNNERS else "package_runner"
    if not runner or runner.startswith("-"):
        return "unknown"
    return "local"


_PYPI_SPLIT = re.compile(r"(===|==|~=|!=|>=|<=|<|>|@|;| )")
_ECOSYSTEM_OF_RUNNER = MappingProxyType(
    {"npx": "npm", "bunx": "npm", "uvx": "pypi", "pipx": "pypi", "pip": "pypi"}
)
#: Flags that name the package explicitly, when the first bare word is the
#: command to run inside it (`uvx --from pkg cmd`, `pipx run --spec pkg cmd`).
_PACKAGE_FLAGS = MappingProxyType({
    "npx": ("--package", "-p"),
    "bunx": ("--package",),
    "uvx": ("--from",),
    "pipx": ("--spec",),
})


def normalize_package_name(ecosystem: str, name: str) -> str:
    name = name.strip().lower()
    return re.sub(r"[-_.]+", "-", name) if ecosystem == "pypi" else name


def package_of(command: str | None, args: tuple[str, ...]) -> tuple[str, str, str | None] | None:
    """(ecosystem, name, version) of the package a runner launches, or None.

    Reads the same operand `pinning` reads. The version is what the operand
    pins (`pkg@1.2.3`, `pkg==1.2.3`) and None when it pins nothing, which
    includes ranges: a range is not a version.
    """
    try:
        command, args = split_line(command, args)
    except ValueError:
        return None
    runner, canonical_args = canonical_launch(command, args)
    ecosystem = _ECOSYSTEM_OF_RUNNER.get(runner)
    if ecosystem is None:
        return None

    operand = None
    flags = _PACKAGE_FLAGS.get(runner, ())
    for i, arg in enumerate(canonical_args):
        flag, eq, inline = arg.partition("=")
        if flag in flags:
            operand = inline if eq else (canonical_args[i + 1] if i + 1 < len(canonical_args) else None)
            break
    if operand is None:
        operand, _ = operand_of(command, args)
    if not operand:
        return None
    if runner == "pip" and operand.startswith("-"):
        return None

    if ecosystem == "npm":
        at = operand.rfind("@")
        if at <= 0:
            name, version = operand, None
        else:
            name, version = operand[:at], operand[at + 1:] or None
    else:
        parts = _PYPI_SPLIT.split(re.sub(r"\[[^\]]*\]", "", operand), maxsplit=1)
        name = parts[0]
        version = None
        if len(parts) == 3 and parts[1] in ("==", "===", "@"):
            version = re.split(r"[;, ]", parts[2], maxsplit=1)[0] or None
    if not name:
        return None
    return ecosystem, normalize_package_name(ecosystem, name), version


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
    that started it: `--dangerously-skip-permissions` is the finding whether
    cron, a timer or a person typed it. Headless mode alone (`-p`) is not."""
    flags = set(argv)
    return bool(
        flags & {"--dangerously-skip-permissions", "--yolo", "--auto-approve", "--no-confirm"}
    )


def transport_of(declaration_raw: dict, url: str | None) -> tuple[str | None, tuple[str, ...]]:
    transport = str(declaration_raw.get("transport") or ("http" if url else "stdio"))
    factors: list[str] = []
    if url and url.startswith("http://"):
        factors.append("plaintext_transport")
    if transport == "sse":
        factors.append("deprecated_transport")
    return transport, tuple(factors)
