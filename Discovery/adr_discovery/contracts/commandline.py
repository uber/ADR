"""Read command lines without executing a shell or expanding variables."""

from __future__ import annotations

import re
import shlex

SHELL_WRAPPERS = frozenset({"cmd", "powershell", "pwsh"})
_WINDOWS_LINE = re.compile(r'^\s*"?(?:[A-Za-z]:[\\/]|\\\\|[^\s"]+\.(?:exe|cmd|bat|com)(?:["\s]|$))', re.I)
_WINDOWS_PROGRAM = re.compile(r'^[A-Za-z]:[\\/].*\.(?:exe|cmd|bat|com)$', re.I)


def executable_name(command: str | None) -> str:
    """Normalize Windows runner names, including drive paths and shims."""
    command = command or ""
    normalized = re.sub(r"^[A-Za-z]:", "", command.replace("\\", "/"))
    name = normalized.rsplit("/", 1)[-1]
    stem, dot, suffix = name.rpartition(".")
    if dot and suffix.casefold() in {"exe", "cmd", "bat", "com"}:
        return stem.casefold()
    return name.casefold() if "\\" in command or re.match(r"^[A-Za-z]:", command) else name


def windows_argv(line: str, *, strict: bool = False) -> tuple[str, ...]:
    """Microsoft CRT argument quoting: backslashes only escape double quotes.

    This is an argv tokenizer, not cmd.exe/PowerShell syntax. Single quotes,
    percent signs and shell metacharacters are literal. Unclosed double
    quotes consume the rest like the CRT, unless a config requests strict
    parsing. No variable expansion, command substitution or execution occurs.
    """
    if not isinstance(line, str) or "\0" in line:
        raise ValueError("invalid Windows command line")
    result: list[str] = []
    i = 0
    while i < len(line):
        while i < len(line) and line[i] in " \t":
            i += 1
        if i == len(line):
            break
        token: list[str] = []
        quoted = False
        while i < len(line) and (quoted or line[i] not in " \t"):
            slashes = 0
            while i < len(line) and line[i] == "\\":
                slashes += 1
                i += 1
            if i < len(line) and line[i] == '"':
                token.append("\\" * (slashes // 2))
                if slashes % 2:
                    token.append('"')
                elif quoted and i + 1 < len(line) and line[i + 1] == '"':
                    token.append('"')
                    i += 1
                else:
                    quoted = not quoted
                i += 1
            else:
                token.append("\\" * slashes)
                if i < len(line) and (quoted or line[i] not in " \t"):
                    token.append(line[i])
                    i += 1
        if quoted and strict:
            raise ValueError("unterminated Windows command quote")
        result.append("".join(token))
    return tuple(result)


def split_command(command: str | None, args: tuple[str, ...], *,
                  separated: bool = False, windows: bool = False) -> tuple[str | None, tuple[str, ...]]:
    """Explicit argv stays argv; legacy whole-line declarations are tokenized.

    A bare absolute Windows executable path can contain spaces. Quoted paths
    and lines with arguments use Windows quoting when the source is Windows
    or the executable spelling identifies it. Shell wrappers remain opaque.
    """
    if not command or separated or args:
        return command, args
    if (_WINDOWS_PROGRAM.fullmatch(command) and '"' not in command
            and not re.search(r"\.(?:exe|cmd|bat|com)\s+", command, re.I)):
        return command, args
    if not any(ch.isspace() for ch in command.strip()) and '"' not in command:
        return command, args
    try:
        parts = windows_argv(command, strict=True) if windows or _WINDOWS_LINE.match(command) else tuple(shlex.split(command))
    except ValueError:
        # Never put command text (which may hold a secret) in diagnostics.
        raise ValueError("invalid command quoting") from None
    return (parts[0], parts[1:]) if parts else (None, ())
