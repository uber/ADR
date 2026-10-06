"""Bounded, local artifact identities. Never execute, import, or download a target.

These recognizers deliberately do not interpret a general shell or emulate a
package resolver. Unresolved evidence is not an allow verdict or a clean scan.
"""

from __future__ import annotations

import configparser
import hashlib
import io
import json
import os
import re
import shlex
import stat
import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .policy import PATH_KEYS, SHELL_TOOLS, event_fields, literal_shell_files, resolve_path
from .threat_feed import normalize_endpoint, normalize_package_name, normalize_registry

READ_TOOLS = {"read", "read_file", "view"}
_ASSIGNMENT = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)=(.*)", re.S)
_PYTHON = re.compile(r"python(?:[23](?:\.\d+)?)?")
_PIP = re.compile(r"pip(?:[23](?:\.\d+)?)?")
_NPM_VERSION = re.compile(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?")
_PYPI_VERSION = re.compile(r"[0-9][0-9A-Za-z.!+_-]*")


@dataclass(frozen=True)
class Candidate:
    subject: dict
    location: str
    label: str


@dataclass
class Evidence:
    candidates: list[Candidate] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)

    def extend(self, other: Evidence):
        self.candidates.extend(other.candidates)
        self.unresolved.extend(code for code in other.unresolved if code not in self.unresolved)
        return self


@dataclass
class IdentityBudget:
    max_file_bytes: int = 8 * 1024 * 1024
    max_total_bytes: int = 16 * 1024 * 1024
    max_config_bytes: int = 256 * 1024
    max_files: int = 64
    seconds: float = 1.5
    consumed: int = 0
    files: int = 0
    started: float = field(default_factory=time.monotonic)
    unresolved: list[str] = field(default_factory=list)

    def check(self):
        if time.monotonic() - self.started > self.seconds or self.consumed > self.max_total_bytes:
            raise ValueError("identity_budget")

    def admit(self):
        self.check()
        self.files += 1
        if self.files > self.max_files:
            raise ValueError("identity_budget")


def _read_regular(path: Path, budget: IdentityBudget, maximum: int) -> bytes:
    budget.admit()
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise ValueError("unsupported_file")
        chunks, size = [], 0
        while True:
            budget.check()
            chunk = handle.read(min(64 * 1024, maximum + 1 - size))
            if not chunk:
                break
            size += len(chunk)
            budget.consumed += len(chunk)
            if size > maximum:
                raise ValueError("unsupported_file")
            chunks.append(chunk)
        after = os.fstat(handle.fileno())
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if size != before.st_size or any(getattr(before, key) != getattr(after, key) for key in fields):
            raise ValueError("changed_file")
        budget.check()
        return b"".join(chunks)


def _read_configuration(path: Path, budget: IdentityBudget) -> bytes:
    """Allow ordinary dotfile links without weakening private ADR state reads."""
    budget.check()
    link_before = path.lstat()
    resolved = path.resolve(strict=True)
    target_before = resolved.lstat()
    raw = _read_regular(resolved, budget, budget.max_config_bytes)
    target_after = resolved.lstat()
    link_after = path.lstat()
    fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
    if path.resolve(strict=True) != resolved or any(
        getattr(before, key) != getattr(after, key)
        for before, after in ((link_before, link_after), (target_before, target_after))
        for key in fields
    ):
        raise ValueError("changed_config")
    budget.check()
    return raw


def inspect_file(path, *, skill=False, budget=None) -> Evidence:
    """Hash all bytes of one referenced regular file; no directory recursion."""
    budget = budget or IdentityBudget()
    try:
        # A caller flag cannot turn an arbitrary file into a skill manifest.
        skill = Path(path).name == "SKILL.md"
        path = Path(path).expanduser().resolve(strict=True)
        raw = _read_regular(path, budget, budget.max_file_bytes)
        digest = hashlib.sha256(raw).hexdigest()
        candidates = [Candidate({"kind": "file_sha256", "sha256": digest}, str(path), path.name)]
        if skill:
            candidates.append(Candidate(
                {"kind": "skill_sha256", "sha256": digest}, str(path), path.parent.name,
            ))
        return Evidence(candidates)
    except (OSError, ValueError, RuntimeError):
        return Evidence(unresolved=["file_unresolved"])


def _json(raw: bytes, *, comments=False):
    text = raw.decode("utf-8")
    if comments:
        # Remove comments only outside JSON strings; preserve line boundaries.
        out, index, quoted, escaped = [], 0, False, False
        while index < len(text):
            char = text[index]
            if quoted:
                out.append(char)
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
                out.append(char)
            elif text.startswith("//", index):
                end = text.find("\n", index)
                index = len(text) if end < 0 else end
                out.append("\n")
                continue
            elif text.startswith("/*", index):
                end = text.find("*/", index + 2)
                if end < 0:
                    raise ValueError("invalid_config")
                out.append(" ")
                index = end + 2
                continue
            else:
                out.append(char)
            index += 1
        text = "".join(out)
        # JSONC trailing commas, again only outside strings.
        out, index, quoted, escaped = [], 0, False, False
        while index < len(text):
            char = text[index]
            if not quoted and char == ",":
                following = index + 1
                while following < len(text) and text[following].isspace():
                    following += 1
                if following < len(text) and text[following] in "]}":
                    index += 1
                    continue
            out.append(char)
            if escaped:
                escaped = False
            elif quoted and char == "\\":
                escaped = True
            elif char == '"':
                quoted = not quoted
            index += 1
        text = "".join(out)

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate_config_key")
            result[key] = value
        return result

    def reject(_):
        raise ValueError("invalid_config")

    result = json.loads(text, object_pairs_hook=pairs, parse_constant=reject)
    pending = [(result, 0)]
    while pending:
        value, depth = pending.pop()
        if depth > 32:
            raise ValueError("config_depth")
        if isinstance(value, dict):
            pending.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            pending.extend((item, depth + 1) for item in value)
    return result


def _config(path: Path, budget: IdentityBudget):
    raw = _read_configuration(path, budget)
    value = tomllib.loads(raw.decode()) if path.suffix == ".toml" else _json(
        raw, comments=path.suffix == ".jsonc",
    )
    if not isinstance(value, dict):
        raise ValueError("invalid_config")
    return value


def configuration_files(harness: str, cwd: str) -> list[Path]:
    """Known user/project files only; these are not a recursive device scan."""
    directory = Path(cwd)
    if not directory.is_absolute() or len(directory.parents) > 24:
        raise ValueError("config_scope")
    roots = [directory, *directory.parents]
    home = Path.home()
    if harness == "claude":
        files = [home / ".claude.json", *(root / ".mcp.json" for root in roots)]
    elif harness == "codex":
        from .hooks import configuration_path

        files = [configuration_path("codex").parent / "config.toml",
                 *(root / ".codex/config.toml" for root in roots)]
    elif harness == "opencode":
        config_home = Path(os.environ.get("XDG_CONFIG_HOME", str(home / ".config")))
        files = [root / name for root in [config_home / "opencode", *roots]
                 for name in ("opencode.json", "opencode.jsonc")]
    elif harness == "copilot":
        files = [home / ".copilot/mcp-config.json"]
    else:
        raise ValueError("unsupported_harness")
    return list(dict.fromkeys(files))


def read_mcp_configurations(harness, cwd, *, budget=None):
    """Return [(alias, definition, config_path, scope)], plus closed error codes."""
    budget = budget or IdentityBudget()
    records, unresolved = [], []
    try:
        files = configuration_files(harness, cwd)
    except ValueError:
        return [], ["config_scope"]
    key = {"claude": "mcpServers", "codex": "mcp_servers", "opencode": "mcp",
           "copilot": "mcpServers"}[harness]
    for path in files:
        try:
            if not path.exists() and not path.is_symlink():
                continue
            data = _config(path, budget)
            blocks = [(data.get(key, {}), "user" if path in files[:1] else "project")]
            if harness == "claude":
                projects = data.get("projects", {})
                if not isinstance(projects, dict):
                    raise ValueError("invalid_config")
                for root in (Path(cwd), *Path(cwd).parents):
                    project = projects.get(str(root), {})
                    if not isinstance(project, dict):
                        raise ValueError("invalid_config")
                    blocks.append((project.get(key, {}), "local"))
            for block, scope in blocks:
                if not isinstance(block, dict) or len(block) > 512:
                    raise ValueError("invalid_config")
                for alias, definition in block.items():
                    if not isinstance(alias, str) or not isinstance(definition, dict):
                        raise ValueError("invalid_config")
                    records.append((alias, definition, path, scope))
        except (OSError, ValueError, TypeError, RuntimeError):
            unresolved.append("config_unresolved")
    return records, list(dict.fromkeys(unresolved))


def configured_mcp_definitions(harness, cwd, state_dir, *, budget=None, diagnostics=None):
    """Scan adapter: no ambiguous alias is represented as an effective live server."""
    del state_dir
    budget = budget or IdentityBudget()
    records, errors = read_mcp_configurations(harness, cwd, budget=budget)
    aliases = [record[0] for record in records]
    if len(aliases) != len(set(aliases)):
        errors.append("mcp_definition_conflict")
    budget.unresolved.extend(code for code in errors if code not in budget.unresolved)
    if diagnostics is not None:
        diagnostics.extend(code for code in errors if code not in diagnostics)
    return [(alias, definition, path) for alias, definition, path, _ in records]


def skill_roots(harness, cwd):
    """Explicit known skill directories only; callers own bounded enumeration."""
    home, directory = Path.home(), Path(cwd)
    if not directory.is_absolute() or len(directory.parents) > 24:
        return []
    roots = []
    for root in (directory, *directory.parents):
        roots.append(root)
        if (root / ".git").exists():
            break
    if harness == "codex":
        codex_home = Path(os.environ.get("CODEX_HOME", str(home / ".codex")))
        locations = [home / ".agents/skills", codex_home / "skills",
                     Path("/etc/codex/skills")]
        locations.extend(root / ".agents/skills" for root in roots)
    elif harness == "claude":
        locations = [home / ".claude/skills", *(root / ".claude/skills" for root in roots)]
    elif harness == "opencode":
        config_home = Path(os.environ.get("XDG_CONFIG_HOME", str(home / ".config")))
        locations = [config_home / "opencode/skills", home / ".claude/skills", home / ".agents/skills"]
        locations.extend(root / surface / "skills" for root in roots
                         for surface in (".opencode", ".claude", ".agents"))
    elif harness == "copilot":
        locations = [home / ".copilot/skills", *(root / ".github/skills" for root in roots)]
    else:
        return []
    return list(dict.fromkeys(locations))


def _skill_name(raw: bytes):
    """Only a simple scalar frontmatter name is resolved, never executable YAML."""
    head = raw[:8192].decode("utf-8")
    if not head.startswith("---\n"):
        raise ValueError("skill_metadata_unresolved")
    parts = head.split("---", 2)
    if len(parts) != 3:
        raise ValueError("skill_metadata_unresolved")
    frontmatter = parts[1]
    matches = re.findall(r"(?m)^name:\s*([^\r\n]+)\s*$", frontmatter)
    if len(matches) != 1:
        raise ValueError("skill_metadata_unresolved")
    name = matches[0].strip()
    if name[:1] in ("'", '"'):
        if name[-1:] != name[:1]:
            raise ValueError("skill_metadata_unresolved")
        name = name[1:-1]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", name):
        raise ValueError("skill_metadata_unresolved")
    return name


def _skill_call(arguments, harness, cwd, budget):
    for key in PATH_KEYS:
        if arguments.get(key) is not None:
            try:
                path = resolve_path(arguments[key], cwd)
                if path.name != "SKILL.md":
                    return Evidence(unresolved=["skill_path_unresolved"])
                return inspect_file(path, skill=True, budget=budget)
            except (ValueError, OSError, RuntimeError):
                return Evidence(unresolved=["skill_path_unresolved"])
    name = arguments.get("skill", arguments.get("name"))
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", name):
        return Evidence(unresolved=["skill_name_unresolved"])
    matches, seen, count = [], set(), 0
    try:
        for root in skill_roots(harness, cwd):
            if not root.exists():
                continue
            with os.scandir(root) as entries:
                for entry in entries:
                    budget.check()
                    count += 1
                    if count > 128:
                        raise ValueError("skill_budget")
                    if not entry.is_dir(follow_symlinks=True) or entry.name.startswith("."):
                        continue
                    manifest = Path(entry.path) / "SKILL.md"
                    if not manifest.exists() and not manifest.is_symlink():
                        continue
                    path = manifest.resolve(strict=True)
                    if path in seen:
                        continue
                    seen.add(path)
                    raw = _read_regular(path, budget, budget.max_file_bytes)
                    declared = _skill_name(raw)
                    if declared == name and (harness != "opencode" or entry.name == declared):
                        digest = hashlib.sha256(raw).hexdigest()
                        matches.append(Evidence([
                            Candidate({"kind": "file_sha256", "sha256": digest}, str(path), path.name),
                            Candidate({"kind": "skill_sha256", "sha256": digest}, str(path), name),
                        ]))
        if len(matches) == 1:
            return matches[0]
        return Evidence(unresolved=["skill_name_ambiguous" if matches else "skill_name_unresolved"])
    except (OSError, ValueError, RuntimeError, UnicodeError):
        return Evidence(unresolved=["skill_resolution_incomplete"])


def _segments(command: str) -> list[str]:
    """Split only literal ;/&& outside quotes. All other shell grammar is unknown."""
    if not isinstance(command, str) or len(command.encode()) > 16384 or "\x00" in command:
        raise ValueError("shell_unresolved")
    quote, escaped, start, index = None, False, 0, 0
    segments = []
    while index < len(command):
        char = command[index]
        if escaped:
            escaped = False
        elif char == "\\" and quote != "'":
            escaped = True
        elif quote:
            if char == quote:
                quote = None
            elif quote == '"' and char in "$`":
                raise ValueError("shell_unresolved")
        elif char in "'\"":
            quote = char
        elif char == "#" and (index == 0 or command[index - 1].isspace()):
            command = command[:index]
            break
        elif char == ";" or command.startswith("&&", index):
            segments.append(command[start:index])
            index += int(char == "&")
            start = index + 1
        elif char in "\n\r$`|<>(){}*?[]" or char == "&":
            raise ValueError("shell_unresolved")
        index += 1
    if quote or escaped:
        raise ValueError("shell_unresolved")
    segments.append(command[start:])
    if len(segments) > 16 or any(not part.strip() for part in segments[:-1]):
        raise ValueError("shell_unresolved")
    return [part.strip() for part in segments if part.strip()]


def _registry(ecosystem, name, cwd, env, explicit, extra, budget, *, uv=False,
              uv_tool=False, npm_global=False):
    """Resolve only unambiguous registry settings; never query a registry."""
    if extra:
        raise ValueError("registry_unresolved")
    if ecosystem == "npm" and explicit is not None and not name.startswith("@"):
        # npm's explicit registry is authoritative for an unscoped package.
        # Lower-priority config/prefix values cannot change it; reading them
        # would unnecessarily lose this identity on a symlink, parse error,
        # or unrelated npm setting. Scoped registry mappings are different
        # keys and still require the checks below.
        return normalize_registry(ecosystem, explicit)
    values = [explicit] if explicit else []
    home = Path(env.get("HOME") or Path.home())

    def config_path(value):
        if (not isinstance(value, (str, Path)) or "$" in str(value)
                or str(value).startswith("__ADR_")):
            raise ValueError("registry_unresolved")
        path = Path(value)
        if str(path).startswith("~/"):
            path = home / str(path)[2:]
        return path if path.is_absolute() else Path(cwd) / path

    if ecosystem == "npm":
        scoped = name.split("/", 1)[0] + ":registry" if name.startswith("@") else None
        if any(env.get(key) for key in ("npm_config_prefix", "NPM_CONFIG_PREFIX")):
            raise ValueError("registry_unresolved")
        for key in ("npm_config_registry", "NPM_CONFIG_REGISTRY"):
            if env.get(key) and not explicit:
                values.append(env[key])
        paths = [config_path(env.get("NPM_CONFIG_USERCONFIG") or env.get("npm_config_userconfig")
                             or home / ".npmrc"),
                 config_path(env.get("NPM_CONFIG_GLOBALCONFIG") or env.get("npm_config_globalconfig")
                             or "/etc/npmrc"),
                 Path("/opt/homebrew/etc/npmrc"), Path("/usr/local/etc/npmrc")]
        global_setting = env.get("npm_config_global", env.get("NPM_CONFIG_GLOBAL", "false"))
        if global_setting not in ("false", "true", "0", "1"):
            raise ValueError("registry_unresolved")
        if not npm_global and global_setting not in ("true", "1"):
            paths.extend(root / ".npmrc" for root in [Path(cwd), *Path(cwd).parents])
        for path in dict.fromkeys(paths):
            if not path.exists() and not path.is_symlink():
                continue
            text = _read_configuration(path, budget).decode()
            parser = configparser.ConfigParser(interpolation=None, strict=True, delimiters=("=",))
            parser.read_string("[npm]\n" + text)
            scope_value = parser["npm"].get(scoped) if scoped else None
            value = scope_value or (parser["npm"].get("registry") if not explicit else None)
            if value:
                values.append(value)
    else:
        unknown_keys = ("UV_EXTRA_INDEX_URL", "UV_INDEX", "UV_NO_INDEX", "UV_FIND_LINKS",
                        "UV_NO_CONFIG") if uv else ("PIP_EXTRA_INDEX_URL", "PIP_NO_INDEX", "PIP_FIND_LINKS")
        if any(env.get(key) for key in unknown_keys):
            raise ValueError("registry_unresolved")
        keys = ("UV_DEFAULT_INDEX", "UV_INDEX_URL") if uv else ("PIP_INDEX_URL",)
        if not explicit:
            values.extend(env[key] for key in keys if env.get(key))
        config_file = env.get("PIP_CONFIG_FILE")
        config_home = config_path(env.get("XDG_CONFIG_HOME") or home / ".config")
        paths = [] if uv or config_file == os.devnull else [
            Path("/etc/pip.conf"), config_home / "pip/pip.conf", home / ".pip/pip.conf",
            home / "Library/Application Support/pip/pip.conf",
        ]
        if config_file and config_file != os.devnull and not uv:
            paths.append(config_path(config_file))
        if env.get("VIRTUAL_ENV") and not uv:
            paths.append(config_path(env["VIRTUAL_ENV"]) / "pip.conf")
        for path in dict.fromkeys(paths):
            if not path.exists() and not path.is_symlink():
                continue
            parser = configparser.ConfigParser(interpolation=None, strict=True)
            parser.read_string(_read_configuration(path, budget).decode())
            for section in ("global", "install"):
                if not parser.has_section(section):
                    continue
                if any(parser[section].get(key) for key in ("extra-index-url", "no-index", "find-links")):
                    raise ValueError("registry_unresolved")
                if parser[section].get("index-url") and not explicit:
                    values.append(parser[section]["index-url"])
        if uv:
            paths = [config_home / "uv/uv.toml", Path("/etc/uv/uv.toml")]
            config_dirs = env.get("XDG_CONFIG_DIRS", "/etc/xdg").split(":")
            if len(config_dirs) > 8:
                raise ValueError("registry_unresolved")
            paths.extend(config_path(root) / "uv/uv.toml" for root in config_dirs if root)
            if not uv_tool:
                paths.extend(root / filename for root in [Path(cwd), *Path(cwd).parents]
                             for filename in ("uv.toml", "pyproject.toml"))
            if env.get("UV_CONFIG_FILE"):
                paths = [config_path(env["UV_CONFIG_FILE"])]
            for path in paths:
                if not path.exists() and not path.is_symlink():
                    continue
                config = _config(path, budget)
                if path.name == "pyproject.toml":
                    config = config.get("tool", {}).get("uv", {})
                sections = [config]
                if not uv_tool:
                    sections.append(config.get("pip", {}))
                for section in sections:
                    if not isinstance(section, dict):
                        raise ValueError("registry_unresolved")
                    if any(key in section for key in (
                        "index", "extra-index-url", "sources", "find-links", "no-index",
                    )):
                        raise ValueError("registry_unresolved")
                    if not explicit:
                        values.extend(
                            section[key] for key in ("index-url", "default-index") if section.get(key)
                        )
    normalized = {normalize_registry(ecosystem, value) for value in values}
    if len(normalized) > 1:
        raise ValueError("registry_unresolved")
    return next(iter(normalized), "https://registry.npmjs.org" if ecosystem == "npm" else "https://pypi.org")


def _package(spec, ecosystem):
    if ecosystem == "npm":
        if "@npm:" in spec:
            _, spec = spec.split("@npm:", 1)
        # URL/VCS/file references cannot establish registry package identity.
        if ":" in spec or spec.startswith((".", "/")):
            raise ValueError("package_unresolved")
        split = spec.rfind("@")
        name, version = (spec[:split], spec[split + 1:]) if split > 0 else (spec, None)
        name = normalize_package_name("npm", name)
        version = version if version and _NPM_VERSION.fullmatch(version) else None
    else:
        if "==" in spec and "===" not in spec:
            name, version = spec.split("==", 1)
        elif re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", spec):
            name, version = spec, None
        else:
            raise ValueError("package_unresolved")
        name = normalize_package_name("pypi", name)
        version = version if version and _PYPI_VERSION.fullmatch(version) else None
    return name, version


def _package_words(words, cwd, environment, budget) -> Evidence:
    result = Evidence()
    if not words:
        return result
    executable = Path(words[0]).name
    ecosystem, mode, uv, uv_tool = None, "", False, False
    if executable == "npm" and len(words) > 1 and words[1] in ("install", "i", "add", "exec", "x"):
        ecosystem, mode, args = "npm", words[1], words[2:]
    elif executable == "npx":
        ecosystem, mode, args = "npm", "npx", words[1:]
    elif _PIP.fullmatch(executable) and len(words) > 1 and words[1] == "install":
        ecosystem, mode, args = "pypi", "install", words[2:]
    elif _PYTHON.fullmatch(executable) and words[1:4] == ["-m", "pip", "install"]:
        ecosystem, mode, args = "pypi", "install", words[4:]
    elif executable == "uv" and words[1:3] in (["pip", "install"], ["tool", "run"], ["tool", "install"]):
        ecosystem, mode, args, uv = "pypi", "uvrun" if words[2] == "run" else "install", words[3:], True
        uv_tool = words[1] == "tool"
    elif executable == "uvx":
        ecosystem, mode, args, uv = "pypi", "uvrun", words[1:], True
        uv_tool = True
    else:
        return result
    packages, registry, extra, index = [], None, False, 0
    zero = {
        "-y", "--yes", "--no", "--ignore-scripts", "--no-audit", "--no-fund",
        "-D", "--save-dev", "-E", "--save-exact", "-g", "--global", "--no-save",
        "-U", "--upgrade", "--no-deps", "--pre", "--system", "--user", "--quiet", "-q",
        "--disable-pip-version-check", "--break-system-packages", "--no-cache",
    }
    try:
        while index < len(args):
            word = args[index]
            option, equals, value = word.partition("=")
            if word == "--":
                if mode in ("exec", "x", "npx", "uvrun"):
                    if not packages and index + 1 < len(args):
                        packages.append(args[index + 1])
                    break
                packages.extend(args[index + 1:])
                break
            if word in zero:
                index += 1
                continue
            if option in ("--registry", "--index-url", "-i", "--default-index",
                          "--extra-index-url", "--index", "--find-links", "-f",
                          "--package", "-p", "--from"):
                if not equals:
                    index += 1
                    if index >= len(args):
                        raise ValueError("package_unresolved")
                    value = args[index]
                if option in ("--package", "-p", "--from"):
                    packages.append(value)
                elif option in ("--extra-index-url", "--index", "--find-links", "-f"):
                    extra = True
                else:
                    if registry is not None and registry != value:
                        raise ValueError("registry_unresolved")
                    registry = value
                index += 1
                continue
            if word.startswith("-"):
                raise ValueError("package_unresolved")
            if mode in ("exec", "x", "npx", "uvrun"):
                if not packages:
                    packages.append(word)
                if mode in ("exec", "x"):
                    # npm exec consumes its options even after a positional
                    # command; npx/uvx pass later options to that command.
                    index += 1
                    continue
                break  # Remaining arguments belong to the invoked program.
            packages.append(word)
            index += 1
        if not packages or len(packages) > 32:
            raise ValueError("package_unresolved")
        for spec in packages:
            try:
                name, version = _package(spec, ecosystem)
                source = _registry(
                    ecosystem, name, cwd, environment, registry, extra, budget,
                    uv=uv, uv_tool=uv_tool, npm_global="-g" in args or "--global" in args,
                )
                result.candidates.append(Candidate({
                    "kind": "package", "ecosystem": ecosystem, "name": name,
                    "version": version, "registry": source,
                }, str(cwd), f"{name}@{version or 'unresolved'}"))
                if version is None:
                    result.unresolved.append("package_version_unresolved")
            except (OSError, ValueError, configparser.Error, AttributeError, TypeError):
                result.unresolved.append("package_unresolved")
    except ValueError:
        result.unresolved.append("package_unresolved")
    return result


def _literal_sed_files(command, cwd):
    """Only numeric address + p, -n, and literal operands; no sed interpreter."""
    stream = io.StringIO(command)
    lexer = shlex.shlex(stream, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    words, ends = [], []
    try:
        while True:
            word = lexer.get_token()
            if word is None:
                break
            words.append(word)
            ends.append(stream.tell())
            if len(words) > 128:
                return []
    except ValueError:
        return []
    if len(words) < 4 or Path(words[0]).name != "sed" or words[1] != "-n":
        return []
    index, options_ended = 2, False
    if words[index] == "--":
        options_ended = True
        index += 1
    if index >= len(words) or not re.fullmatch(r"[1-9][0-9]*(?:,[1-9][0-9]*)?p", words[index]):
        return []
    index += 1
    if index < len(words) and words[index] == "--":
        options_ended = True
        index += 1
    if index == len(words) or (not options_ended and any(word.startswith("-") for word in words[index:])):
        return []
    # Reuse the existing read recognizer's exact quoted/unquoted tilde handling.
    operands = command[ends[index - 1]:]
    return literal_shell_files({"command": "cat -- " + operands}, cwd)


def inspect_command(command, cwd, *, budget=None, environment=None, _depth=0) -> Evidence:
    budget = budget or IdentityBudget()
    environment = dict(os.environ if environment is None else environment)
    result = Evidence()
    try:
        if _depth > 2:
            raise ValueError("shell_unresolved")
        segments = _segments(command)
        opaque_prefix = False
        for segment in segments:
            if opaque_prefix:
                raise ValueError("shell_sequence_unresolved")
            words = shlex.split(segment, posix=True)
            if not words or len(words) > 128:
                raise ValueError("shell_unresolved")
            original_words = tuple(words)
            local_env = dict(environment)
            while words and _ASSIGNMENT.fullmatch(words[0]):
                match = _ASSIGNMENT.fullmatch(words.pop(0))
                local_env[match[1]] = match[2]
            if not words:
                # Shell assignments are inherited by child programs only if
                # that variable was already exported. A new bare assignment
                # must not turn a public install into a private-registry one.
                environment.update((key, value) for key, value in local_env.items() if key in environment)
                continue
            if words[0] == "export":
                if any(not _ASSIGNMENT.fullmatch(word) for word in words[1:]):
                    raise ValueError("shell_unresolved")
                for word in words[1:]:
                    match = _ASSIGNMENT.fullmatch(word)
                    environment[match[1]] = match[2]
                continue
            if Path(words[0]).name == "env":
                words.pop(0)
                if words and words[0] in ("-i", "--ignore-environment"):
                    local_env.clear()
                    words.pop(0)
                if words and words[0] == "--":
                    words.pop(0)
                while words and _ASSIGNMENT.fullmatch(words[0]):
                    match = _ASSIGNMENT.fullmatch(words.pop(0))
                    local_env[match[1]] = match[2]
            if words and words[0] == "command":
                words.pop(0)
                if words and words[0] == "--":
                    words.pop(0)
            if not words or words[0].startswith("-"):
                raise ValueError("shell_unresolved")
            executable = Path(words[0]).name
            if executable in ("sh", "bash", "zsh", "dash") and len(words) == 3 and words[1] in ("-c", "-lc"):
                result.extend(inspect_command(
                    words[2], cwd, budget=budget, environment=local_env, _depth=_depth + 1,
                ))
                opaque_prefix = True
                continue
            if words[0] == "cd" and len(words) == 2:
                if Path(original_words[0]).name == "env" or words[1].startswith("~"):
                    raise ValueError("shell_sequence_unresolved")
                directory = resolve_path(words[1], cwd)
                if not directory.is_dir():
                    raise ValueError("shell_sequence_unresolved")
                cwd = str(directory)
                continue
            result.extend(_package_words(words, cwd, local_env, budget))
            read_command = segment if tuple(words) == original_words else shlex.join(words)
            sed_files = _literal_sed_files(read_command, cwd)
            for path in [*literal_shell_files({"command": read_command}, cwd), *sed_files]:
                result.extend(inspect_file(path, budget=budget))
            if ("/" in words[0] and Path(words[0]).is_absolute()) or words[0].startswith("./"):
                result.extend(inspect_file(resolve_path(words[0], cwd), budget=budget))
            if (_PYTHON.fullmatch(executable) or executable in ("node", "sh", "bash")) and len(words) > 1:
                if words[1].startswith("~"):
                    result.unresolved.append("script_path_unresolved")
                elif not words[1].startswith("-"):
                    result.extend(inspect_file(resolve_path(words[1], cwd), budget=budget))
            # An earlier opaque program may change registry files or the shell
            # environment. Do not classify a later install using stale state.
            opaque_prefix = not sed_files and words[0] not in (
                "echo", "printf", "pwd", "true", "false", ":", "cat", "head", "tail", "ls",
            )
    except (ValueError, OSError, RuntimeError):
        result.unresolved.append("shell_unresolved")
    return result


def inspect_mcp_definition(definition, config_path, cwd, *, budget=None, environment=None) -> Evidence:
    budget = budget or IdentityBudget()
    result = Evidence()
    try:
        if not isinstance(definition, dict):
            raise ValueError("mcp_unresolved")
        if definition.get("enabled") is False or definition.get("disabled") is True:
            return result
        if definition.get("url"):
            if definition.get("command") or definition.get("args"):
                raise ValueError("mcp_unresolved")
            if definition.get("type") not in (None, "http", "sse", "remote", "streamable-http",
                                              "streamable_http"):
                raise ValueError("mcp_unresolved")
            if not isinstance(definition["url"], str) or "$" in definition["url"]:
                raise ValueError("mcp_unresolved")
            url = normalize_endpoint(definition["url"])
            return Evidence([Candidate({"kind": "mcp_endpoint", "url": url},
                                       str(config_path), "Configured MCP endpoint")])
        command = definition.get("command")
        if definition.get("type") not in (None, "stdio", "local"):
            raise ValueError("mcp_unresolved")
        if not isinstance(definition.get("args", []), list):
            raise ValueError("mcp_unresolved")
        if isinstance(command, list) and definition.get("args"):
            raise ValueError("mcp_unresolved")
        words = command if isinstance(command, list) else [command, *definition.get("args", [])]
        if not words or len(words) > 128 or any(not isinstance(word, str) or not word for word in words):
            raise ValueError("mcp_unresolved")
        if any("$" in word or "\x00" in word for word in words):
            raise ValueError("mcp_unresolved")
        if "cwd" in definition:
            if not isinstance(definition["cwd"], str) or not Path(definition["cwd"]).is_absolute():
                raise ValueError("mcp_unresolved")
            cwd = str(resolve_path(definition["cwd"], cwd))
        env = dict(os.environ if environment is None else environment)
        overrides = definition.get("env", definition.get("environment", {}))
        if not isinstance(overrides, dict) or any(
            not isinstance(key, str) or not isinstance(value, str) or "$" in value
            for key, value in overrides.items()
        ):
            raise ValueError("mcp_unresolved")
        env.update(overrides)
        forwarded = definition.get("env_vars", [])
        if not isinstance(forwarded, list) or any(not isinstance(key, str) for key in forwarded):
            raise ValueError("mcp_unresolved")
        for key in forwarded:
            if key not in env:
                env[key] = "__ADR_UNKNOWN_ENVIRONMENT_VALUE__"
        result.extend(inspect_command(shlex.join(words), cwd, budget=budget, environment=env))
    except (OSError, ValueError, TypeError, AttributeError):
        result.unresolved.append("mcp_unresolved")
    return result


def _mcp_call(event, harness, cwd, budget) -> Evidence:
    name = event.get("tool_name", event.get("toolName", ""))
    provenance = event.get("mcp_server")
    if not isinstance(name, str):
        return Evidence()
    records, unresolved = read_mcp_configurations(harness, cwd, budget=budget)
    if unresolved:
        return Evidence(unresolved=unresolved)
    if provenance is not None:
        if not isinstance(provenance, dict) or provenance.get("source") not in ("user", "project", "local"):
            return Evidence(unresolved=["mcp_provenance_unresolved"])
        records = [record for record in records if record[0] == provenance.get("name")
                   and record[3] == provenance["source"]]
    else:
        records = [record for record in records if name.startswith(f"mcp__{record[0]}__")
                   or (harness == "opencode" and name.startswith(record[0] + "_"))]
    if not records:
        return Evidence(unresolved=["mcp_provenance_unresolved"])
    # Even equal declarations can have different relative roots/environment.
    # Do not implement guessed harness precedence for conflicting sources.
    if len(records) != 1:
        return Evidence(unresolved=["mcp_definition_conflict"])
    _, definition, path, _ = records[0]
    return inspect_mcp_definition(definition, path, cwd, budget=budget)


def identify_event(event, harness, state_dir, *, budget=None, environment=None) -> Evidence:
    """Extract evidence from a supported pending operation; never execute it."""
    del state_dir  # Kept in the public interface for harness-specific future sources.
    budget = budget or IdentityBudget()
    tool, arguments, cwd, _ = event_fields(event, harness)
    result = Evidence()
    name = tool.lower()
    if name in READ_TOOLS:
        for key in PATH_KEYS:
            if arguments.get(key) is not None:
                try:
                    result.extend(inspect_file(resolve_path(arguments[key], cwd), budget=budget))
                except (ValueError, OSError, RuntimeError):
                    result.unresolved.append("file_unresolved")
    elif name == "skill":
        result.extend(_skill_call(arguments, harness, cwd, budget))
    elif name in SHELL_TOOLS:
        try:
            directory = resolve_path(arguments.get("workdir", arguments.get("cwd", cwd)), cwd)
            result.extend(inspect_command(arguments.get("command", arguments.get("cmd")),
                                          str(directory), budget=budget, environment=environment))
        except (ValueError, OSError, RuntimeError):
            result.unresolved.append("shell_unresolved")
    elif tool.startswith("mcp__") or event.get("mcp_server") or harness == "opencode":
        result.extend(_mcp_call(event, harness, cwd, budget))
    return result
