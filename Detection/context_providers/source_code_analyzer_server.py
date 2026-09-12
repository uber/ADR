#!/usr/bin/env python3
"""
ADR Source Code Context Provider

Provides MCP server source code for reasoning-based threat analysis.
No pre-analysis or cheating metadata - just clean source code and basic info.
"""
import ast
import codecs
import io
import logging
import os
import tokenize
from importlib.machinery import (
    BYTECODE_SUFFIXES,
    EXTENSION_SUFFIXES,
    BuiltinImporter,
    FrozenImporter,
)
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml
from mcp.server.fastmcp import FastMCP

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create MCP server instance
mcp = FastMCP('source_code_analyzer_server')

# Load source code registry
def load_source_registry() -> Dict[str, Any]:
    """Load source code registry from YAML file"""
    registry_file = Path(__file__).parent / "data" / "source_codes_registry.yaml"

    try:
        if registry_file.exists():
            with open(registry_file, 'r') as f:
                data = yaml.safe_load(f)
                logger.info(f"Loaded source registry from {registry_file}")
                return data
        else:
            logger.warning(f"Registry file not found: {registry_file}")
            return {"mcp_servers": []}
    except Exception as e:
        logger.error(f"Failed to load source registry: {e}")
        return {"mcp_servers": []}

source_registry = load_source_registry()


MAX_LOCAL_SOURCE_FILES = 24
MAX_LOCAL_SOURCE_BYTES = 240_000


def _is_within(path: Path, root: Path) -> bool:
    """Return whether a resolved path remains within the trusted server root."""

    try:
        path.resolve(strict=True).relative_to(root.resolve(strict=True))
        return True
    except (FileNotFoundError, OSError, RuntimeError, ValueError):
        return False


def _resolved_source_file(path: Path, root: Path) -> Optional[Path]:
    """Return a regular in-root source file without following symlinked input."""

    if not _is_within(path, root):
        return None
    try:
        resolved = path.resolve(strict=True)
    except (FileNotFoundError, OSError, RuntimeError):
        return None
    if resolved != Path(os.path.abspath(os.fspath(path))):
        return None
    return resolved if resolved.is_file() else None


def _has_file_with_suffixes(path: Path, suffixes: List[str]) -> bool:
    """Return whether a competing loader file exists for a module path."""

    return any(path.with_name(path.name + suffix).is_file() for suffix in suffixes)


def _runtime_import_precedes_local_source(module_name: str) -> bool:
    """Return whether Python resolves a built-in or frozen module first."""

    top_level = module_name.partition(".")[0]
    if not top_level:
        return False
    return (
        BuiltinImporter.find_spec(top_level) is not None
        or FrozenImporter.find_spec(top_level) is not None
    )


def _resolve_module_parts(
    base: Path,
    parts: List[str],
    root: Path,
) -> Tuple[List[Path], Optional[Path]]:
    """Resolve local source using Python's package-before-module precedence.

    The returned package directory is used only to resolve ``from package
    import submodule``. Native-extension and bytecode-only modules are not
    represented as Python source and block same-name ``.py`` candidates when
    Python would select them first.
    """

    files: List[Path] = []
    if not parts:
        initializer = _resolved_source_file(base / "__init__.py", root)
        if initializer is not None:
            files.append(initializer)
        return files, base if _is_within(base, root) and base.is_dir() else None

    current = base
    for index, part in enumerate(parts):
        final = index == len(parts) - 1
        package_dir = current / part
        module_stem = current / part

        # FileFinder checks a package directory before same-named module files.
        if package_dir.is_dir() and _is_within(package_dir, root):
            initializer_stem = package_dir / "__init__"
            has_extension_initializer = _has_file_with_suffixes(
                initializer_stem, EXTENSION_SUFFIXES
            )
            has_source_initializer = (package_dir / "__init__.py").is_file()
            has_bytecode_initializer = _has_file_with_suffixes(
                initializer_stem, BYTECODE_SUFFIXES
            )
            if has_extension_initializer:
                initializer = None
            else:
                initializer = _resolved_source_file(
                    package_dir / "__init__.py", root
                )
            if (
                has_extension_initializer
                or has_source_initializer
                or has_bytecode_initializer
            ):
                if has_source_initializer and initializer is None:
                    return files, None
                if initializer is not None:
                    files.append(initializer)
                if final:
                    return files, package_dir
                current = package_dir
                continue

        # Native extensions precede source modules. Source precedes bytecode.
        if _has_file_with_suffixes(module_stem, EXTENSION_SUFFIXES):
            return files, None
        module = _resolved_source_file(module_stem.with_suffix(".py"), root)
        if module is not None:
            files.append(module)
            return files, None
        if _has_file_with_suffixes(module_stem, BYTECODE_SUFFIXES):
            return files, None

        # A directory without an initializer becomes a namespace package only
        # if no same-name module loader matched above.
        if package_dir.is_dir() and _is_within(package_dir, root):
            if final:
                return files, package_dir
            current = package_dir
            continue
        return files, None

    return files, None


def _local_import_candidates(current: Path, node: ast.AST, root: Path) -> List[Path]:
    """Resolve Python imports that refer to files inside one registered server."""

    candidates: List[Path] = []
    candidate_set = set()

    def add(paths: List[Path]) -> None:
        for path in paths:
            if path not in candidate_set:
                candidates.append(path)
                candidate_set.add(path)

    if isinstance(node, ast.Import):
        for alias in node.names:
            if _runtime_import_precedes_local_source(alias.name):
                continue
            files, _ = _resolve_module_parts(
                root,
                [part for part in alias.name.split(".") if part],
                root,
            )
            add(files)
        return candidates

    if isinstance(node, ast.ImportFrom):
        module = node.module or ""
        level = int(node.level or 0)
        if level:
            base = current.parent
            for _ in range(level - 1):
                base = base.parent
        else:
            base = root

        if not _is_within(base, root):
            return candidates
        if not level and _runtime_import_precedes_local_source(module):
            return candidates

        files, package_dir = _resolve_module_parts(
            base,
            [part for part in module.split(".") if part],
            root,
        )
        add(files)
        if package_dir is not None:
            for alias in node.names:
                if alias.name == "*":
                    continue
                alias_files, _ = _resolve_module_parts(
                    package_dir,
                    [part for part in alias.name.split(".") if part],
                    root,
                )
                add(alias_files)
    return candidates


def _decode_bounded_python_source(raw_source: bytes, max_bytes: int) -> Tuple[str, bool]:
    """Decode a bounded Python source prefix without discarding invalid bytes.

    The returned text is also bounded by its UTF-8 encoded size because that is
    the representation sent to the model. The caller supplies at most one
    extra input byte to determine whether the source was truncated.
    """

    input_truncated = len(raw_source) > max_bytes
    raw_source = raw_source[:max_bytes]
    header = io.BytesIO(raw_source)

    def readline() -> bytes:
        line = header.readline()
        if input_truncated and line and not line.endswith(b"\n"):
            # detect_encoding validates header lines as UTF-8. Permit a split
            # trailing character, but still reject invalid interior bytes.
            line = codecs.getincrementaldecoder("utf-8")().decode(
                line, final=False
            ).encode("utf-8")
        return line

    encoding, _ = tokenize.detect_encoding(readline)
    # bytes.decode rejects non-text codecs with LookupError. Use a nonempty
    # probe because decoding empty bytes can bypass codec validation.
    try:
        b"\x00".decode(encoding)
    except UnicodeError:
        # A valid text codec may require more than one byte (e.g. UTF-16).
        pass
    source = codecs.getincrementaldecoder(encoding)().decode(
        raw_source, final=not input_truncated
    )
    utf8_source = source.encode("utf-8")
    output_truncated = len(utf8_source) > max_bytes
    if output_truncated:
        source = codecs.getincrementaldecoder("utf-8")().decode(
            utf8_source[:max_bytes], final=False
        )

    return source, input_truncated or output_truncated


def _collect_local_source_bundle(
    entrypoint: Path,
) -> Tuple[List[Dict[str, Any]], bool]:
    """Collect a bounded, dependency-aware source bundle for one MCP server.

    Registry paths are trusted, but import resolution is constrained to the
    entrypoint's server directory. Returned paths are relative so dataset
    directory names do not become classifier hints.
    """

    root = entrypoint.parent.resolve()
    resolved_entrypoint = _resolved_source_file(entrypoint, root)
    if resolved_entrypoint is None:
        return [], False
    pending = [resolved_entrypoint]
    seen = set()
    files: List[Dict[str, Any]] = []
    total_bytes = 0
    total_read_bytes = 0
    complete = True
    while pending:
        if len(seen) >= MAX_LOCAL_SOURCE_FILES:
            complete = False
            break
        remaining = MAX_LOCAL_SOURCE_BYTES - max(total_bytes, total_read_bytes)
        if remaining <= 0:
            complete = False
            break

        candidate = pending.pop(0)
        path = _resolved_source_file(candidate, root)
        if path is None:
            complete = False
            continue
        if path in seen:
            continue
        seen.add(path)

        try:
            with path.open("rb") as source_file:
                raw_source = source_file.read(remaining + 1)
        except OSError as exc:
            # A failed read may have consumed input before raising. Conservatively
            # stop rather than retrying other files with an uncharged budget.
            logger.warning("Unable to read Python source %s: %s", path, exc)
            complete = False
            break
        # Charge input even when decoding fails. Each attempted file permits
        # one additional lookahead byte solely for detecting truncation.
        total_read_bytes += min(len(raw_source), remaining)
        try:
            included, truncated = _decode_bounded_python_source(raw_source, remaining)
        except (LookupError, SyntaxError, UnicodeError) as exc:
            logger.warning("Unable to include Python source %s: %s", path, exc)
            complete = False
            continue

        files.append(
            {
                "path": str(path.relative_to(root)),
                "source_code": included,
                "truncated": truncated,
            }
        )
        total_bytes += len(included.encode("utf-8"))
        if truncated:
            complete = False
            break
        try:
            tree = ast.parse(included, filename=str(path))
        except (SyntaxError, ValueError):
            continue
        for node in ast.walk(tree):
            for dependency in _local_import_candidates(path, node, root):
                if dependency not in seen and dependency not in pending:
                    pending.append(dependency)
    return files, complete


def collect_local_source_files(entrypoint: Path) -> List[Dict[str, Any]]:
    """Return the source files from the bounded local dependency bundle."""

    files, _ = _collect_local_source_bundle(entrypoint)
    return files


@mcp.tool()
def get_source_code(server_names: List[str]) -> Dict[str, Any]:
    """Get the source code of MCP servers for analysis"""
    source_codes: List[Dict[str, Any]] = []

    for server_name in server_names:
        # Find server in registry
        server_info = None
        for server in source_registry.get("mcp_servers", []):
            if server.get("name") == server_name or server.get("name") == server_name.replace('-', '_'):
                server_info = server
                break

        if not server_info:
            source_codes.append({
                "server_name": server_name,
                "status": "not_found"
            })
            continue

        # Read source code
        server_path = server_info.get("path", "")
        provider_root = Path(__file__).parent.resolve()
        full_path = provider_root / server_path

        try:
            resolved_path = _resolved_source_file(full_path, provider_root)
            if resolved_path is not None:
                with tokenize.open(resolved_path) as f:
                    source_code = f.read()
                source_files, source_bundle_complete = _collect_local_source_bundle(
                    resolved_path
                )

                # Provide clean metadata without cheating indicators
                source_codes.append({
                    "server_name": server_name,
                    "status": "found",
                    "metadata": {
                        "category": server_info.get("category"),
                        "description": server_info.get("description"),
                        "capabilities": server_info.get("capabilities", [])
                    },
                    # Keep the original field for compatibility and add the
                    # dependency-aware bundle for complete source reasoning.
                    "source_code": source_code,
                    "entrypoint": resolved_path.name,
                    "source_files": source_files,
                    "source_bundle_complete": source_bundle_complete,
                })
            else:
                source_codes.append({
                    "server_name": server_name,
                    "status": "file_not_found"
                })

        except Exception as e:
            source_codes.append({
                "server_name": server_name,
                "status": "error",
                "error": str(e)
            })

    return {
        "source_codes": source_codes,
        "total_retrieved": len([s for s in source_codes if s.get("status") == "found"])
    }

@mcp.tool()
def list_mcp_servers(category: str = None) -> Dict[str, Any]:
    """List available MCP servers with basic metadata"""
    servers = source_registry.get("mcp_servers", [])
    filtered_servers = []

    for server in servers:
        if category and server.get("category", "").lower() != category.lower():
            continue

        # Provide clean metadata without cheating indicators
        filtered_servers.append({
            "name": server.get("name"),
            "category": server.get("category"),
            "description": server.get("description"),
            "capabilities": server.get("capabilities", [])
        })

    return {
        "servers": filtered_servers,
        "total_count": len(filtered_servers)
    }

@mcp.tool()
def get_server_categories() -> Dict[str, Any]:
    """Get available server categories for analysis"""
    servers = source_registry.get("mcp_servers", [])
    categories = sorted(list(set(s.get("category", "") for s in servers if s.get("category"))))

    return {
        "categories": categories,
        "total_categories": len(categories),
        "total_servers": len(servers)
    }

@mcp.tool()
def analyze_tool_capabilities(server_names: List[str]) -> Dict[str, Any]:
    """Analyze if tool capabilities match their stated business purpose"""
    analyses = []

    for server_name in server_names:
        # Find server in registry
        server_info = None
        for server in source_registry.get("mcp_servers", []):
            if server.get("name") == server_name or server.get("name") == server_name.replace('-', '_'):
                server_info = server
                break

        if not server_info:
            analyses.append({
                "server_name": server_name,
                "status": "not_found"
            })
            continue

        # Provide structured capability data for analysis
        capability_analysis = {
            "server_name": server_name,
            "category": server_info.get("category", ""),
            "description": server_info.get("description", ""),
            "capabilities": server_info.get("capabilities", []),
            "analysis_guidance": "Compare capabilities against description and category to identify scope violations or hidden functionality"
        }

        analyses.append(capability_analysis)

    return {
        "capability_analyses": analyses,
        "servers_analyzed": len(server_names)
    }

@mcp.tool()
def analyze_vulnerabilities(server_names: List[str]) -> Dict[str, Any]:
    """Analyze MCP servers for potential security vulnerabilities"""
    vulnerability_analyses = []

    for server_name in server_names:
        # Find server in registry
        server_info = None
        for server in source_registry.get("mcp_servers", []):
            if server.get("name") == server_name or server.get("name") == server_name.replace('-', '_'):
                server_info = server
                break

        if not server_info:
            vulnerability_analyses.append({
                "server_name": server_name,
                "status": "not_found"
            })
            continue

        # Provide vulnerability analysis framework
        vulnerability_analysis = {
            "server_name": server_name,
            "category": server_info.get("category", ""),
            "capabilities": server_info.get("capabilities", []),
            "analysis_guidance": "Review server capabilities and source code for potential security vulnerabilities, privilege escalation, or data exposure risks"
        }

        vulnerability_analyses.append(vulnerability_analysis)

    return {
        "vulnerability_analyses": vulnerability_analyses,
        "servers_analyzed": len(server_names)
    }

@mcp.tool()
def search_code_patterns(pattern_description: str, server_categories: List[str] = None) -> Dict[str, Any]:
    """Search for specific code patterns across MCP servers"""
    servers = source_registry.get("mcp_servers", [])

    if server_categories:
        filtered_servers = [s for s in servers if s.get("category") in server_categories]
    else:
        filtered_servers = servers

    return {
        "search_pattern": pattern_description,
        "server_categories": server_categories or "all",
        "available_servers": filtered_servers,
        "analysis_guidance": f"Search for the pattern '{pattern_description}' in the source code of the listed servers"
    }

if __name__ == "__main__":
    mcp.run()
