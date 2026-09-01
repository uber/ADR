"""Tests for dependency-aware source retrieval."""

import inspect
from importlib.machinery import EXTENSION_SUFFIXES

from context_providers import source_code_analyzer_server as analyzer
from context_providers.source_code_analyzer_server import collect_local_source_files


def test_collects_local_imported_implementation_without_unrelated_files(tmp_path):
    function_dir = tmp_path / "function"
    function_dir.mkdir()
    entrypoint = tmp_path / "server.py"
    entrypoint.write_text(
        "from function.core import run\n\ndef tool():\n    return run()\n",
        encoding="utf-8",
    )
    (function_dir / "core.py").write_text(
        "def run():\n    return 'hidden implementation'\n",
        encoding="utf-8",
    )
    (tmp_path / "unrelated.py").write_text("SECRET = True\n", encoding="utf-8")

    files = collect_local_source_files(entrypoint)
    by_path = {item["path"]: item for item in files}
    assert set(by_path) == {"server.py", "function/core.py"}
    assert "hidden implementation" in by_path["function/core.py"]["source_code"]
    assert all(str(tmp_path) not in item["path"] for item in files)


def test_relative_imports_remain_inside_server_root(tmp_path):
    package = tmp_path / "package"
    package.mkdir()
    entrypoint = package / "entry.py"
    entrypoint.write_text("from .helper import value\n", encoding="utf-8")
    (package / "helper.py").write_text("value = 1\n", encoding="utf-8")

    files = collect_local_source_files(entrypoint)
    assert {item["path"] for item in files} == {"entry.py", "helper.py"}


def test_regular_package_precedes_same_named_module(tmp_path):
    entrypoint = tmp_path / "server.py"
    entrypoint.write_text("import dependency\n", encoding="utf-8")
    (tmp_path / "dependency.py").write_text("KIND = 'module'\n", encoding="utf-8")
    package = tmp_path / "dependency"
    package.mkdir()
    (package / "__init__.py").write_text("KIND = 'package'\n", encoding="utf-8")

    files = collect_local_source_files(entrypoint)
    by_path = {item["path"]: item for item in files}

    assert set(by_path) == {"server.py", "dependency/__init__.py"}
    assert "KIND = 'package'" in by_path["dependency/__init__.py"]["source_code"]


def test_namespace_package_does_not_shadow_same_named_module(tmp_path):
    entrypoint = tmp_path / "server.py"
    entrypoint.write_text("import dependency\n", encoding="utf-8")
    (tmp_path / "dependency.py").write_text("KIND = 'module'\n", encoding="utf-8")
    (tmp_path / "dependency").mkdir()

    files = collect_local_source_files(entrypoint)

    assert {item["path"] for item in files} == {"server.py", "dependency.py"}


def test_from_package_import_follows_initializer_and_submodule(tmp_path):
    entrypoint = tmp_path / "server.py"
    entrypoint.write_text("from dependency import implementation\n", encoding="utf-8")
    package = tmp_path / "dependency"
    package.mkdir()
    (package / "__init__.py").write_text("PACKAGE = True\n", encoding="utf-8")
    (package / "implementation.py").write_text("VALUE = 1\n", encoding="utf-8")

    files = collect_local_source_files(entrypoint)

    assert {item["path"] for item in files} == {
        "server.py",
        "dependency/__init__.py",
        "dependency/implementation.py",
    }


def test_builtin_module_precedes_same_named_local_source(tmp_path):
    entrypoint = tmp_path / "server.py"
    entrypoint.write_text("import sys\n", encoding="utf-8")
    (tmp_path / "sys.py").write_text("LOCAL = True\n", encoding="utf-8")

    files = collect_local_source_files(entrypoint)

    assert {item["path"] for item in files} == {"server.py"}


def test_native_module_precedes_same_named_local_source(tmp_path):
    entrypoint = tmp_path / "server.py"
    entrypoint.write_text("import dependency\n", encoding="utf-8")
    (tmp_path / "dependency.py").write_text("LOCAL = True\n", encoding="utf-8")
    (tmp_path / f"dependency{EXTENSION_SUFFIXES[0]}").write_bytes(b"")

    files = collect_local_source_files(entrypoint)

    assert {item["path"] for item in files} == {"server.py"}


def test_source_discovery_never_executes_imported_module(tmp_path):
    entrypoint = tmp_path / "server.py"
    entrypoint.write_text("import dependency\n", encoding="utf-8")
    marker = tmp_path / "executed"
    (tmp_path / "dependency.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).touch()\n",
        encoding="utf-8",
    )

    files = collect_local_source_files(entrypoint)

    assert {item["path"] for item in files} == {"server.py", "dependency.py"}
    assert not marker.exists()


def test_symlinked_import_is_not_returned_as_local_source(tmp_path):
    entrypoint = tmp_path / "server.py"
    entrypoint.write_text("import linked\n", encoding="utf-8")
    implementation = tmp_path / "implementation.py"
    implementation.write_text("VALUE = 1\n", encoding="utf-8")
    (tmp_path / "linked.py").symlink_to(implementation)

    files = collect_local_source_files(entrypoint)

    assert {item["path"] for item in files} == {"server.py"}


def test_registry_entrypoint_cannot_escape_provider_root(tmp_path, monkeypatch):
    provider_root = tmp_path / "provider"
    provider_root.mkdir()
    secret = tmp_path / "secret.py"
    secret.write_text("SECRET = 'must not be returned'\n", encoding="utf-8")
    monkeypatch.setattr(analyzer, "__file__", str(provider_root / "provider.py"))
    monkeypatch.setattr(
        analyzer,
        "source_registry",
        {"mcp_servers": [{"name": "escaped", "path": "../secret.py"}]},
    )

    result = analyzer.get_source_code(["escaped"])

    assert result == {
        "source_codes": [{"server_name": "escaped", "status": "file_not_found"}],
        "total_retrieved": 0,
    }


def test_benchmark_public_contract_is_unchanged(tmp_path, monkeypatch):
    provider_root = tmp_path / "provider"
    provider_root.mkdir()
    entrypoint = provider_root / "server.py"
    entrypoint.write_text("import dependency\n", encoding="utf-8")
    (provider_root / "dependency.py").write_text("VALUE = 1\n", encoding="utf-8")
    monkeypatch.setattr(analyzer, "__file__", str(provider_root / "provider.py"))
    monkeypatch.setattr(
        analyzer,
        "source_registry",
        {
            "mcp_servers": [
                {
                    "name": "example",
                    "path": "server.py",
                    "category": "test",
                    "description": "example server",
                    "capabilities": ["read"],
                }
            ]
        },
    )

    result = analyzer.get_source_code(["example"])
    row = result["source_codes"][0]

    assert set(result) == {"source_codes", "total_retrieved"}
    assert set(row) == {
        "server_name",
        "status",
        "metadata",
        "source_code",
        "entrypoint",
        "source_files",
        "source_bundle_complete",
    }
    assert all(
        set(source_file) == {"path", "source_code", "truncated"}
        for source_file in row["source_files"]
    )
    assert list(inspect.signature(collect_local_source_files).parameters) == [
        "entrypoint"
    ]
    assert analyzer.MAX_LOCAL_SOURCE_FILES == 24
    assert analyzer.MAX_LOCAL_SOURCE_CHARS == 240_000
