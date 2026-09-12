"""Tests for dependency-aware source retrieval."""

import inspect
from importlib.machinery import EXTENSION_SUFFIXES
from pathlib import Path

import pytest

from context_providers import source_code_analyzer_server as analyzer
from context_providers.source_code_analyzer_server import collect_local_source_files


def _get_registered_source(monkeypatch, provider_root, entrypoint):
    monkeypatch.setattr(analyzer, "__file__", str(provider_root / "provider.py"))
    monkeypatch.setattr(
        analyzer,
        "source_registry",
        {
            "mcp_servers": [
                {
                    "name": "example",
                    "path": str(entrypoint.relative_to(provider_root)),
                    "category": "test",
                    "description": "example server",
                    "capabilities": ["read"],
                }
            ]
        },
    )
    return analyzer.get_source_code(["example"])["source_codes"][0]


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


def test_file_limit_marks_bundle_incomplete_when_dependencies_remain(tmp_path, monkeypatch):
    entrypoint = tmp_path / "server.py"
    entrypoint.write_text(
        "\n".join(f"import dependency_{index}" for index in range(analyzer.MAX_LOCAL_SOURCE_FILES)),
        encoding="utf-8",
    )
    for index in range(analyzer.MAX_LOCAL_SOURCE_FILES):
        (tmp_path / f"dependency_{index}.py").write_text(f"VALUE = {index}\n", encoding="utf-8")

    row = _get_registered_source(monkeypatch, tmp_path, entrypoint)

    assert len(row["source_files"]) == analyzer.MAX_LOCAL_SOURCE_FILES
    assert not any(item["truncated"] for item in row["source_files"])
    assert row["source_bundle_complete"] is False


def test_exact_byte_limit_marks_bundle_incomplete_when_dependency_remains(tmp_path, monkeypatch):
    entrypoint = tmp_path / "server.py"
    entrypoint_source = "import dependency\n"
    entrypoint.write_text(entrypoint_source, encoding="utf-8")
    (tmp_path / "dependency.py").write_text("VALUE = 1\n", encoding="utf-8")
    monkeypatch.setattr(analyzer, "MAX_LOCAL_SOURCE_BYTES", len(entrypoint_source.encode("utf-8")))

    row = _get_registered_source(monkeypatch, tmp_path, entrypoint)

    assert [item["path"] for item in row["source_files"]] == ["server.py"]
    assert row["source_files"][0]["truncated"] is False
    assert row["source_bundle_complete"] is False


def test_source_bundle_limit_counts_utf8_bytes(tmp_path, monkeypatch):
    entrypoint = tmp_path / "server.py"
    entrypoint.write_text("import dependency\n", encoding="utf-8")
    (tmp_path / "dependency.py").write_text(f"VALUE = {'😀' * 100!r}\n", encoding="utf-8")
    byte_limit = 128
    monkeypatch.setattr(analyzer, "MAX_LOCAL_SOURCE_BYTES", byte_limit)

    row = _get_registered_source(monkeypatch, tmp_path, entrypoint)

    assert (
        sum(len(item["source_code"].encode("utf-8")) for item in row["source_files"]) <= byte_limit
    )
    assert row["source_files"][-1]["truncated"] is True
    assert row["source_bundle_complete"] is False


def test_valid_non_utf8_dependency_does_not_fail_server_response(tmp_path, monkeypatch):
    entrypoint = tmp_path / "server.py"
    entrypoint.write_text("import dependency\n", encoding="utf-8")
    (tmp_path / "dependency.py").write_bytes(b"# -*- coding: latin-1 -*-\nVALUE = 'caf\xe9'\n")

    row = _get_registered_source(monkeypatch, tmp_path, entrypoint)
    source_by_path = {item["path"]: item["source_code"] for item in row["source_files"]}

    assert row["status"] == "found"
    assert row["source_bundle_complete"] is True
    assert "café" in source_by_path["dependency.py"]


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
    assert list(inspect.signature(collect_local_source_files).parameters) == ["entrypoint"]
    assert analyzer.MAX_LOCAL_SOURCE_FILES == 24
    assert analyzer.MAX_LOCAL_SOURCE_BYTES == 240_000


def _record_binary_reads(monkeypatch):
    opened = []
    original_open = Path.open

    def recording_open(path, mode="r", *args, **kwargs):
        if mode == "rb":
            opened.append(path.name)
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", recording_open)
    return opened


def test_failed_decodes_count_toward_file_limit(tmp_path, monkeypatch):
    entrypoint = tmp_path / "server.py"
    entrypoint.write_text("import bad0, bad1, bad2, bad3\n", encoding="utf-8")
    for index in range(4):
        (tmp_path / f"bad{index}.py").write_bytes(b"# coding: ascii\nVALUE = '\xff'\n")
    monkeypatch.setattr(analyzer, "MAX_LOCAL_SOURCE_FILES", 3)
    opened = _record_binary_reads(monkeypatch)

    files, complete = analyzer._collect_local_source_bundle(entrypoint)

    assert opened == ["server.py", "bad0.py", "bad1.py"]
    assert [item["path"] for item in files] == ["server.py"]
    assert complete is False


def test_failed_decode_consumes_read_budget(tmp_path, monkeypatch):
    entrypoint = tmp_path / "server.py"
    entrypoint.write_text("import bad, good\n", encoding="utf-8")
    (tmp_path / "bad.py").write_bytes(b"# coding: ascii\n" + b"\xff" * 200)
    (tmp_path / "good.py").write_text("VALUE = 1\n", encoding="utf-8")
    monkeypatch.setattr(analyzer, "MAX_LOCAL_SOURCE_BYTES", 96)
    opened = _record_binary_reads(monkeypatch)

    files, complete = analyzer._collect_local_source_bundle(entrypoint)

    assert opened == ["server.py", "bad.py"]
    assert [item["path"] for item in files] == ["server.py"]
    assert complete is False


@pytest.mark.parametrize("prefix", [
    b"VALUE = 'se\xffcret'\n",
    b"# coding: ascii\nVALUE = 'se\xffcret'\n",
    b"# coding: not_a_codec\nVALUE = 1\n",
])
def test_truncated_invalid_source_is_not_silently_rewritten(tmp_path, monkeypatch, prefix):
    entrypoint = tmp_path / "server.py"
    entrypoint.write_text("import dependency\n", encoding="utf-8")
    (tmp_path / "dependency.py").write_bytes(prefix + b"#" * 200)
    monkeypatch.setattr(analyzer, "MAX_LOCAL_SOURCE_BYTES", 96)

    row = _get_registered_source(monkeypatch, tmp_path, entrypoint)

    assert row["status"] == "found"
    assert row["source_code"] == "import dependency\n"
    assert [item["path"] for item in row["source_files"]] == ["server.py"]
    assert row["source_bundle_complete"] is False


@pytest.mark.parametrize("encoding,header", [
    ("utf-8", ""),
    ("utf-8", "# coding: utf-8\n"),
    ("shift_jis", "# coding: shift_jis\n"),
])
def test_split_trailing_character_preserves_valid_prefix(tmp_path, monkeypatch, encoding, header):
    entrypoint = tmp_path / "server.py"
    entry_source = "import dependency\n"
    entrypoint.write_text(entry_source, encoding="utf-8")
    prefix = header + "VALUE = '"
    (tmp_path / "dependency.py").write_bytes((prefix + "日'\n").encode(encoding))
    # Include the first byte of a multibyte character at the input boundary.
    limit = len(entry_source.encode()) + len(prefix.encode(encoding)) + 1
    monkeypatch.setattr(analyzer, "MAX_LOCAL_SOURCE_BYTES", limit)

    row = _get_registered_source(monkeypatch, tmp_path, entrypoint)

    assert row["source_files"][-1]["source_code"] == prefix
    assert row["source_files"][-1]["truncated"] is True
    assert row["source_bundle_complete"] is False


def test_decode_failure_keeps_later_dependency_when_budget_remains(tmp_path, monkeypatch):
    entrypoint = tmp_path / "server.py"
    entrypoint.write_text("import bad, good\n", encoding="utf-8")
    (tmp_path / "bad.py").write_bytes(b"\xff")
    (tmp_path / "good.py").write_text("VALUE = 1\n", encoding="utf-8")

    row = _get_registered_source(monkeypatch, tmp_path, entrypoint)

    assert row["status"] == "found"
    assert [item["path"] for item in row["source_files"]] == ["server.py", "good.py"]
    assert row["source_bundle_complete"] is False


@pytest.mark.parametrize("encoding", ["rot_13", "base64_codec", "hex_codec"])
def test_non_text_codec_preserves_entrypoint_and_other_dependencies(
    tmp_path, monkeypatch, encoding
):
    entrypoint = tmp_path / "server.py"
    entry_source = "import bad, good\n"
    entrypoint.write_text(entry_source, encoding="utf-8")
    (tmp_path / "bad.py").write_text(
        f"# coding: {encoding}\nVALUE = 1\n", encoding="utf-8"
    )
    (tmp_path / "good.py").write_text("VALUE = 2\n", encoding="utf-8")

    row = _get_registered_source(monkeypatch, tmp_path, entrypoint)

    assert row["status"] == "found"
    assert row["source_code"] == entry_source
    assert [item["path"] for item in row["source_files"]] == ["server.py", "good.py"]
    assert row["source_files"][1]["source_code"] == "VALUE = 2\n"
    assert row["source_bundle_complete"] is False
