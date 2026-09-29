"""Synthetic checks for Cline discovery across independent editor roots."""

import json
import logging
from pathlib import Path

import pytest

from adr_sensor import sensor_log
from adr_sensor.observer import AgentObserver
from adr_sensor.parsers.cline_parser import ClineParser


def _write_task(root, task_id):
    task = root / task_id
    task.mkdir(parents=True)
    (task / "api_conversation_history.json").write_text(
        json.dumps([{"role": "user", "content": [{"type": "text", "text": "Synthetic task"}]}]),
        encoding="utf-8",
    )


def _make_bad_root(root, failure, monkeypatch):
    if failure == "not_directory":
        root.write_text("Not a task directory", encoding="utf-8")
        return

    root.mkdir()
    method = "exists" if failure == "exists" else "iterdir"
    original = getattr(Path, method)

    def fail_one_root(path):
        if path == root:
            raise PermissionError("Synthetic access denied")
        return original(path)

    monkeypatch.setattr(Path, method, fail_one_root)


@pytest.mark.parametrize("failure", ["exists", "enumeration", "not_directory"])
@pytest.mark.parametrize("bad_first", [True, False])
@pytest.mark.parametrize("through_observer", [False, True])
def test_failed_editor_does_not_discard_healthy_sessions(tmp_path, monkeypatch, failure, bad_first, through_observer):
    healthy = tmp_path / "healthy-editor"
    _write_task(healthy, "healthy")
    bad = tmp_path / "failed-editor"
    _make_bad_root(bad, failure, monkeypatch)
    roots = [bad, healthy] if bad_first else [healthy, bad]
    monkeypatch.setattr(ClineParser, "BASE_PATHS", roots)
    parser = ClineParser(max_age_days=0)

    if through_observer:
        # Avoid initializing other parsers or inspecting real agent histories.
        observer = AgentObserver.__new__(AgentObserver)
        observer.cline_parser = parser
        observer.output_dir = tmp_path / "output"
        observer.output_dir.mkdir()
        entries, configs = observer.ingest_all("cline")
        assert configs == []
        record = observer.get_diagnostic_records()[0]
        assert record["reasons"] == {"file_read_error": 1}
        assert record["counts"]["events_emitted"] == 1
    else:
        entries = parser.parse_all()

    assert [entry.session_id for entry in entries] == ["cline_healthy"]
    assert parser.get_diagnostics() == {"file_read_error": 1}


@pytest.mark.parametrize("failure", ["exists", "enumeration", "not_directory"])
def test_inaccessible_input_is_not_reported_as_missing(tmp_path, monkeypatch, failure):
    root = tmp_path / "failed-editor"
    _make_bad_root(root, failure, monkeypatch)
    monkeypatch.setattr(ClineParser, "BASE_PATHS", [root])
    parser = ClineParser(max_age_days=0)

    assert parser.parse_all() == []
    assert parser.get_diagnostics() == {"file_read_error": 1}


def test_absent_editors_report_input_missing_once(tmp_path, monkeypatch):
    monkeypatch.setattr(ClineParser, "BASE_PATHS", [tmp_path / "missing-code", tmp_path / "missing-cursor"])
    parser = ClineParser()

    assert parser.parse_all() == []
    assert parser.get_diagnostics() == {"input_missing": 1}


def test_explicit_base_path_does_not_scan_other_editors(tmp_path, monkeypatch):
    selected = tmp_path / "selected"
    other = tmp_path / "other-editor"
    _write_task(selected, "selected")
    _write_task(other, "unselected")
    monkeypatch.setattr(ClineParser, "BASE_PATHS", [other, selected])

    entries = ClineParser(base_path=selected, max_age_days=0).parse_all()

    assert [entry.session_id for entry in entries] == ["cline_selected"]


@pytest.mark.parametrize("editor", ["code", "cursor"])
def test_base_path_assignment_restricts_collection_to_a_known_editor(tmp_path, monkeypatch, editor):
    code = tmp_path / "code"
    cursor = tmp_path / "cursor"
    _write_task(code, "code")
    _write_task(cursor, "cursor")
    monkeypatch.setattr(ClineParser, "BASE_PATHS", [code, cursor])
    parser = ClineParser(max_age_days=0)
    assert parser.base_path == code
    parser.base_path = tmp_path / editor

    assert [entry.session_id for entry in parser.parse_all()] == [f"cline_{editor}"]


def test_repeated_session_is_emitted_once_across_roots(tmp_path, monkeypatch):
    code = tmp_path / "code"
    cursor = tmp_path / "cursor"
    _write_task(code, "shared")
    _write_task(cursor, "shared")
    monkeypatch.setattr(ClineParser, "BASE_PATHS", [code, code, cursor])

    entries = ClineParser(max_age_days=0).parse_all()

    assert [entry.session_id for entry in entries] == ["cline_shared"]


def test_quiet_collection_keeps_errors_in_stderr_and_runtime_log(tmp_path, monkeypatch, capsys):
    healthy = tmp_path / "healthy-editor"
    bad = tmp_path / "failed-editor"
    _write_task(healthy, "healthy")
    _make_bad_root(bad, "enumeration", monkeypatch)
    monkeypatch.setattr(ClineParser, "BASE_PATHS", [healthy, bad])
    for handler in sensor_log._console_handlers():
        monkeypatch.setattr(handler, "level", logging.WARNING)

    log_dir = tmp_path / "runtime"
    assert sensor_log.enable_runtime_log(log_dir)
    try:
        entries = ClineParser(max_age_days=0).parse_all()
    finally:
        sensor_log.disable_runtime_log()

    captured = capsys.readouterr()
    assert [entry.session_id for entry in entries] == ["cline_healthy"]
    assert captured.out == ""
    assert "Error scanning task directory" in captured.err
    records = [
        json.loads(line) for line in (log_dir / sensor_log.RUNTIME_ERRORS_LOG).read_text(encoding="utf-8").splitlines()
    ]
    assert len(records) == 1
    assert records[0]["level"] == "ERROR"
    assert records[0]["component"] == "parsers.cline_parser"
    assert records[0]["exception_type"] == "PermissionError"
