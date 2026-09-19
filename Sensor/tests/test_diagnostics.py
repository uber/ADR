"""Health summaries are bounded and remain useful when capture yields no data."""

import json
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from opentelemetry.sdk._logs.export import InMemoryLogRecordExporter, SimpleLogRecordProcessor

from adr_sensor import diagnostics
from adr_sensor.cli import main
from adr_sensor.diagnostics import health_record, sanitize_health_record, write_health_records
from adr_sensor.exporters.config import OpenTelemetryConfig
from adr_sensor.exporters.opentelemetry import OpenTelemetryExportError, OpenTelemetryLogExporter
from adr_sensor.observer import AgentObserver
from adr_sensor.parsers.base_parser import BaseParser
from adr_sensor.schemas.agent_event_schema import AgentEvent, ChatMessage


def _event():
    return AgentEvent(
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        source="claude",
        session_id="synthetic-session",
        chat_history=[ChatMessage(role="user", content="Keep the full synthetic prompt SECRET_CANARY")],
        username="synthetic-user",
        hostname="synthetic-host",
    )


class _Parser(BaseParser):
    def __init__(self, records=(), reason=None, error=False):
        self.records = list(records)
        self.reason = reason
        self.error = error

    def parse_all(self):
        if self.reason:
            self.record_diagnostic(self.reason, 4)
        if self.error:
            raise ValueError("SECRET_CANARY /private/project/secret.txt")
        return self.records


def _observer(tmp_path, parser):
    observer = AgentObserver(output_dir=tmp_path)
    observer.SOURCES = (("claude", "Claude Code"),)
    observer.claude_parser = parser
    return observer


@pytest.mark.parametrize(
    ("reasons", "status", "drift"),
    [
        ({}, "empty", False),
        ({"input_missing": 1}, "no_input", False),
        ({"file_age_skipped": 4}, "empty", False),
        ({"incomplete_record": 1}, "empty", False),
        ({"record_decode_error": 2}, "failed", False),
        ({"unsupported_schema": 1}, "failed", True),
    ],
)
def test_health_distinguishes_no_input_corruption_and_suspected_drift(reasons, status, drift):
    record = health_record("claude", "parse", reasons=reasons)
    assert record["status"] == status
    assert record["suspected_schema_drift"] is drift


def test_fixed_schema_rejects_payloads_paths_and_arbitrary_label_values():
    record = health_record(
        "SECRET_CANARY",
        "SECRET_CANARY",
        counts={"SECRET_CANARY": 1, "events_emitted": "SECRET_CANARY", "failed": -1, "attempted": True},
        reasons={"SECRET_CANARY": 1, "record_decode_error": 10**100},
    )
    record.update(message="SECRET_CANARY", trace="SECRET_CANARY", session_id="SECRET_CANARY")
    record["timestamp"] = "SECRET_CANARY"
    safe = sanitize_health_record(record)
    assert "SECRET_CANARY" not in json.dumps(safe)
    assert safe["source"] == "sensor"
    assert safe["counts"] == {}
    assert safe["reasons"] == {"record_decode_error": 2**63 - 1}


def test_parser_counts_are_written_when_no_session_survives(tmp_path):
    observer = _observer(tmp_path, _Parser(reason="record_decode_error"))
    assert observer.ingest_all("claude") == ([], [])
    record = json.loads((tmp_path / "diagnostics.jsonl").read_text())
    assert record["reasons"] == {"record_decode_error": 4}
    assert record["status"] == "failed"
    assert observer.has_errors
    assert json.loads((tmp_path / "error.log").read_text()) == record


def test_partial_capture_preserves_payload_and_resets_counters_between_runs(tmp_path):
    event = _event()
    observer = _observer(tmp_path, _Parser([event], reason="record_shape_error"))
    for _ in range(2):
        entries, _ = observer.ingest_all("claude")
        assert entries == [event]
        assert "SECRET_CANARY" in entries[0].chat_history[0].content
    records = [json.loads(line) for line in (tmp_path / "diagnostics.jsonl").read_text().splitlines()]
    assert len(records) == 2
    assert all(record["reasons"] == {"record_shape_error": 4} for record in records)
    assert all(record["status"] == "partial" for record in records)
    assert "SECRET_CANARY" not in json.dumps(records)


def test_escaping_parser_error_does_not_log_exception_values(tmp_path):
    observer = _observer(tmp_path, _Parser(error=True))
    observer.ingest_all("claude")
    assert observer.has_errors
    assert "SECRET_CANARY" not in (tmp_path / "error.log").read_text()
    assert observer.get_diagnostic_records()[0]["reasons"] == {"parser_error": 1}


def test_invalid_parser_return_is_isolated_and_reported(tmp_path):
    parser = _Parser()
    parser.parse_all = lambda: None
    observer = _observer(tmp_path, parser)
    assert observer.ingest_all("claude") == ([], [])
    assert observer.get_diagnostic_records()[0]["reasons"] == {"parser_error": 1}


def test_repeated_output_errors_are_coalesced_without_retaining_details(tmp_path):
    observer = _observer(tmp_path, _Parser())
    for _ in range(1000):
        observer._emit_error({"stage": "compare_session", "source": "claude", "message": "SECRET_CANARY"})
    records = observer.get_diagnostic_records()
    assert len(records) == 1
    assert records[0]["stage"] == "save"
    assert records[0]["reasons"] == {"write_error": 1000}
    records[0]["reasons"]["write_error"] = 0
    assert observer.get_diagnostic_records()[0]["reasons"] == {"write_error": 1000}
    observer.flush_diagnostics()
    assert "SECRET_CANARY" not in (tmp_path / "error.log").read_text()


def test_diagnostic_files_rotate_and_keep_a_bounded_number_of_backups(tmp_path, monkeypatch):
    monkeypatch.setattr(diagnostics, "MAX_LOG_BYTES", 650)
    records = [health_record("claude", "parse", reasons={"record_shape_error": 1}) for _ in range(25)]
    assert write_health_records(tmp_path, records)
    assert len(list(tmp_path.glob("diagnostics.jsonl*"))) == 3
    assert len(list(tmp_path.glob("error.log*"))) == 3
    for path in tmp_path.iterdir():
        assert path.stat().st_size <= 650
        for line in path.read_text().splitlines():
            assert json.loads(line)["event"] == "adr.sensor.health"


def test_log_failure_warns_once_without_breaking_capture(tmp_path, monkeypatch, capsys):
    observer = _observer(tmp_path, _Parser([_event()]))

    def fail(*args, **kwargs):
        raise OSError("SECRET_CANARY")

    monkeypatch.setattr(diagnostics, "RotatingFileHandler", fail)
    entries, _ = observer.ingest_all("claude")
    observer.flush_diagnostics()
    observer.flush_diagnostics()
    assert len(entries) == 1
    assert observer.has_errors
    stderr = capsys.readouterr().err
    assert stderr.count("Unable to write sensor diagnostics") == 1
    assert "SECRET_CANARY" not in stderr


def test_failed_session_save_is_persisted_and_counted(tmp_path, monkeypatch):
    observer = _observer(tmp_path, _Parser())

    def fail(*args, **kwargs):
        raise OSError("SECRET_CANARY")

    monkeypatch.setattr(observer, "_create_session_temp", fail)
    assert observer.save_sessions_to_individual_files([_event()], tmp_path) == []
    assert observer.has_errors
    record = observer.get_diagnostic_records()[0]
    assert record["stage"] == "save_session"
    assert record["counts"] == {"attempted": 1, "succeeded": 0, "failed": 1}
    assert record["reasons"] == {"write_error": 1}
    assert "SECRET_CANARY" not in (tmp_path / "error.log").read_text()


def test_otlp_health_record_uses_separate_schema_and_warning_severity():
    memory = InMemoryLogRecordExporter()
    exporter = OpenTelemetryLogExporter(
        OpenTelemetryConfig(endpoint="http://localhost:4318/v1/logs"),
        "test",
        _log_record_exporter=memory,
        _processor_factory=SimpleLogRecordProcessor,
    )
    record = health_record("claude", "parse", reasons={"record_decode_error": 3})
    record["message"] = "SECRET_CANARY"
    assert exporter.export_diagnostics([record]) == 1
    exporter.shutdown()
    emitted = memory.get_finished_logs()[0].log_record
    assert emitted.event_name == "adr.sensor.health"
    assert emitted.severity_text == "WARN"
    assert emitted.attributes["adr.event.type"] == "sensor_health"
    assert emitted.body["reasons"] == {"record_decode_error": 3}
    assert "SECRET_CANARY" not in json.dumps(emitted.body)


def test_cli_sends_health_even_when_no_session_was_captured(tmp_path, monkeypatch):
    observer = _observer(tmp_path, _Parser(reason="unsupported_schema"))
    exporter = MagicMock()
    exporter.export.return_value = 0
    monkeypatch.setattr("sys.argv", ["adr-sensor", "--no-save", "--otel-config", "synthetic.json"])
    with (
        patch("adr_sensor.cli.AgentObserver", return_value=observer),
        patch("adr_sensor.cli.load_opentelemetry_config", return_value=MagicMock()),
        patch("adr_sensor.cli.OpenTelemetryLogExporter", return_value=exporter),
    ):
        main()
    exporter.export.assert_called_once_with([], [])
    assert exporter.export_diagnostics.call_args.args[0][0]["suspected_schema_drift"] is True
    exporter.shutdown.assert_called_once()


def test_cli_can_fail_after_preserving_partial_capture(tmp_path, monkeypatch, capsys):
    observer = _observer(tmp_path, _Parser([_event()], reason="record_shape_error"))
    monkeypatch.setattr("sys.argv", ["adr-sensor", "--no-save", "--fail-on-error"])
    with patch("adr_sensor.cli.AgentObserver", return_value=observer), pytest.raises(SystemExit) as failure:
        main()
    assert failure.value.code == 1
    assert "completed with errors" in capsys.readouterr().out
    assert (tmp_path / "diagnostics.jsonl").exists()


def test_export_failure_is_recorded_locally(tmp_path, monkeypatch):
    observer = _observer(tmp_path, _Parser())
    exporter = MagicMock()
    exporter.shutdown.side_effect = OpenTelemetryExportError("synthetic delivery failure")
    monkeypatch.setattr("sys.argv", ["adr-sensor", "--no-save", "--otel-config", "synthetic.json"])
    with (
        patch("adr_sensor.cli.AgentObserver", return_value=observer),
        patch("adr_sensor.cli.load_opentelemetry_config", return_value=MagicMock()),
        patch("adr_sensor.cli.OpenTelemetryLogExporter", return_value=exporter),
        pytest.raises(SystemExit),
    ):
        main()
    records = [json.loads(line) for line in (tmp_path / "error.log").read_text().splitlines()]
    assert records[-1]["reasons"] == {"export_error": 1}


def test_resource_log_marks_observed_partial_failure_unsuccessful(tmp_path, monkeypatch):
    observer = _observer(tmp_path, _Parser([_event()], reason="record_shape_error"))
    usage = SimpleNamespace(ru_utime=0, ru_stime=0, ru_maxrss=0)
    resources = MagicMock()
    resources.getrusage.return_value = usage
    monkeypatch.setattr("sys.argv", ["adr-sensor", "--no-save", "--resource", "--output-dir", str(tmp_path)])
    with (
        patch("adr_sensor.cli.AgentObserver", return_value=observer),
        patch("adr_sensor.cli.resource_mod", resources),
        patch("adr_sensor.cli.platform.system", return_value="Linux"),
    ):
        main()
    assert json.loads((tmp_path / "resource.log").read_text())["success"] is False


def test_startup_failure_has_content_free_local_record(tmp_path, monkeypatch):
    monkeypatch.setattr("sys.argv", ["adr-sensor", "--no-save", "--output-dir", str(tmp_path)])
    with (
        patch("adr_sensor.cli.AgentObserver", side_effect=RuntimeError("SECRET_CANARY")),
        pytest.raises(RuntimeError),
    ):
        main()
    record = json.loads((tmp_path / "error.log").read_text())
    assert record["reasons"] == {"startup_error": 1}
    assert "SECRET_CANARY" not in json.dumps(record)
