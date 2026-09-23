"""Tests for OTLP conversion of ADR Sensor records."""

import time
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceResponse
from opentelemetry.sdk._logs.export import (
    InMemoryLogRecordExporter,
    LogRecordExportResult,
    SimpleLogRecordProcessor,
)
from requests import Response

from adr_sensor.diagnostics import health_record
from adr_sensor.exporters.config import OpenTelemetryConfig
from adr_sensor.exporters.opentelemetry import (
    OpenTelemetryExportError,
    OpenTelemetryLogExporter,
    _datetime_to_unix_nanos,
)
from adr_sensor.schemas.agent_event_schema import AgentEvent, ChatMessage, ToolUsage


def _event() -> AgentEvent:
    return AgentEvent(
        timestamp=datetime(2026, 9, 9, 10, 11, 12, 345678, tzinfo=timezone.utc),
        source="codex",
        session_id="codex_session-1",
        hostname="test-host",
        username="developer",
        model="gpt-test",
        project_path="/workspace/private-project",
        chat_history=[
            ChatMessage(role="user", content="full prompt content", sequence_id="message-1"),
            ChatMessage(
                role="assistant",
                content="full response content",
                sequence_id="message-2",
                tools=[
                    ToolUsage(
                        tool_name="shell",
                        tool_type="custom_tool_call",
                        arguments={"command": "printenv SECRET_TOKEN"},
                        result="sensitive-result",
                        status="success",
                    )
                ],
            ),
        ],
    )


def test_export_preserves_complete_agent_event_payload():
    memory_exporter = InMemoryLogRecordExporter()
    exporter = OpenTelemetryLogExporter(
        OpenTelemetryConfig(endpoint="http://localhost:4318/v1/logs"),
        service_version="1.2.3",
        _log_record_exporter=memory_exporter,
        _processor_factory=SimpleLogRecordProcessor,
    )
    event = _event()

    assert exporter.export([event], []) == 1

    records = memory_exporter.get_finished_logs()
    assert len(records) == 1
    record = records[0]
    assert record.log_record.body == event.get_non_null_fields()
    assert record.log_record.event_name == "adr.agent.session"
    assert record.log_record.severity_text == "INFO"
    assert record.log_record.attributes == {
        "adr.event.type": "agent_session",
        "adr.event.uuid": event.uuid,
        "adr.schema.version": "1",
        "adr.source": "codex",
        "adr.session.id": "codex_session-1",
        "adr.model": "gpt-test",
    }
    assert record.log_record.timestamp == _datetime_to_unix_nanos(event.timestamp)
    assert record.resource.attributes["service.name"] == "adr-sensor"
    assert record.resource.attributes["service.version"] == "1.2.3"

    exporter.shutdown()


def test_shutdown_is_idempotent():
    exporter = OpenTelemetryLogExporter(
        OpenTelemetryConfig(endpoint="http://localhost:4318/v1/logs"),
        service_version="1.2.3",
        _log_record_exporter=InMemoryLogRecordExporter(),
        _processor_factory=SimpleLogRecordProcessor,
    )

    exporter.shutdown()
    exporter.shutdown()


def test_shutdown_reports_exporter_delivery_failure():
    class FailingExporter(InMemoryLogRecordExporter):
        def export(self, batch):
            return LogRecordExportResult.FAILURE

    exporter = OpenTelemetryLogExporter(
        OpenTelemetryConfig(endpoint="http://localhost:4318/v1/logs"),
        service_version="1.2.3",
        _log_record_exporter=FailingExporter(),
        _processor_factory=SimpleLogRecordProcessor,
    )

    exporter.export([_event()], [])

    with pytest.raises(OpenTelemetryExportError, match="did not accept"):
        exporter.shutdown()


def test_datetime_to_unix_nanos_treats_naive_datetime_as_utc():
    aware = datetime(2026, 9, 9, 10, 11, 12, 345678, tzinfo=timezone.utc)
    naive = aware.replace(tzinfo=None)

    assert _datetime_to_unix_nanos(naive) == _datetime_to_unix_nanos(aware)


def test_large_export_drains_bounded_batches_without_losing_records(monkeypatch):
    # The old default queue lost records above 2048 when its worker was busy.
    # Environment settings must not silently shrink our explicit queue bound.
    monkeypatch.setenv("OTEL_BLRP_MAX_QUEUE_SIZE", "1")
    monkeypatch.setenv("OTEL_BLRP_MAX_EXPORT_BATCH_SIZE", "1")
    memory_exporter = InMemoryLogRecordExporter()
    batch_sizes = []
    original_export = memory_exporter.export

    def record_batch(batch):
        time.sleep(0.005)
        batch_sizes.append(len(batch))
        return original_export(batch)

    memory_exporter.export = record_batch
    exporter = OpenTelemetryLogExporter(
        OpenTelemetryConfig(endpoint="http://localhost:4318/v1/logs"),
        service_version="1.2.3",
        _log_record_exporter=memory_exporter,
    )
    entries = [_event()] * 4097
    health = [health_record("codex", "parse", counts={"events_emitted": 1})] * 1025

    assert exporter.export(entries, []) == len(entries)
    assert exporter.export_diagnostics(health) == len(health)
    exporter.shutdown()

    assert len(memory_exporter.get_finished_logs()) == len(entries) + len(health)
    assert sum(batch_sizes) == len(entries) + len(health)
    assert max(batch_sizes) <= 512


def test_shutdown_detects_silently_dropped_records():
    class DroppingProcessor(SimpleLogRecordProcessor):
        def on_emit(self, log_record):
            pass

    exporter = OpenTelemetryLogExporter(
        OpenTelemetryConfig(endpoint="http://localhost:4318/v1/logs"),
        service_version="1.2.3",
        _log_record_exporter=InMemoryLogRecordExporter(),
        _processor_factory=DroppingProcessor,
    )
    exporter.export([_event()], [])

    with pytest.raises(OpenTelemetryExportError, match="submitted 1, successfully exported 0"):
        exporter.shutdown()


def test_failed_intermediate_batch_stops_large_exports():
    class FailingExporter(InMemoryLogRecordExporter):
        def export(self, batch):
            return LogRecordExportResult.FAILURE

    exporter = OpenTelemetryLogExporter(
        OpenTelemetryConfig(endpoint="http://localhost:4318/v1/logs"),
        service_version="1.2.3",
        _log_record_exporter=FailingExporter(),
    )
    with pytest.raises(OpenTelemetryExportError, match="did not accept"):
        exporter.export([_event()] * 4097, [])
    with pytest.raises(OpenTelemetryExportError, match="did not accept"):
        exporter.shutdown()


def test_shutdown_reports_flush_timeout_and_still_stops_provider():
    exporter = OpenTelemetryLogExporter(
        OpenTelemetryConfig(endpoint="http://localhost:4318/v1/logs"),
        service_version="1.2.3",
        _log_record_exporter=InMemoryLogRecordExporter(),
    )
    with (
        patch.object(exporter._provider, "force_flush", return_value=False),
        patch.object(exporter._provider, "shutdown", wraps=exporter._provider.shutdown) as shutdown,
        pytest.raises(OpenTelemetryExportError, match="did not flush"),
    ):
        exporter.shutdown()
    shutdown.assert_called_once_with()


def test_export_after_shutdown_is_rejected():
    exporter = OpenTelemetryLogExporter(
        OpenTelemetryConfig(endpoint="http://localhost:4318/v1/logs"),
        service_version="1.2.3",
        _log_record_exporter=InMemoryLogRecordExporter(),
    )
    exporter.shutdown()
    with pytest.raises(OpenTelemetryExportError, match="already shut down"):
        exporter.export([_event()], [])


def _http_response(body, status_code=200):
    response = Response()
    response.status_code = status_code
    response._content = body
    response.headers["Content-Type"] = "application/x-protobuf"
    return response


@pytest.mark.parametrize(
    "body",
    [
        b"",
        ExportLogsServiceResponse(partial_success={"rejected_log_records": 0}).SerializeToString(),
        ExportLogsServiceResponse(
            partial_success={"rejected_log_records": 0, "error_message": "synthetic private warning"}
        ).SerializeToString(),
        b"\x10\x01",  # Unknown protobuf fields remain forward compatible.
    ],
)
def test_http_acknowledgement_accepts_full_success_and_zero_rejection_warnings(body, caplog):
    exporter = OpenTelemetryLogExporter(
        OpenTelemetryConfig(endpoint="https://collector.example.invalid/v1/logs"), service_version="1.2.3"
    )
    with patch("requests.adapters.HTTPAdapter.send", return_value=_http_response(body)) as transport:
        assert exporter.export([_event()], []) == 1
        exporter.shutdown()

    transport.assert_called_once()
    assert exporter._record_exporter.exported_count == 1
    assert "synthetic private warning" not in caplog.text


@pytest.mark.parametrize(
    "body,status_code",
    [
        (
            ExportLogsServiceResponse(
                partial_success={"rejected_log_records": 1, "error_message": "synthetic private rejection"}
            ).SerializeToString(),
            200,
        ),
        (ExportLogsServiceResponse(partial_success={"rejected_log_records": -1}).SerializeToString(), 200),
        (b"synthetic private invalid response", 200),
        (b"", 304),
    ],
)
def test_http_acknowledgement_rejects_partial_or_invalid_success_without_private_text(body, status_code, caplog):
    exporter = OpenTelemetryLogExporter(
        OpenTelemetryConfig(endpoint="https://collector.example.invalid/v1/logs"), service_version="1.2.3"
    )
    with patch("requests.adapters.HTTPAdapter.send", return_value=_http_response(body, status_code)) as transport:
        exporter.export([_event()], [])
        with pytest.raises(OpenTelemetryExportError, match="did not accept") as error:
            exporter.shutdown()

    transport.assert_called_once()
    assert exporter._record_exporter.exported_count == 0
    assert "synthetic private" not in caplog.text
    assert "synthetic private" not in str(error.value)


@pytest.mark.parametrize(
    "variable",
    ["OTEL_PYTHON_EXPORTER_OTLP_HTTP_CREDENTIAL_PROVIDER", "OTEL_PYTHON_EXPORTER_OTLP_HTTP_LOGS_CREDENTIAL_PROVIDER"],
)
def test_opaque_credential_providers_fail_explicitly_without_loading_plugin(variable, monkeypatch):
    monkeypatch.setenv(variable, "synthetic-private-provider")
    with (
        patch("adr_sensor.exporters.opentelemetry._load_opentelemetry_components") as load_components,
        pytest.raises(OpenTelemetryExportError, match="credential-provider plugins are unsupported") as error,
    ):
        OpenTelemetryLogExporter(
            OpenTelemetryConfig(endpoint="https://collector.example.invalid/v1/logs"), service_version="1.2.3"
        )
    load_components.assert_not_called()
    assert "synthetic-private-provider" not in str(error.value)
