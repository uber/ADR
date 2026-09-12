"""Tests for OTLP conversion of ADR Sensor records."""

from datetime import datetime, timezone

import pytest
from opentelemetry.sdk._logs.export import (
    InMemoryLogRecordExporter,
    LogRecordExportResult,
    SimpleLogRecordProcessor,
)

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
