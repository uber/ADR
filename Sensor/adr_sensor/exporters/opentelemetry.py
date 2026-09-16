"""OTLP/HTTP logs exporter for normalized ADR Sensor records."""

import socket
import threading
import time
from datetime import datetime, timezone
from typing import Any, List, Optional, Tuple

from ..schemas.agent_event_schema import AgentEvent
from ..schemas.system_config_schema import SystemConfiguration
from .config import OpenTelemetryConfig

SCHEMA_VERSION = "1"


class OpenTelemetryExportError(RuntimeError):
    """Raised when OpenTelemetry export cannot be initialized or completed."""


class OpenTelemetryLogExporter:
    """Emit the Sensor's existing normalized records as OpenTelemetry logs."""

    def __init__(
        self,
        config: OpenTelemetryConfig,
        service_version: str,
        *,
        _log_record_exporter: Optional[Any] = None,
        _processor_factory: Optional[Any] = None,
    ):
        components = _load_opentelemetry_components()
        (
            logger_provider_cls,
            processor_cls,
            otlp_exporter_cls,
            resource_cls,
            severity_number_cls,
            export_result_cls,
        ) = components

        resource = resource_cls.create(
            {
                "service.name": config.service_name,
                "service.version": service_version,
                "host.name": socket.gethostname(),
            }
        )
        self._provider = logger_provider_cls(resource=resource)

        record_exporter = _log_record_exporter
        if record_exporter is None:
            record_exporter = otlp_exporter_cls(
                endpoint=config.endpoint,
                certificate_file=config.certificate_file,
                headers=config.headers,
                timeout=config.timeout_seconds,
            )

        self._record_exporter = _ExportStatusTracker(record_exporter, export_result_cls.SUCCESS)

        processor_factory = _processor_factory or processor_cls
        processor = processor_factory(self._record_exporter)
        self._provider.add_log_record_processor(processor)
        self._logger = self._provider.get_logger("adr_sensor", service_version)
        self._info_severity = severity_number_cls.INFO
        self._flush_timeout_millis = int(config.flush_timeout_seconds * 1000)
        self._closed = False

    def export(
        self,
        entries: List[AgentEvent],
        system_config_data: List[SystemConfiguration],
    ) -> int:
        """Queue complete, unredacted Sensor records for OTLP export."""
        for entry in entries:
            self._emit(
                body=entry.get_non_null_fields(),
                timestamp=entry.timestamp,
                event_name="adr.agent.session",
                attributes={
                    "adr.event.type": "agent_session",
                    "adr.event.uuid": entry.uuid,
                    "adr.schema.version": SCHEMA_VERSION,
                    "adr.source": entry.source,
                    "adr.session.id": entry.session_id,
                    **({"adr.model": entry.model} if entry.model else {}),
                },
            )

        for configuration in system_config_data:
            self._emit(
                body=configuration.to_dict(),
                timestamp=configuration.timestamp,
                event_name="adr.system.configuration",
                attributes={
                    "adr.event.type": "system_configuration",
                    "adr.event.uuid": configuration.uuid,
                    "adr.schema.version": SCHEMA_VERSION,
                },
            )

        return len(entries) + len(system_config_data)

    def shutdown(self) -> None:
        """Flush pending records and stop the provider's worker thread."""
        if self._closed:
            return

        self._closed = True
        flushed = False
        try:
            flushed = self._provider.force_flush(timeout_millis=self._flush_timeout_millis)
        finally:
            self._provider.shutdown()

        if not flushed:
            raise OpenTelemetryExportError(f"OpenTelemetry logs did not flush within {self._flush_timeout_millis} ms")
        if self._record_exporter.failed:
            raise OpenTelemetryExportError("the OTLP endpoint did not accept one or more log batches")

    def _emit(self, body: dict, timestamp: datetime, event_name: str, attributes: dict) -> None:
        self._logger.emit(
            timestamp=_datetime_to_unix_nanos(timestamp),
            observed_timestamp=time.time_ns(),
            severity_number=self._info_severity,
            severity_text="INFO",
            body=body,
            attributes=attributes,
            event_name=event_name,
        )


def _datetime_to_unix_nanos(value: datetime) -> int:
    if value.tzinfo is None or value.utcoffset() is None:
        value = value.replace(tzinfo=timezone.utc)
    value = value.astimezone(timezone.utc)
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = value - epoch
    return ((delta.days * 86400 + delta.seconds) * 1_000_000_000) + (delta.microseconds * 1000)


class _ExportStatusTracker:
    """Track exporter failures that OpenTelemetry's batch processor otherwise ignores."""

    def __init__(self, exporter: Any, success_result: Any):
        self._exporter = exporter
        self._success_result = success_result
        self._failed = False
        self._lock = threading.Lock()

    @property
    def failed(self) -> bool:
        with self._lock:
            return self._failed

    def export(self, batch: Any) -> Any:
        try:
            result = self._exporter.export(batch)
        except Exception:
            with self._lock:
                self._failed = True
            raise

        if result != self._success_result:
            with self._lock:
                self._failed = True
        return result

    def shutdown(self) -> None:
        self._exporter.shutdown()

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return self._exporter.force_flush(timeout_millis)


def _load_opentelemetry_components() -> Tuple[Any, Any, Any, Any, Any, Any]:
    try:
        from opentelemetry._logs import SeverityNumber
        from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
        from opentelemetry.sdk._logs import LoggerProvider
        from opentelemetry.sdk._logs.export import BatchLogRecordProcessor, LogRecordExportResult
        from opentelemetry.sdk.resources import Resource
    except ImportError as exc:
        raise OpenTelemetryExportError(
            "OpenTelemetry export requires the optional dependency; install adr-sensor[otel]"
        ) from exc

    return LoggerProvider, BatchLogRecordProcessor, OTLPLogExporter, Resource, SeverityNumber, LogRecordExportResult
