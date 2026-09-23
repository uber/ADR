"""OTLP/HTTP logs exporter for normalized ADR Sensor records."""

import os
import socket
import threading
import time
from datetime import datetime, timezone
from typing import Any, List, Optional, Tuple

from ..diagnostics import sanitize_health_record
from ..schemas.agent_event_schema import AgentEvent
from ..schemas.system_config_schema import SystemConfiguration
from .config import OpenTelemetryConfig

SCHEMA_VERSION = "1"
_MAX_BATCH_SIZE = 512


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
        _validate_credential_provider()
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
                session=_create_otlp_session(),
            )

        self._record_exporter = _ExportStatusTracker(record_exporter, export_result_cls.SUCCESS)

        if _processor_factory is None:
            # Bound the queue explicitly instead of inheriting environment defaults.
            # _emit() drains it before submitting another batch, providing backpressure.
            processor = processor_cls(
                self._record_exporter,
                max_queue_size=_MAX_BATCH_SIZE,
                max_export_batch_size=_MAX_BATCH_SIZE,
            )
        else:
            processor = _processor_factory(self._record_exporter)
        self._provider.add_log_record_processor(processor)
        self._logger = self._provider.get_logger("adr_sensor", service_version)
        self._info_severity = severity_number_cls.INFO
        self._warning_severity = severity_number_cls.WARN
        self._flush_timeout_millis = int(config.flush_timeout_seconds * 1000)
        self._closed = False
        self._submitted_count = 0
        self._flushed_count = 0
        self._emit_lock = threading.Lock()

    def export(
        self,
        entries: List[AgentEvent],
        system_config_data: List[SystemConfiguration],
    ) -> int:
        """Submit complete Sensor records; shutdown must succeed to confirm delivery."""
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

    def export_diagnostics(self, records: List[dict]) -> int:
        """Send bounded health summaries through the explicitly configured sink."""
        for record in records:
            body = sanitize_health_record(record)
            degraded = body["status"] in {"partial", "failed"}
            self._emit(
                timestamp=datetime.fromisoformat(body["timestamp"]),
                severity_number=self._warning_severity if degraded else self._info_severity,
                severity_text="WARN" if degraded else "INFO",
                body=body,
                attributes={
                    "adr.event.type": "sensor_health",
                    "adr.schema.version": SCHEMA_VERSION,
                    "adr.source": body["source"],
                    "adr.sensor.stage": body["stage"],
                    "adr.sensor.status": body["status"],
                },
                event_name="adr.sensor.health",
            )
        return len(records)

    def shutdown(self) -> None:
        """Flush pending records and stop the provider's worker thread."""
        with self._emit_lock:
            if self._closed:
                return

            self._closed = True
            try:
                self._flush()
            finally:
                try:
                    self._provider.shutdown()
                except Exception as exc:
                    raise OpenTelemetryExportError("OpenTelemetry exporter shutdown failed") from exc
            self._check_delivery()

    def _check_delivery(self) -> None:
        if self._record_exporter.failed:
            raise OpenTelemetryExportError("the OTLP endpoint did not accept one or more log batches")
        exported_count = self._record_exporter.exported_count
        if exported_count != self._submitted_count:
            raise OpenTelemetryExportError(
                f"OpenTelemetry delivery count mismatch: submitted {self._submitted_count}, "
                f"successfully exported {exported_count}"
            )

    def _flush(self) -> None:
        try:
            flushed = self._provider.force_flush(timeout_millis=self._flush_timeout_millis)
        except Exception as exc:
            raise OpenTelemetryExportError("OpenTelemetry logs could not be flushed") from exc
        if not flushed:
            raise OpenTelemetryExportError(f"OpenTelemetry logs did not flush within {self._flush_timeout_millis} ms")
        self._check_delivery()
        self._flushed_count = self._submitted_count

    def _emit(
        self,
        body: dict,
        timestamp: datetime,
        event_name: str,
        attributes: dict,
        *,
        severity_number: Optional[Any] = None,
        severity_text: str = "INFO",
    ) -> None:
        with self._emit_lock:
            if self._closed:
                raise OpenTelemetryExportError("OpenTelemetry exporter is already shut down")
            self._logger.emit(
                timestamp=_datetime_to_unix_nanos(timestamp),
                observed_timestamp=time.time_ns(),
                severity_number=self._info_severity if severity_number is None else severity_number,
                severity_text=severity_text,
                body=body,
                attributes=attributes,
                event_name=event_name,
            )
            self._submitted_count += 1
            if self._submitted_count - self._flushed_count >= _MAX_BATCH_SIZE:
                self._flush()


def _datetime_to_unix_nanos(value: datetime) -> int:
    if value.tzinfo is None or value.utcoffset() is None:
        value = value.replace(tzinfo=timezone.utc)
    value = value.astimezone(timezone.utc)
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = value - epoch
    return ((delta.days * 86400 + delta.seconds) * 1_000_000_000) + (delta.microseconds * 1000)


def _validate_credential_provider() -> None:
    """Reject opaque authentication that cannot be identified in checkpoints."""
    if os.environ.get("OTEL_PYTHON_EXPORTER_OTLP_HTTP_CREDENTIAL_PROVIDER") or os.environ.get(
        "OTEL_PYTHON_EXPORTER_OTLP_HTTP_LOGS_CREDENTIAL_PROVIDER"
    ):
        raise OpenTelemetryExportError(
            "OpenTelemetry HTTP credential-provider plugins are unsupported; use explicit headers or mTLS settings"
        )


def _create_otlp_session() -> Any:
    """Validate the collector acknowledgement before the SDK counts HTTP success.

    The pinned SDK treats any successful HTTP response as full batch success,
    including OTLP partial rejection. Its public session hook lets us check the
    protobuf response without overriding the SDK's private transport methods.
    """
    import requests
    from google.protobuf.message import DecodeError
    from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceResponse

    def validate_response(response: Any, *args: Any, **kwargs: Any) -> Any:
        if response.is_redirect:
            return response
        if not 200 <= response.status_code < 300:
            # Requests follows real redirects; other 3xx responses are not OTLP
            # acknowledgements even though the SDK's Response.ok accepts them.
            if response.ok:
                raise OpenTelemetryExportError("the OTLP endpoint returned an invalid acknowledgement")
            return response
        if not response.content:
            return response
        acknowledgement = ExportLogsServiceResponse()
        try:
            acknowledgement.ParseFromString(response.content)
        except DecodeError:
            raise OpenTelemetryExportError("the OTLP endpoint returned an invalid acknowledgement") from None
        if acknowledgement.partial_success.rejected_log_records != 0:
            # Do not log the collector's error_message; it may contain payloads.
            raise OpenTelemetryExportError("the OTLP endpoint rejected one or more log records")
        return response

    session = requests.Session()
    session.hooks["response"].append(validate_response)
    return session


class _ExportStatusTracker:
    """Count successful records and track failures the batch processor ignores."""

    def __init__(self, exporter: Any, success_result: Any):
        self._exporter = exporter
        self._success_result = success_result
        self._failed = False
        self._exported_count = 0
        self._lock = threading.Lock()

    @property
    def failed(self) -> bool:
        with self._lock:
            return self._failed

    @property
    def exported_count(self) -> int:
        with self._lock:
            return self._exported_count

    def export(self, batch: Any) -> Any:
        try:
            result = self._exporter.export(batch)
        except Exception:
            with self._lock:
                self._failed = True
            raise

        with self._lock:
            if result == self._success_result:
                self._exported_count += len(batch)
            else:
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
