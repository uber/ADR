"""Configuration loading for the optional OpenTelemetry exporter."""

import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional
from urllib.parse import urlparse

MAX_CONFIG_SIZE = 1024 * 1024
_CONFIG_KEYS = {
    "endpoint",
    "service_name",
    "headers",
    "timeout_seconds",
    "flush_timeout_seconds",
    "certificate_file",
}


class OpenTelemetryConfigError(ValueError):
    """Raised when an OpenTelemetry configuration file is invalid."""


@dataclass(frozen=True)
class OpenTelemetryConfig:
    """Settings used to send ADR records to an OTLP/HTTP logs endpoint."""

    endpoint: str
    service_name: str = "adr-sensor"
    headers: Dict[str, str] = field(default_factory=dict)
    timeout_seconds: float = 10.0
    flush_timeout_seconds: float = 30.0
    certificate_file: Optional[str] = None


def load_opentelemetry_config(path: Path) -> OpenTelemetryConfig:
    """Load and validate an OTLP/HTTP exporter configuration from JSON."""
    config_path = Path(path)
    try:
        with open(config_path, "rb") as config_file:
            raw = config_file.read(MAX_CONFIG_SIZE + 1)
    except OSError as exc:
        raise OpenTelemetryConfigError(f"cannot read OpenTelemetry config {config_path}: {exc}") from exc

    if len(raw) > MAX_CONFIG_SIZE:
        raise OpenTelemetryConfigError(f"OpenTelemetry config exceeds {MAX_CONFIG_SIZE} bytes")

    try:
        document = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise OpenTelemetryConfigError(f"OpenTelemetry config is not valid JSON: {exc}") from exc

    if not isinstance(document, dict):
        raise OpenTelemetryConfigError("OpenTelemetry config root must be an object")

    unexpected = sorted(set(document) - _CONFIG_KEYS)
    if unexpected:
        raise OpenTelemetryConfigError(f"unknown OpenTelemetry config field(s): {', '.join(unexpected)}")

    endpoint = _required_string(document, "endpoint")
    parsed_endpoint = urlparse(endpoint)
    if parsed_endpoint.scheme not in ("http", "https") or not parsed_endpoint.netloc:
        raise OpenTelemetryConfigError("OpenTelemetry endpoint must be an absolute HTTP(S) URL")

    service_name = _optional_string(document, "service_name", "adr-sensor")
    timeout_seconds = _positive_number(document, "timeout_seconds", 10.0)
    flush_timeout_seconds = _positive_number(document, "flush_timeout_seconds", 30.0)

    headers_value = document.get("headers", {})
    if not isinstance(headers_value, dict) or not all(
        isinstance(key, str) and key and isinstance(value, str) for key, value in headers_value.items()
    ):
        raise OpenTelemetryConfigError("OpenTelemetry headers must be an object with non-empty string keys and values")

    certificate_file = document.get("certificate_file")
    if certificate_file is not None:
        if not isinstance(certificate_file, str) or not certificate_file.strip():
            raise OpenTelemetryConfigError("OpenTelemetry certificate_file must be a non-empty string")
        certificate_path = Path(certificate_file)
        if not certificate_path.is_absolute():
            certificate_path = config_path.parent / certificate_path
        certificate_file = str(certificate_path.resolve())
        if not Path(certificate_file).is_file():
            raise OpenTelemetryConfigError(f"OpenTelemetry certificate file does not exist: {certificate_file}")

    return OpenTelemetryConfig(
        endpoint=endpoint,
        service_name=service_name,
        headers=dict(headers_value),
        timeout_seconds=timeout_seconds,
        flush_timeout_seconds=flush_timeout_seconds,
        certificate_file=certificate_file,
    )


def _required_string(document: dict, key: str) -> str:
    value = document.get(key)
    if not isinstance(value, str) or not value.strip():
        raise OpenTelemetryConfigError(f"OpenTelemetry {key} must be a non-empty string")
    return value.strip()


def _optional_string(document: dict, key: str, default: str) -> str:
    if key not in document:
        return default
    return _required_string(document, key)


def _positive_number(document: dict, key: str, default: float) -> float:
    value = document.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
        raise OpenTelemetryConfigError(f"OpenTelemetry {key} must be a positive number")
    return float(value)
