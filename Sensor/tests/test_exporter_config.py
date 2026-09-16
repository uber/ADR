"""Tests for OpenTelemetry exporter configuration."""

import json
import re
from pathlib import Path

import pytest

from adr_sensor.exporters import OpenTelemetryConfigError, load_opentelemetry_config


def _write_config(path: Path, document) -> Path:
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_load_opentelemetry_config_defaults(tmp_path):
    config = load_opentelemetry_config(
        _write_config(tmp_path / "otel.json", {"endpoint": "http://localhost:4318/v1/logs"})
    )

    assert config.endpoint == "http://localhost:4318/v1/logs"
    assert config.service_name == "adr-sensor"
    assert config.headers == {}
    assert config.timeout_seconds == 10.0
    assert config.flush_timeout_seconds == 30.0
    assert config.certificate_file is None


def test_load_opentelemetry_config_all_fields(tmp_path):
    certificate = tmp_path / "collector-ca.pem"
    certificate.write_text("test certificate", encoding="utf-8")
    config = load_opentelemetry_config(
        _write_config(
            tmp_path / "otel.json",
            {
                "endpoint": "https://collector.example.test/v1/logs",
                "service_name": "workstation-sensor",
                "headers": {"Authorization": "Bearer test-token"},
                "timeout_seconds": 5,
                "flush_timeout_seconds": 12.5,
                "certificate_file": certificate.name,
            },
        )
    )

    assert config.service_name == "workstation-sensor"
    assert config.headers == {"Authorization": "Bearer test-token"}
    assert config.timeout_seconds == 5.0
    assert config.flush_timeout_seconds == 12.5
    assert config.certificate_file == str(certificate.resolve())


@pytest.mark.parametrize(
    "document, message",
    [
        ({}, "endpoint must be a non-empty string"),
        ({"endpoint": "localhost:4318"}, "absolute HTTP(S) URL"),
        ({"endpoint": "ftp://collector.test/logs"}, "absolute HTTP(S) URL"),
        ({"endpoint": "http://localhost:4318/v1/logs", "headers": []}, "headers must be an object"),
        ({"endpoint": "http://localhost:4318/v1/logs", "timeout_seconds": 0}, "positive number"),
        ({"endpoint": "http://localhost:4318/v1/logs", "timeout_seconds": float("nan")}, "positive number"),
        ({"endpoint": "http://localhost:4318/v1/logs", "unexpected": True}, "unknown"),
    ],
)
def test_load_opentelemetry_config_rejects_invalid_values(tmp_path, document, message):
    config_path = _write_config(tmp_path / "otel.json", document)

    with pytest.raises(OpenTelemetryConfigError, match=re.escape(message)):
        load_opentelemetry_config(config_path)


def test_load_opentelemetry_config_rejects_missing_certificate(tmp_path):
    config_path = _write_config(
        tmp_path / "otel.json",
        {
            "endpoint": "https://collector.example.test/v1/logs",
            "certificate_file": "missing.pem",
        },
    )

    with pytest.raises(OpenTelemetryConfigError, match="certificate file does not exist"):
        load_opentelemetry_config(config_path)


def test_load_opentelemetry_config_rejects_missing_file(tmp_path):
    with pytest.raises(OpenTelemetryConfigError, match="cannot read"):
        load_opentelemetry_config(tmp_path / "missing.json")
