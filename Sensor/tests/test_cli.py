from importlib.metadata import version
from unittest.mock import MagicMock, patch

import pytest

from adr_sensor.cli import get_version, main
from adr_sensor.exporters import OpenTelemetryConfigError


def test_cli_version_matches_package_metadata():
    assert get_version() == version("adr-sensor")


@patch("adr_sensor.cli.OpenTelemetryLogExporter")
@patch("adr_sensor.cli.load_opentelemetry_config")
@patch("adr_sensor.cli.AgentObserver")
def test_cli_does_not_load_or_export_opentelemetry_without_config(observer_cls, load_config, exporter_cls, monkeypatch):
    observer_cls.return_value.ingest_all.return_value = ([], [])
    monkeypatch.setattr("sys.argv", ["adr-sensor", "--no-save"])

    main()

    load_config.assert_not_called()
    exporter_cls.assert_not_called()


@patch("adr_sensor.cli.OpenTelemetryLogExporter")
@patch("adr_sensor.cli.load_opentelemetry_config")
@patch("adr_sensor.cli.AgentObserver")
def test_cli_exports_and_shuts_down_when_config_is_provided(observer_cls, load_config, exporter_cls, monkeypatch):
    event = MagicMock()
    observer_cls.return_value.ingest_all.return_value = ([event], [])
    config = MagicMock()
    load_config.return_value = config
    exporter = exporter_cls.return_value
    exporter.export.return_value = 1
    monkeypatch.setattr(
        "sys.argv",
        ["adr-sensor", "--no-save", "--otel-config", "otel.json"],
    )

    main()

    load_config.assert_called_once()
    exporter_cls.assert_called_once_with(config, service_version=get_version())
    exporter.export.assert_called_once_with([event], [])
    exporter.shutdown.assert_called_once_with()


@patch("adr_sensor.cli.OpenTelemetryLogExporter")
@patch("adr_sensor.cli.load_opentelemetry_config")
def test_cli_rejects_invalid_opentelemetry_config(load_config, exporter_cls, monkeypatch):
    load_config.side_effect = OpenTelemetryConfigError("invalid exporter config")
    monkeypatch.setattr("sys.argv", ["adr-sensor", "--otel-config", "otel.json"])

    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 2
    exporter_cls.assert_not_called()
