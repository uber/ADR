"""Synthetic incremental-delivery tests; no collector or real sessions needed."""

import json
import re
from dataclasses import replace
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest, ExportLogsServiceResponse
from requests import Response

from adr_sensor.cli import main
from adr_sensor.diagnostics import health_record
from adr_sensor.exporters.config import OpenTelemetryConfig
from adr_sensor.exporters.delivery_checkpoint import DeliveryCheckpoint, DeliveryCheckpointError
from adr_sensor.exporters.opentelemetry import OpenTelemetryExportError
from adr_sensor.schemas.agent_event_schema import AgentEvent, ChatMessage, ToolUsage


@pytest.fixture
def event():
    return AgentEvent(
        timestamp=datetime(2026, 9, 9, tzinfo=timezone.utc),
        source="codex",
        session_id="synthetic-private-session",
        hostname="synthetic-host",
        username="synthetic-user",
        chat_history=[
            ChatMessage(
                role="assistant",
                content="synthetic private text",
                tools=[ToolUsage(tool_name="shell", tool_type="custom", result="first synthetic result")],
            )
        ],
    )


@pytest.fixture
def config():
    return OpenTelemetryConfig(
        endpoint="https://collector.example.invalid/v1/logs",
        headers={"Authorization": "Bearer synthetic-secret"},
    )


def test_checkpoint_skips_only_successfully_committed_payloads(tmp_path, config, event):
    checkpoint = DeliveryCheckpoint(tmp_path, config)
    assert checkpoint.pending_entries([event]) == [event]
    assert not checkpoint.path.exists()
    assert DeliveryCheckpoint(tmp_path, config).pending_entries([event]) == [event]

    checkpoint.commit()

    assert DeliveryCheckpoint(tmp_path, config).pending_entries([event]) == []


@pytest.mark.parametrize("changed_field", ["tool_result", "tool_status", "model", "session_context"])
def test_checkpoint_hashes_complete_normalized_payload(tmp_path, config, event, changed_field):
    checkpoint = DeliveryCheckpoint(tmp_path, config)
    checkpoint.pending_entries([event])
    checkpoint.commit()
    original_uuid = event.uuid
    if changed_field == "tool_result":
        event.chat_history[0].tools[0] = replace(event.chat_history[0].tools[0], result="updated synthetic result")
    elif changed_field == "tool_status":
        event.chat_history[0].tools[0] = replace(event.chat_history[0].tools[0], status="error")
    elif changed_field == "model":
        event = replace(event, model="changed-model")
    else:
        event = replace(event, session_context={"changed": True})

    assert event.uuid == original_uuid
    assert DeliveryCheckpoint(tmp_path, config).pending_entries([event]) == [event]


@pytest.mark.parametrize(
    "settings",
    [
        {"endpoint": "https://other.example.invalid/v1/logs"},
        {"headers": {"Authorization": "Bearer other-synthetic-secret"}},
        {"service_name": "another-service"},
    ],
)
def test_destination_or_authentication_change_resends_sessions(tmp_path, config, event, settings):
    checkpoint = DeliveryCheckpoint(tmp_path, config)
    checkpoint.pending_entries([event])
    checkpoint.commit()
    changed = DeliveryCheckpoint(tmp_path, replace(config, **settings))

    assert changed.path != checkpoint.path
    assert changed.pending_entries([event]) == [event]


def test_environment_authentication_change_resends_sessions(tmp_path, event, monkeypatch):
    config = OpenTelemetryConfig(endpoint="https://collector.example.invalid/v1/logs")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_LOGS_HEADERS", "Authorization=first-synthetic-token")
    checkpoint = DeliveryCheckpoint(tmp_path, config)
    checkpoint.pending_entries([event])
    checkpoint.commit()
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_LOGS_HEADERS", "Authorization=second-synthetic-token")

    assert DeliveryCheckpoint(tmp_path, config).pending_entries([event]) == [event]


@pytest.mark.parametrize("prefix", ["OTEL_EXPORTER_OTLP", "OTEL_EXPORTER_OTLP_LOGS"])
@pytest.mark.parametrize("setting", ["CLIENT_CERTIFICATE", "CLIENT_KEY"])
def test_environment_mtls_path_change_resends_sessions(tmp_path, config, event, monkeypatch, prefix, setting):
    variable = f"{prefix}_{setting}"
    monkeypatch.setenv(variable, "/synthetic/first-credential.pem")
    checkpoint = DeliveryCheckpoint(tmp_path, config)
    checkpoint.pending_entries([event])
    checkpoint.commit()
    monkeypatch.setenv(variable, "/synthetic/second-credential.pem")
    changed = DeliveryCheckpoint(tmp_path, config)

    assert changed.path != checkpoint.path
    assert changed.pending_entries([event]) == [event]


def test_checkpoint_uses_effective_mtls_settings(tmp_path, config, monkeypatch):
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE", "/synthetic/generic-cert.pem")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_LOGS_CLIENT_CERTIFICATE", "/synthetic/logs-cert.pem")
    checkpoint = DeliveryCheckpoint(tmp_path, config)
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE", "/synthetic/unused-cert.pem")

    assert DeliveryCheckpoint(tmp_path, config).path == checkpoint.path


def test_opaque_credential_provider_cannot_skip_previously_delivered_sessions(tmp_path, config, event, monkeypatch):
    checkpoint = DeliveryCheckpoint(tmp_path, config)
    checkpoint.pending_entries([event])
    checkpoint.commit()
    monkeypatch.setenv("OTEL_PYTHON_EXPORTER_OTLP_HTTP_LOGS_CREDENTIAL_PROVIDER", "synthetic-private-provider")

    with pytest.raises(OpenTelemetryExportError, match="credential-provider plugins are unsupported"):
        DeliveryCheckpoint(tmp_path, config)


def test_checkpoint_persists_only_hashes(tmp_path, config, event):
    checkpoint = DeliveryCheckpoint(tmp_path, config)
    checkpoint.pending_entries([event])
    checkpoint.commit()

    assert re.fullmatch(r"\.adr-otel-delivery\.[0-9a-f]{64}\.json", checkpoint.path.name)
    data = json.loads(checkpoint.path.read_text())
    assert len(data) == 1
    assert all(re.fullmatch(r"[0-9a-f]{64}", digest) for pair in data.items() for digest in pair)


@pytest.mark.parametrize("contents", ["broken JSON", "[]", '{"raw-session": "raw-content"}', "\udcff"])
def test_corrupt_checkpoint_retries_and_can_be_replaced(tmp_path, config, event, contents):
    path = DeliveryCheckpoint(tmp_path, config).path
    path.write_bytes(contents.encode("utf-8", errors="surrogateescape"))

    checkpoint = DeliveryCheckpoint(tmp_path, config)
    assert checkpoint.load_failed
    assert checkpoint.pending_entries([event]) == [event]
    checkpoint.commit()
    assert DeliveryCheckpoint(tmp_path, config).pending_entries([event]) == []


def test_unreadable_checkpoint_retries(tmp_path, config, event):
    with patch("pathlib.Path.open", side_effect=PermissionError("synthetic private path")):
        checkpoint = DeliveryCheckpoint(tmp_path, config)
    assert checkpoint.load_failed
    assert checkpoint.pending_entries([event]) == [event]


def test_atomic_replace_failure_keeps_previous_checkpoint_and_retries(tmp_path, config, event):
    checkpoint = DeliveryCheckpoint(tmp_path, config)
    checkpoint.pending_entries([event])
    checkpoint.commit()
    previous = checkpoint.path.read_bytes()
    event.chat_history[0].tools[0] = replace(event.chat_history[0].tools[0], result="changed result")
    checkpoint.pending_entries([event])

    with (
        patch("adr_sensor.exporters.delivery_checkpoint.os.replace", side_effect=OSError("synthetic private path")),
        pytest.raises(DeliveryCheckpointError, match="could not save") as error,
    ):
        checkpoint.commit()

    assert "synthetic private path" not in str(error.value)
    assert checkpoint.path.read_bytes() == previous
    assert not list(tmp_path.glob("*.tmp"))
    assert DeliveryCheckpoint(tmp_path, config).pending_entries([event]) == [event]


def _prepare_cli(observer, event, tmp_path, monkeypatch, extra_args=()):
    observer.ingest_all.return_value = ([event], [])
    observer.get_diagnostic_records.return_value = [health_record("codex", "parse", counts={"events_emitted": 1})]
    local_file = tmp_path / "synthetic-session.json"
    observer.filter_entries_by_existing_files.side_effect = lambda entries, _: [] if local_file.exists() else entries

    def save_sessions(entries, output_dir):
        local_file.write_text(json.dumps(entries[0].get_non_null_fields()))
        return [local_file]

    observer.save_sessions_to_individual_files.side_effect = save_sessions
    monkeypatch.setattr(
        "sys.argv",
        [
            "adr-sensor",
            "--save-sessions",
            "--output-dir",
            str(tmp_path),
            "--otel-config",
            "synthetic.json",
            *extra_args,
        ],
    )
    return local_file


@patch("adr_sensor.cli.OpenTelemetryLogExporter")
@patch("adr_sensor.cli.load_opentelemetry_config")
@patch("adr_sensor.cli.AgentObserver")
def test_cli_failed_delivery_retries_then_skips_unchanged(
    observer_cls, load_config, exporter_cls, tmp_path, config, event, monkeypatch
):
    load_config.return_value = config
    observer = observer_cls.return_value
    local_file = _prepare_cli(observer, event, tmp_path, monkeypatch)
    exporter = exporter_cls.return_value
    exporter.export.return_value = 1
    exporter.shutdown.side_effect = [OpenTelemetryExportError("synthetic delivery failure"), None, None]

    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 1
    assert local_file.exists()
    assert not list(tmp_path.glob(".adr-otel-delivery.*.json"))

    main()
    main()

    assert exporter_cls.call_count == 3
    assert exporter.export.call_count == 3
    assert [call.args for call in exporter.export.call_args_list] == [([event], []), ([event], []), ([], [])]
    assert exporter.export_diagnostics.call_count == 3
    assert observer.save_sessions_to_individual_files.call_count == 1
    assert DeliveryCheckpoint(tmp_path, config).pending_entries([event]) == []


@patch("adr_sensor.cli.OpenTelemetryLogExporter")
@patch("adr_sensor.cli.load_opentelemetry_config")
@patch("adr_sensor.cli.AgentObserver")
def test_cli_checkpoint_write_failure_is_reported_and_retried(
    observer_cls, load_config, exporter_cls, tmp_path, config, event, monkeypatch, capsys
):
    load_config.return_value = config
    _prepare_cli(observer_cls.return_value, event, tmp_path, monkeypatch)
    exporter_cls.return_value.export.return_value = 1
    with patch("adr_sensor.exporters.delivery_checkpoint.os.replace", side_effect=OSError("synthetic private path")):
        with pytest.raises(SystemExit) as error:
            main()

    assert error.value.code == 1
    stderr = capsys.readouterr().err
    assert "OpenTelemetry checkpoint failed" in stderr
    assert "synthetic private path" not in stderr
    assert not list(tmp_path.glob(".adr-otel-delivery.*.json"))
    main()
    assert exporter_cls.return_value.export.call_count == 2


@patch("adr_sensor.cli.OpenTelemetryLogExporter")
@patch("adr_sensor.cli.load_opentelemetry_config")
@patch("adr_sensor.cli.AgentObserver")
def test_cli_no_save_does_not_read_or_write_delivery_state(
    observer_cls, load_config, exporter_cls, tmp_path, config, event, monkeypatch
):
    load_config.return_value = config
    _prepare_cli(observer_cls.return_value, event, tmp_path, monkeypatch, extra_args=["--no-save"])
    checkpoint = DeliveryCheckpoint(tmp_path, config)
    checkpoint.pending_entries([event])
    checkpoint.commit()
    original = checkpoint.path.read_bytes()
    exporter_cls.return_value.export.return_value = 1

    main()

    exporter_cls.return_value.export.assert_called_once_with([event], [])
    observer_cls.return_value.save_sessions_to_individual_files.assert_not_called()
    assert checkpoint.path.read_bytes() == original


@patch("adr_sensor.cli.load_opentelemetry_config")
@patch("adr_sensor.cli.AgentObserver")
def test_cli_partial_rejection_does_not_checkpoint_and_next_run_retries(
    observer_cls, load_config, tmp_path, config, event, monkeypatch, caplog
):
    load_config.return_value = config
    local_file = _prepare_cli(observer_cls.return_value, event, tmp_path, monkeypatch)
    rejected = Response()
    rejected.status_code = 200
    rejected._content = ExportLogsServiceResponse(
        partial_success={"rejected_log_records": 1, "error_message": "synthetic private collector response"}
    ).SerializeToString()
    accepted = Response()
    accepted.status_code = 200
    accepted._content = b""

    with patch("requests.adapters.HTTPAdapter.send", side_effect=[rejected, accepted, accepted]) as transport:
        with pytest.raises(SystemExit) as error:
            main()
        assert error.value.code == 1
        assert local_file.exists()
        assert not list(tmp_path.glob(".adr-otel-delivery.*.json"))

        main()
        main()

    assert transport.call_count == 3
    requests = [ExportLogsServiceRequest.FromString(call.args[0].body) for call in transport.call_args_list]
    event_names = [
        [
            record.event_name
            for resource in request.resource_logs
            for scope in resource.scope_logs
            for record in scope.log_records
        ]
        for request in requests
    ]
    assert event_names == [
        ["adr.agent.session", "adr.sensor.health"],
        ["adr.agent.session", "adr.sensor.health"],
        ["adr.sensor.health"],
    ]
    assert DeliveryCheckpoint(tmp_path, config).pending_entries([event]) == []
    assert "synthetic private collector response" not in caplog.text
