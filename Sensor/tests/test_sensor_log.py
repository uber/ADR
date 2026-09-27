"""Tests for the leveled sensor logger."""

import importlib
import json
import logging
import pkgutil
import sys
from unittest.mock import patch

import pytest

import adr_sensor.parsers as parsers
from adr_sensor import __version__, sensor_log
from adr_sensor.cli import main


@pytest.fixture(autouse=True)
def reset_console_level():
    yield
    sensor_log.set_console_level(logging.INFO)


def test_info_goes_to_stdout_and_warnings_to_stderr(capsys):
    log = logging.getLogger("adr_sensor.parsers.example")
    log.info("[EXAMPLE] parsed 2 sessions")
    log.warning("[EXAMPLE] skipped unreadable file")
    log.error("[EXAMPLE] database error")

    captured = capsys.readouterr()
    assert captured.out == "[EXAMPLE] parsed 2 sessions\n"
    assert captured.err == "[EXAMPLE] skipped unreadable file\n[EXAMPLE] database error\n"


def test_debug_is_hidden_by_default(capsys):
    logging.getLogger("adr_sensor.observer").debug("detail")
    assert capsys.readouterr().out == ""


def test_set_console_level_accepts_names_and_constants(capsys):
    log = logging.getLogger("adr_sensor.observer")
    sensor_log.set_console_level("debug")
    log.debug("detail")
    sensor_log.set_console_level(logging.WARNING)
    log.info("hidden")
    log.warning("shown")

    captured = capsys.readouterr()
    assert captured.out == "detail\n"
    assert captured.err == "shown\n"


def test_set_console_level_rejects_unknown_names():
    with pytest.raises(ValueError):
        sensor_log.set_console_level("chatty")


def test_console_handlers_are_installed_once():
    handlers = sensor_log._console_handlers()
    sensor_log._install_console_handlers()
    assert sensor_log._console_handlers() == handlers
    assert len(handlers) == 2


def test_sensor_records_do_not_propagate_to_root():
    received = []

    class _Collect(logging.Handler):
        def emit(self, record):
            received.append(record)

    root_handler = _Collect()
    logging.getLogger().addHandler(root_handler)
    try:
        logging.getLogger("adr_sensor.cli").warning("only on the sensor console")
    finally:
        logging.getLogger().removeHandler(root_handler)
    assert received == []


@pytest.mark.parametrize(
    "name, component",
    [
        ("adr_sensor", "sensor"),
        ("adr_sensor.observer", "observer"),
        ("adr_sensor.parsers.claude_parser", "parsers.claude_parser"),
        ("other.module", "other.module"),
    ],
)
def test_component_is_derived_from_logger_name(name, component):
    record = logging.LogRecord(name, logging.INFO, "", 0, "msg", (), None)
    assert sensor_log.component_for(record) == component


def test_append_rotating_line_appends_lines(tmp_path):
    path = tmp_path / "resource.log"
    sensor_log.append_rotating_line(path, '{"n":1}')
    sensor_log.append_rotating_line(path, '{"n":2}')
    assert path.read_text(encoding="utf-8") == '{"n":1}\n{"n":2}\n'


def test_append_rotating_line_rotates_by_size_and_keeps_backups(tmp_path):
    path = tmp_path / "resource.log"
    for index in range(6):
        sensor_log.append_rotating_line(path, f"line-{index}-" + "x" * 20, max_bytes=40, backup_count=2)
    assert path.read_text(encoding="utf-8").startswith("line-5-")
    assert (tmp_path / "resource.log.1").read_text(encoding="utf-8").startswith("line-4-")
    assert (tmp_path / "resource.log.2").read_text(encoding="utf-8").startswith("line-3-")
    assert not (tmp_path / "resource.log.3").exists()


def test_append_rotating_line_raises_when_the_file_cannot_be_written(tmp_path):
    with pytest.raises(OSError):
        sensor_log.append_rotating_line(tmp_path / "missing" / "resource.log", "line")


@pytest.mark.parametrize(
    "flags, level",
    [([], logging.INFO), (["--log-level", "debug"], logging.DEBUG), (["-q"], logging.WARNING)],
)
def test_cli_flags_set_the_console_level(flags, level, monkeypatch):
    monkeypatch.setattr("sys.argv", ["adr-sensor", "--no-save", *flags])
    with patch("adr_sensor.cli.AgentObserver") as observer_cls:
        observer_cls.return_value.ingest_all.side_effect = RuntimeError("stop after argument parsing")
        observer_cls.return_value.get_diagnostic_records.return_value = []
        with pytest.raises(RuntimeError):
            main()
    assert {handler.level for handler in sensor_log._console_handlers()} == {level}


def test_cli_rejects_quiet_with_log_level(monkeypatch):
    monkeypatch.setattr("sys.argv", ["adr-sensor", "-q", "--log-level", "debug"])
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 2


def test_every_parser_logs_through_a_sensor_child_logger():
    for module_info in pkgutil.iter_modules(parsers.__path__):
        if not module_info.name.endswith("_parser") or module_info.name == "base_parser":
            continue
        module = importlib.import_module(f"adr_sensor.parsers.{module_info.name}")
        assert module.logger.name == f"adr_sensor.parsers.{module_info.name}"


def _record(msg="[EXAMPLE] Error reading %s: %s", args=("/tmp/example.jsonl", OSError("denied")), **extra):
    record = logging.LogRecord("adr_sensor.parsers.example_parser", logging.WARNING, "", 0, msg, args, None)
    record.funcName = "parse_all"
    record.__dict__.update(extra)
    return record


def test_json_formatter_includes_the_message_by_default():
    data = json.loads(sensor_log.JsonRecordFormatter().format(_record(phase="parse")))
    assert data["level"] == "WARNING"
    assert data["component"] == "parsers.example_parser"
    assert data["function"] == "parse_all"
    assert data["phase"] == "parse"
    assert data["sensor_version"] == __version__
    assert data["exception_type"] == "OSError"
    assert data["message"] == "[EXAMPLE] Error reading /tmp/example.jsonl: denied"
    assert "stack" not in data


def test_json_formatter_includes_the_stack_of_an_attached_exception():
    try:
        raise ValueError("synthetic")
    except ValueError:
        record = _record(msg="failed", args=())
        record.exc_info = sys.exc_info()
    data = json.loads(sensor_log.JsonRecordFormatter().format(record))
    assert data["exception_type"] == "ValueError"
    assert "Traceback" in data["stack"]
    assert data["stack"].rstrip().endswith("ValueError: synthetic")


def test_json_formatter_can_omit_message_and_stack():
    try:
        raise ValueError("SECRET_CANARY")
    except ValueError:
        record = _record()
        record.exc_info = sys.exc_info()
    line = sensor_log.JsonRecordFormatter(include_details=False).format(record)
    data = json.loads(line)
    assert "message" not in data and "stack" not in data
    assert data["exception_type"] == "ValueError"
    assert "SECRET_CANARY" not in line and "/tmp/example.jsonl" not in line


@pytest.fixture
def runtime_log(tmp_path):
    yield tmp_path
    sensor_log.disable_runtime_log()


def _lines(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_runtime_log_splits_records_by_level(runtime_log, capsys):
    assert sensor_log.enable_runtime_log(runtime_log)
    log = logging.getLogger("adr_sensor.observer")
    log.debug("detail")
    log.info("progress")
    log.warning("skipped")
    log.error("failed")
    sensor_log.disable_runtime_log()

    debug = _lines(runtime_log / "sensor_runtime_debug.jsonl")
    errors = _lines(runtime_log / "sensor_runtime_errors.jsonl")
    assert [(r["level"], r["message"]) for r in debug] == [("DEBUG", "detail"), ("INFO", "progress")]
    assert [(r["level"], r["message"]) for r in errors] == [("WARNING", "skipped"), ("ERROR", "failed")]
    assert "detail" not in capsys.readouterr().out


def test_runtime_log_can_be_content_free(runtime_log):
    sensor_log.enable_runtime_log(runtime_log, include_details=False)
    logging.getLogger("adr_sensor.observer").warning("Error saving session %s", "SECRET_CANARY")
    sensor_log.disable_runtime_log()
    text = (runtime_log / "sensor_runtime_errors.jsonl").read_text(encoding="utf-8")
    assert "SECRET_CANARY" not in text
    assert json.loads(text)["component"] == "observer"


def test_enabling_the_runtime_log_again_replaces_the_files(runtime_log):
    sensor_log.enable_runtime_log(runtime_log / "first")
    sensor_log.enable_runtime_log(runtime_log / "second")
    logging.getLogger("adr_sensor.cli").warning("once")
    sensor_log.disable_runtime_log()
    assert len(sensor_log._runtime_handlers()) == 0
    assert (runtime_log / "first" / "sensor_runtime_errors.jsonl").read_text() == ""
    assert len(_lines(runtime_log / "second" / "sensor_runtime_errors.jsonl")) == 1


def test_runtime_log_rotates_by_size(runtime_log, monkeypatch):
    monkeypatch.setattr(sensor_log, "MAX_LOG_BYTES", 200)
    sensor_log.enable_runtime_log(runtime_log)
    for index in range(10):
        logging.getLogger("adr_sensor.cli").warning("record %d", index)
    sensor_log.disable_runtime_log()
    assert (runtime_log / "sensor_runtime_errors.jsonl.1").exists()
    assert (runtime_log / "sensor_runtime_errors.jsonl.2").exists()
    assert not (runtime_log / "sensor_runtime_errors.jsonl.3").exists()


def test_unwritable_runtime_log_falls_back_to_stderr(runtime_log, capsys):
    blocked = runtime_log / "blocked"
    blocked.write_text("not a directory", encoding="utf-8")
    assert sensor_log.enable_runtime_log(blocked) is False
    logging.getLogger("adr_sensor.cli").error("still visible")
    err = capsys.readouterr().err
    assert "Unable to open the runtime log" in err
    assert "still visible" in err
    assert sensor_log._runtime_handlers() == []


def test_runtime_log_write_failure_is_reported_once(runtime_log, capsys):
    sensor_log.enable_runtime_log(runtime_log)
    class _FullDisk:
        def write(self, text):
            raise OSError("no space left on device")

        def flush(self):
            raise OSError("no space left on device")

    for handler in sensor_log._runtime_handlers():
        handler.stream.close()
        handler.stream = _FullDisk()
    log = logging.getLogger("adr_sensor.cli")
    log.warning("first")
    log.warning("second")
    err = capsys.readouterr().err
    assert err.count("Unable to write the runtime log sensor_runtime_errors.jsonl") == 1
    assert "first\n" in err and "second\n" in err


def _run_cli(tmp_path, monkeypatch, *flags):
    def ingest_all(source):
        logging.getLogger("adr_sensor.parsers.example_parser").warning(
            "[EXAMPLE] Error reading %s: %s", "/synthetic/path.jsonl", OSError("denied")
        )
        return [], []

    monkeypatch.setattr("sys.argv", ["adr-sensor", "--no-save", "--output-dir", str(tmp_path), *flags])
    with patch("adr_sensor.cli.AgentObserver") as observer_cls:
        observer_cls.return_value.has_errors = False
        observer_cls.return_value.ingest_all.side_effect = ingest_all
        main()


def test_cli_log_file_writes_runtime_logs_to_the_output_dir(tmp_path, monkeypatch):
    _run_cli(tmp_path, monkeypatch, "--log-file")
    errors = _lines(tmp_path / "sensor_runtime_errors.jsonl")
    assert errors[0]["message"] == "[EXAMPLE] Error reading /synthetic/path.jsonl: denied"
    assert any(r["message"].strip() == "ADR Sensor complete!" for r in _lines(tmp_path / "sensor_runtime_debug.jsonl"))
    assert sensor_log._runtime_handlers() == []


def test_cli_log_file_content_free_omits_messages(tmp_path, monkeypatch):
    _run_cli(tmp_path, monkeypatch, "--log-file", "--log-file-content-free")
    text = (tmp_path / "sensor_runtime_errors.jsonl").read_text(encoding="utf-8")
    assert "/synthetic/path.jsonl" not in text
    assert json.loads(text)["exception_type"] == "OSError"


def test_cli_writes_no_runtime_log_by_default(tmp_path, monkeypatch):
    _run_cli(tmp_path, monkeypatch)
    assert not list(tmp_path.glob("sensor_runtime_*"))


def test_cli_log_file_content_free_requires_log_file(monkeypatch):
    monkeypatch.setattr("sys.argv", ["adr-sensor", "--log-file-content-free"])
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 2
