"""Tests for the leveled sensor logger."""

import logging

import pytest

from adr_sensor import sensor_log


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
