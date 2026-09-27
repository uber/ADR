"""Leveled runtime logging for the ADR Sensor.

Modules log through a child of the ``adr_sensor`` logger, normally
``logging.getLogger(__name__)``, instead of calling ``print()``. The component
of a record is derived from the logger name, and an optional ``phase`` can be
passed via ``extra``::

    import logging

    logger = logging.getLogger(__name__)
    logger.warning("[CLAUDE] Skipped unreadable transcript", extra={"phase": "parse"})

Console output keeps the sensor's historical behaviour: records below WARNING
are written to stdout and WARNING or above to stderr, as the bare message. The
handlers are installed when this module is imported so library callers see the
same output as before; ``set_console_level()`` changes the threshold.

Runtime logs are separate from the content-free health records written by
``diagnostics.py``: they describe what the sensor did, not how healthy a run was.
"""

import logging
import sys

LOGGER_NAME = "adr_sensor"

logger = logging.getLogger(LOGGER_NAME)


class _StdStreamHandler(logging.StreamHandler):
    """Write to ``sys.stdout``/``sys.stderr`` as they are at emit time.

    Resolving the stream on every record keeps output working when the
    standard streams are replaced after import (for example by test capture).
    """

    def __init__(self, stream_name: str) -> None:
        super().__init__(getattr(sys, stream_name))
        self.stream_name = stream_name

    def emit(self, record: logging.LogRecord) -> None:
        self.stream = getattr(sys, self.stream_name)
        super().emit(record)


class _BelowWarningFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno < logging.WARNING


class _WarningAndAboveFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno >= logging.WARNING


def component_for(record: logging.LogRecord) -> str:
    """Return the record's component: its logger name below ``adr_sensor``."""
    name = record.name
    if name == LOGGER_NAME:
        return "sensor"
    prefix = LOGGER_NAME + "."
    return name[len(prefix) :] if name.startswith(prefix) else name


def _console_handlers():
    return [handler for handler in logger.handlers if isinstance(handler, _StdStreamHandler)]


def _install_console_handlers() -> None:
    """Attach the stdout/stderr handlers once; repeated calls are no-ops."""
    if _console_handlers():
        return
    formatter = logging.Formatter("%(message)s")
    stdout_handler = _StdStreamHandler("stdout")
    stdout_handler.addFilter(_BelowWarningFilter())
    stderr_handler = _StdStreamHandler("stderr")
    stderr_handler.addFilter(_WarningAndAboveFilter())
    for handler in (stdout_handler, stderr_handler):
        handler.setFormatter(formatter)
        logger.addHandler(handler)


def set_console_level(level) -> None:
    """Set the minimum level printed to the console (name or ``logging`` constant)."""
    if isinstance(level, str):
        level = logging.getLevelName(level.upper())
    if not isinstance(level, int):
        raise ValueError(f"unknown log level: {level!r}")
    for handler in _console_handlers():
        handler.setLevel(level)


logger.setLevel(logging.DEBUG)
# The sensor owns its console output; do not duplicate it through the root logger.
logger.propagate = False
_install_console_handlers()
set_console_level(logging.INFO)
