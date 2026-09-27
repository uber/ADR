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

import json
import logging
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

from . import __version__

LOGGER_NAME = "adr_sensor"

# Size-based rotation shared by the sensor's append-only files.
MAX_LOG_BYTES = 1024 * 1024
LOG_BACKUP_COUNT = 2

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


def _exception_type(record: logging.LogRecord):
    """Name the exception attached to *record*, or the first one passed as an argument."""
    if record.exc_info and record.exc_info[0] is not None:
        return record.exc_info[0].__name__
    args = record.args if isinstance(record.args, tuple) else ()
    for arg in args:
        if isinstance(arg, BaseException):
            return type(arg).__name__
    return None


class JsonRecordFormatter(logging.Formatter):
    """Format records as one JSON object per line for the runtime log files.

    Every record carries ``timestamp``, ``level``, ``component``, ``function``,
    ``phase``, ``sensor_version`` and ``exception_type``. The rendered
    ``message`` and, when an exception is attached, its ``stack`` are included
    unless *include_details* is false, which keeps records free of paths and
    error text.
    """

    def __init__(self, *, include_details: bool = True) -> None:
        super().__init__()
        self.include_details = include_details

    def format(self, record: logging.LogRecord) -> str:
        data = {
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "component": component_for(record),
            "function": record.funcName,
            "phase": getattr(record, "phase", None),
            "sensor_version": __version__,
            "exception_type": _exception_type(record),
        }
        if self.include_details:
            data["message"] = record.getMessage()
            if record.exc_info:
                data["stack"] = self.formatException(record.exc_info)
        return json.dumps(data, ensure_ascii=False, separators=(",", ":"), default=str)


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


def append_rotating_line(
    path: Path, line: str, *, max_bytes: int = MAX_LOG_BYTES, backup_count: int = LOG_BACKUP_COUNT
) -> None:
    """Append one line to *path*, rotating it by size first when needed.

    Rotation renames the active file to ``<name>.1`` (and so on up to
    *backup_count*) instead of rewriting it, so tailing readers never see a
    truncated file. Use one sensor process per output directory: rotation is
    not coordinated between concurrent writers.
    """
    handler = RotatingFileHandler(Path(path), maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))

    # Handler.emit normally reports write failures itself; let the caller decide.
    def handle_error(record):
        raise OSError("rotating append failed")

    handler.handleError = handle_error
    try:
        handler.handle(logging.LogRecord(LOGGER_NAME, logging.INFO, "", 0, line, (), None))
    finally:
        handler.close()


logger.setLevel(logging.DEBUG)
# The sensor owns its console output; do not duplicate it through the root logger.
logger.propagate = False
_install_console_handlers()
set_console_level(logging.INFO)
