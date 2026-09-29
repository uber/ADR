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

import getpass
import json
import logging
import socket
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

from . import __version__

LOGGER_NAME = "adr_sensor"
RUNTIME_ERRORS_LOG = "sensor_runtime_errors.jsonl"
RUNTIME_DEBUG_LOG = "sensor_runtime_debug.jsonl"

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


def _local_identity():
    """Return the local ``(username, hostname)``, with ``None`` for unknown parts."""
    try:
        username = getpass.getuser()
    except Exception:
        username = None
    try:
        hostname = socket.gethostname() or None
    except OSError:
        hostname = None
    return username, hostname


class JsonRecordFormatter(logging.Formatter):
    """Format records as one JSON object per line for the runtime log files.

    Every record carries ``timestamp``, ``level``, ``component``, ``function``,
    ``phase``, ``sensor_version`` and ``exception_type``. The rendered
    ``message`` and, when an exception is attached, its ``stack`` are included
    unless *include_details* is false, which keeps records free of paths and
    error text. *include_identity* adds the local ``username`` and ``hostname``,
    looked up once.
    """

    def __init__(self, *, include_details: bool = True, include_identity: bool = False) -> None:
        super().__init__()
        self.include_details = include_details
        self.identity = _local_identity() if include_identity else None

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
        if self.identity is not None:
            data["username"], data["hostname"] = self.identity
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


class _RuntimeFileHandler(RotatingFileHandler):
    """Rotating runtime log file that never interrupts or floods a run."""

    def handleError(self, record: logging.LogRecord) -> None:
        if getattr(self, "_reported_error", False):
            return
        self._reported_error = True
        sys.stderr.write(f"[ADR] Unable to write the runtime log {Path(self.baseFilename).name}; continuing.\n")


def _runtime_handlers():
    return [handler for handler in logger.handlers if isinstance(handler, _RuntimeFileHandler)]


def disable_runtime_log() -> None:
    """Detach and close the runtime log files, if any."""
    for handler in _runtime_handlers():
        logger.removeHandler(handler)
        try:
            handler.close()
        except (OSError, ValueError):
            pass


def enable_runtime_log(directory: Path, *, include_details: bool = True, include_identity: bool = False) -> bool:
    """Also write sensor log records to rotating JSON-lines files in *directory*.

    WARNING and above go to ``sensor_runtime_errors.jsonl``; DEBUG and INFO go
    to ``sensor_runtime_debug.jsonl`` whatever the console level is. Each file
    rotates at 1 MiB with two backups. Calling it again replaces the previous
    files. If the files cannot be opened, warnings and errors still reach
    stderr through the console handlers and this returns ``False``.
    """
    disable_runtime_log()
    formatter = JsonRecordFormatter(include_details=include_details, include_identity=include_identity)
    handlers = []
    try:
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        for name, level_filter in (
            (RUNTIME_ERRORS_LOG, _WarningAndAboveFilter()),
            (RUNTIME_DEBUG_LOG, _BelowWarningFilter()),
        ):
            handler = _RuntimeFileHandler(
                directory / name, maxBytes=MAX_LOG_BYTES, backupCount=LOG_BACKUP_COUNT, encoding="utf-8"
            )
            handler.addFilter(level_filter)
            handler.setFormatter(formatter)
            handlers.append(handler)
    except OSError:
        for handler in handlers:
            handler.close()
        logger.warning("[ADR] Unable to open the runtime log; warnings and errors are printed to stderr only.")
        return False
    for handler in handlers:
        logger.addHandler(handler)
    return True


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
