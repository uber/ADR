"""Bounded, content-free operational records, separate from captured sessions."""

import json
import logging
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Dict, Iterable, Optional

from . import __version__
from .parsers.base_parser import BaseParser

DIAGNOSTIC_SOURCES = frozenset(
    {"sensor", "claude", "claude_desktop", "cursor", "cline", "codex", "copilot", "dsh", "gemini", "opencode", "warp"}
)
DIAGNOSTIC_STAGES = frozenset({"parse", "save", "save_session", "export", "startup"})
OPERATIONAL_REASONS = frozenset(
    {"parser_error", "write_error", "export_error", "startup_error", "checkpoint_read_error", "checkpoint_write_error"}
)
COUNT_FIELDS = frozenset({"events_returned", "events_emitted", "events_filtered", "attempted", "succeeded", "failed"})
MAX_LOG_BYTES = 1024 * 1024
LOG_BACKUP_COUNT = 2
MAX_COUNT = 2**63 - 1


def _counts(values: Dict[str, int], allowed: Iterable[str]) -> Dict[str, int]:
    """Accept only fixed keys and bounded integers, never caller-provided text."""
    allowed = frozenset(allowed)
    if not isinstance(values, dict):
        return {}
    return {
        key: min(value, MAX_COUNT)
        for key, value in values.items()
        if key in allowed and isinstance(value, int) and not isinstance(value, bool) and value >= 0
    }


def health_record(
    source: str,
    stage: str,
    *,
    counts: Optional[Dict[str, int]] = None,
    reasons: Optional[Dict[str, int]] = None,
) -> dict:
    """Summarize observed issues without claiming that every issue is schema drift."""
    safe_counts = _counts(counts or {}, COUNT_FIELDS)
    safe_reasons = _counts(reasons or {}, BaseParser.DIAGNOSTIC_CODES | OPERATIONAL_REASONS)
    issues = sum(count for reason, count in safe_reasons.items() if reason not in BaseParser.EXPECTED_DIAGNOSTIC_CODES)
    emitted = safe_counts.get("events_emitted", safe_counts.get("succeeded", 0))
    if issues:
        status = "partial" if emitted else "failed"
    elif safe_reasons.get("input_missing") and not emitted:
        status = "no_input"
    elif not emitted and stage == "parse":
        status = "empty"
    else:
        status = "ok"
    return {
        "schema_version": 1,
        "event": "adr.sensor.health",
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "sensor_version": __version__,
        "source": source if isinstance(source, str) and source in DIAGNOSTIC_SOURCES else "sensor",
        "stage": stage if isinstance(stage, str) and stage in DIAGNOSTIC_STAGES else "startup",
        "status": status,
        "suspected_schema_drift": any(
            count and reason in {"unsupported_schema", "unsupported_record_type", "unsupported_content_block"}
            for reason, count in safe_reasons.items()
        ),
        "counts": safe_counts,
        "reasons": safe_reasons,
    }


def sanitize_health_record(record: dict) -> dict:
    """Revalidate the fixed schema at each serialization boundary."""
    safe = health_record(
        record.get("source"), record.get("stage"), counts=record.get("counts"), reasons=record.get("reasons")
    )
    try:
        timestamp = datetime.fromisoformat(record.get("timestamp", ""))
        if timestamp.tzinfo is not None:
            safe["timestamp"] = timestamp.astimezone(timezone.utc).isoformat(timespec="milliseconds")
    except (TypeError, ValueError):
        pass
    return safe


def write_health_records(output_dir: Path, records: Iterable[dict]) -> bool:
    """Append rotating JSONL diagnostics; logging failures never erase capture."""
    handlers = []
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        for name in ("diagnostics.jsonl", "error.log"):
            handler = RotatingFileHandler(
                output_dir / name, maxBytes=MAX_LOG_BYTES, backupCount=LOG_BACKUP_COUNT, encoding="utf-8", delay=True
            )
            handler.setFormatter(logging.Formatter("%(message)s"))

            # Handler.emit normally suppresses write failures. Surface them to
            # the single bounded fallback below instead of logging record data.
            def handle_error(record):
                raise OSError("diagnostic write failed")

            handler.handleError = handle_error
            handlers.append(handler)
        for record in records:
            record = sanitize_health_record(record)
            message = json.dumps(record, ensure_ascii=True, separators=(",", ":"))
            item = logging.LogRecord("adr_sensor.health", logging.INFO, "", 0, message, (), None)
            handlers[0].handle(item)
            if record["status"] in {"partial", "failed"}:
                handlers[1].handle(item)
        return True
    except Exception:
        print("[ADR] Unable to write sensor diagnostics; captured session data is unaffected.", file=sys.stderr)
        return False
    finally:
        for handler in handlers:
            try:
                handler.close()
            except Exception:
                pass
