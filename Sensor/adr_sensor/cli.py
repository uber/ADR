#!/usr/bin/env python3
"""
ADR Sensor CLI - Command-line interface for the ADR Sensor.

Usage:
    adr-sensor                    # Ingest from all sources
    adr-sensor --source claude    # Ingest from Claude Code only
    adr-sensor --save-sessions    # Save individual session files
    adr-sensor --output-format jsonl --output-dir ./my-output
"""

import argparse
import json
import logging
import os
import platform
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import resource as resource_mod  # Unix-only
except Exception:
    resource_mod = None

from . import __version__
from .diagnostics import health_record, write_health_records
from .exporters import OpenTelemetryConfigError, load_opentelemetry_config
from .exporters.delivery_checkpoint import DeliveryCheckpoint, DeliveryCheckpointError
from .exporters.opentelemetry import OpenTelemetryExportError, OpenTelemetryLogExporter
from .observer import AgentObserver
from .sensor_log import append_rotating_line, disable_runtime_log, enable_runtime_log, set_console_level

logger = logging.getLogger(__name__)


def get_version():
    """Return the version number."""
    return __version__


def _non_negative_int(value: str) -> int:
    """Parse a non-negative integer for bounded display options."""
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be zero or greater")
    return parsed


def main():
    """Main entry point for the ADR Sensor CLI."""
    parser = argparse.ArgumentParser(
        description="ADR Sensor - Security observability for AI coding agents",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  adr-sensor                              Ingest from all sources
  adr-sensor --source claude              Ingest Claude Code logs only
  adr-sensor --source cursor              Ingest Cursor IDE logs only
  adr-sensor --source claude_desktop      Ingest Claude Desktop agent-mode logs only (macOS/Windows)
  adr-sensor --source copilot             Ingest GitHub Copilot CLI logs only
  adr-sensor --source dsh                 Ingest DeepSeek Harness logs only
  adr-sensor --source opencode            Ingest opencode logs only
  adr-sensor --source gemini              Ingest Gemini CLI chat sessions
  adr-sensor --save-sessions              Save individual session files
  adr-sensor --output-format jsonl        Export as JSONL
  adr-sensor --otel-config ./otel.json    Export logs to an OTLP/HTTP endpoint
  adr-sensor --all-history                Include all logs (not just last 2 weeks)
        """,
    )
    parser.add_argument("--version", action="version", version=get_version(), help="Show version and exit")
    parser.add_argument(
        "--resource",
        action="store_true",
        help="Capture process resource usage and append to resource.log, rotated at 1 MiB (Unix only)",
    )
    parser.add_argument(
        "--source",
        choices=["all", *(source for source, _ in AgentObserver.SOURCES)],
        default="all",
        help="Source to ingest logs from (default: all)",
    )
    parser.add_argument(
        "--output-format",
        choices=["json", "jsonl"],
        default="json",
        help="Output format for saved files (default: json)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Directory to save output files (default: ./output)",
    )
    parser.add_argument("--limit", type=_non_negative_int, default=2, help="Number of entries to display")
    parser.add_argument(
        "--no-save", action="store_true", help="Do not save captured sessions (diagnostics still written)"
    )
    parser.add_argument(
        "--fail-on-error", action="store_true", help="Exit nonzero after partial capture or output failures"
    )
    parser.add_argument(
        "--save-sessions",
        action="store_true",
        help="Save each session to individual files (incremental)",
    )
    parser.add_argument(
        "--all-history",
        action="store_true",
        help="Include all event logs regardless of age (default: last 2 weeks)",
    )
    parser.add_argument(
        "--otel-config",
        type=Path,
        default=None,
        help="JSON configuration for OTLP/HTTP log export (disabled when omitted)",
    )
    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument(
        "--log-level",
        choices=["debug", "info", "warning", "error"],
        default="info",
        help="Minimum level of progress and error messages printed to the console (default: info)",
    )
    verbosity.add_argument(
        "-q", "--quiet", action="store_true", help="Print only warnings and errors (same as --log-level warning)"
    )
    parser.add_argument(
        "--log-file",
        action="store_true",
        help="Also write runtime logs as rotating JSON lines (sensor_runtime_*.jsonl) in the output directory",
    )
    parser.add_argument(
        "--log-file-content-free",
        action="store_true",
        help="Omit messages and tracebacks from --log-file records (no paths or error text)",
    )
    parser.add_argument(
        "--log-identity",
        action="store_true",
        help="Add the local username and hostname to --log-file records",
    )

    args = parser.parse_args()
    for option in ("log_file_content_free", "log_identity"):
        if getattr(args, option) and not args.log_file:
            parser.error(f"--{option.replace('_', '-')} requires --log-file")
    set_console_level("warning" if args.quiet else args.log_level)
    if args.log_file:
        enable_runtime_log(
            args.output_dir or Path.cwd() / "output",
            include_details=not args.log_file_content_free,
            include_identity=args.log_identity,
        )

    otel_config = None
    if args.otel_config is not None:
        try:
            otel_config = load_opentelemetry_config(args.otel_config)
        except OpenTelemetryConfigError as exc:
            parser.error(str(exc))

    host_os = platform.system()
    capture_resource = bool(args.resource and host_os != "Windows" and resource_mod is not None)

    # Prepare resource measurement
    start_time = time.monotonic()
    start_self = start_children = None
    if capture_resource:
        try:
            start_self = resource_mod.getrusage(resource_mod.RUSAGE_SELF)
            start_children = resource_mod.getrusage(resource_mod.RUSAGE_CHILDREN)
        except Exception:
            capture_resource = False

    success = True
    observer = None
    stage = "startup"

    try:
        # Determine max_age_days
        max_age_days = None
        if args.all_history:
            max_age_days = 10000

        observer = AgentObserver(output_dir=args.output_dir, max_age_days=max_age_days)

        # Ingest logs
        stage = "parse"
        entries, system_config_data = observer.ingest_all(args.source)

        # A local file is not an OTLP acknowledgement. Keep remote candidates
        # independent of local incremental filtering, including after a failed run.
        otel_entries = entries
        delivery_checkpoint = None
        if otel_config is not None and args.save_sessions and not args.no_save:
            stage = "export"
            checkpoint_dir = args.output_dir if args.output_dir is not None else observer._get_default_session_dir()
            delivery_checkpoint = DeliveryCheckpoint(checkpoint_dir, otel_config)
            otel_entries = delivery_checkpoint.pending_entries(entries)
            if delivery_checkpoint.load_failed:
                observer.record_failure("export", "checkpoint_read_error")
                logger.warning("OpenTelemetry delivery checkpoint unreadable or invalid; retrying sessions.")

        # Apply incremental filtering
        stage = "save"
        if args.save_sessions and entries:
            logger.info("\nSession-based incremental mode: Checking existing session files...")
            original_count = len(entries)
            entries = observer.filter_entries_by_existing_files(entries, args.output_dir)
            filtered_count = len(entries)
            logger.info(
                "  -> Filtered %d existing sessions, processing %d new",
                original_count - filtered_count,
                filtered_count,
            )

        # Display summary
        observer.display_summary(entries, system_config_data, limit=args.limit)

        # Save
        stage = "save"
        if entries or system_config_data:
            if not args.no_save:
                if args.save_sessions:
                    if entries:
                        saved_files = observer.save_sessions_to_individual_files(entries, output_dir=args.output_dir)
                        logger.info(
                            "\nSession files saved to: %s", saved_files[0].parent if saved_files else "No files saved"
                        )
                else:
                    if args.output_dir is None:
                        project_output_dir = Path.cwd() / "output"
                    else:
                        project_output_dir = args.output_dir

                    project_output_dir.mkdir(parents=True, exist_ok=True)
                    observer.save_to_file(
                        entries, system_config_data, output_format=args.output_format, output_dir=project_output_dir
                    )

        if otel_config is not None:
            # Health records must reach monitoring even when parsing produced
            # no sessions, or all local session snapshots were unchanged.
            stage = "export"
            otel_exporter = OpenTelemetryLogExporter(otel_config, service_version=get_version())
            try:
                exported_count = otel_exporter.export(otel_entries, system_config_data)
                otel_exporter.export_diagnostics(observer.get_diagnostic_records())
            finally:
                otel_exporter.shutdown()
            if delivery_checkpoint is not None:
                delivery_checkpoint.commit()
            logger.info("\nOpenTelemetry session/configuration logs sent: %d", exported_count)

        success = observer.has_errors is not True
        if success:
            logger.info("\nADR Sensor complete!\n")
        else:
            logger.warning("\nADR Sensor completed with errors; see diagnostics.jsonl.\n")
            if args.fail_on_error:
                raise SystemExit(1)

    except OpenTelemetryExportError as exc:
        success = False
        if observer is not None:
            observer.record_failure("export", "export_error")
        logger.error("OpenTelemetry export failed: %s", exc)
        raise SystemExit(1)

    except DeliveryCheckpointError as exc:
        success = False
        if observer is not None:
            observer.record_failure("export", "checkpoint_write_error")
        logger.error("OpenTelemetry checkpoint failed: %s", exc)
        raise SystemExit(1)

    except Exception:
        success = False
        if observer is not None:
            reason = {"parse": "parser_error", "save": "write_error", "export": "export_error"}.get(
                stage, "startup_error"
            )
            observer.record_failure(stage, reason)
        else:
            write_health_records(
                args.output_dir or Path.cwd() / "output",
                [health_record("sensor", "startup", reasons={"startup_error": 1})],
            )
        raise

    except BaseException:
        success = False
        raise

    finally:
        if observer is not None:
            observer.flush_diagnostics()
            if observer.has_errors is True:
                success = False
        if capture_resource:
            try:
                end_time = time.monotonic()
                end_self = resource_mod.getrusage(resource_mod.RUSAGE_SELF)
                end_children = resource_mod.getrusage(resource_mod.RUSAGE_CHILDREN)

                def _delta(attr: str) -> float:
                    return float(getattr(end_self, attr, 0.0) - getattr(start_self, attr, 0.0)) + float(
                        getattr(end_children, attr, 0.0) - getattr(start_children, attr, 0.0)
                    )

                user_cpu = _delta("ru_utime")
                sys_cpu = _delta("ru_stime")

                raw_maxrss = getattr(end_self, "ru_maxrss", 0)
                if host_os == "Darwin":
                    max_rss_bytes = int(raw_maxrss)
                else:
                    max_rss_bytes = int(raw_maxrss) * 1024

                if args.output_dir is not None:
                    out_dir = Path(args.output_dir)
                elif args.save_sessions and observer is not None:
                    out_dir = observer._get_default_session_dir()
                else:
                    out_dir = Path.cwd() / "output"

                out_dir.mkdir(parents=True, exist_ok=True)
                log_path = out_dir / "resource.log"

                record = {
                    "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                    "version": get_version(),
                    "host_os": host_os,
                    "pid": os.getpid(),
                    "source": args.source,
                    "duration_seconds": round(end_time - start_time, 6),
                    "success": bool(success),
                    "metrics": {
                        "cpu_user_seconds": round(user_cpu, 6),
                        "cpu_system_seconds": round(sys_cpu, 6),
                        "max_rss_bytes": int(max_rss_bytes),
                    },
                }

                append_rotating_line(log_path, json.dumps(record, separators=(",", ":"), ensure_ascii=False))
            except Exception:
                pass
        disable_runtime_log()


if __name__ == "__main__":
    main()
