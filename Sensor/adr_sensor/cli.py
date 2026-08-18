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
import os
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import resource as resource_mod  # Unix-only
except Exception:
    resource_mod = None

from . import __version__
from .observer import AgentObserver


def get_version():
    """Return the version number."""
    return __version__


def main():
    """Main entry point for the ADR Sensor CLI."""
    # ``adr-sensor discover`` runs ADR Discovery (inventory) rather than the
    # observability ingest. It is dispatched before argparse so the two
    # subsystems keep independent option sets.
    if len(sys.argv) > 1 and sys.argv[1] == "discover":
        from .discovery.cli import main as discover_main

        return discover_main(sys.argv[2:])

    parser = argparse.ArgumentParser(
        description="ADR Sensor - Security observability for AI coding agents",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  adr-sensor                              Ingest from all sources
  adr-sensor --source claude              Ingest Claude Code logs only
  adr-sensor --source cursor              Ingest Cursor IDE logs only
  adr-sensor --source claude_desktop      Ingest Claude Desktop agent-mode logs only (macOS/Windows)
  adr-sensor --source opencode            Ingest opencode logs only
  adr-sensor --save-sessions              Save individual session files
  adr-sensor --output-format jsonl        Export as JSONL
  adr-sensor --all-history                Include all logs (not just last 2 weeks)
  adr-sensor discover                     Inventory AI tools on this endpoint
  adr-sensor discover --dry-run --explain Show what would be collected, write nothing
        """,
    )
    parser.add_argument("--version", action="version", version=get_version(), help="Show version and exit")
    parser.add_argument(
        "--resource",
        action="store_true",
        help="Capture process resource usage and append to resource.log (Unix only)",
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
    parser.add_argument("--limit", type=int, default=2, help="Number of entries to display")
    parser.add_argument("--no-save", action="store_true", help="Do not save to file")
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

    args = parser.parse_args()

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

    try:
        # Determine max_age_days
        max_age_days = None
        if args.all_history:
            max_age_days = 10000

        observer = AgentObserver(output_dir=args.output_dir, max_age_days=max_age_days)

        # Ingest logs
        entries, system_config_data = observer.ingest_all(args.source)

        # Apply incremental filtering
        if args.save_sessions and entries:
            print("\nSession-based incremental mode: Checking existing session files...")
            original_count = len(entries)
            entries = observer.filter_entries_by_existing_files(entries, args.output_dir)
            filtered_count = len(entries)
            print(f"  -> Filtered {original_count - filtered_count} existing sessions, processing {filtered_count} new")

        # Display summary
        observer.display_summary(entries, system_config_data)

        # Save
        if entries or system_config_data:
            if not args.no_save:
                if args.save_sessions:
                    if entries:
                        saved_files = observer.save_sessions_to_individual_files(entries, output_dir=args.output_dir)
                        print(
                            f"\nSession files saved to: {saved_files[0].parent if saved_files else 'No files saved'}"
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

        print("\nADR Sensor complete!\n")

    except BaseException:
        success = False
        raise

    finally:
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

                with open(log_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(record, separators=(",", ":"), ensure_ascii=False) + "\n")
            except Exception:
                pass


if __name__ == "__main__":
    main()
