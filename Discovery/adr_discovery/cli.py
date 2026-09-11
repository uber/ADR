"""Argument parsing and exit codes. Nothing else.

Everything this file knows how to do is delegated; keeping it thin is what
lets `discover()` be called from a test, a fixture harness or another
program without going through a command line.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import platform
import socket
import sys
import unicodedata
from datetime import datetime, timezone

from .catalog.load import CatalogError
from .catalog.load import loads as load_catalog
from .coverage.ledger import Ledger
from .judge import Policy
from .pipeline import discover
from .redact import rules as redact
from .reporter import diff, from_dict, stats, to_json
from .reporter.delta import DifferentEndpoints
from .world.budget import Budget
from .world.gate import Gate
from .world.platform import for_host

EXIT_OK, EXIT_ERROR, EXIT_PARTIAL = 0, 1, 2
MAX_JSON_INPUT = 16 * 1024 * 1024


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="adr-discovery", description="Inventory the AI tools on this endpoint.")
    p.add_argument("--root", default="/", help="scan a fixture tree instead of the live machine")
    p.add_argument("--json", action="store_true", help="print the whole snapshot as JSON")
    p.add_argument("--dry-run", action="store_true", help="scan and print, write nothing")
    p.add_argument("--explain", action="store_true", help="print exactly what would leave the machine")
    p.add_argument("--output-dir", default="./output", help="where the snapshot lands")
    p.add_argument("--policy", help="tenant policy JSON: approved, forbidden, tenant_domains")
    p.add_argument("--telemetry", help="JSON mapping catalog id to last-used timestamp")
    p.add_argument("--diff", metavar="SNAPSHOT",
                   help="compare this scan against a previous snapshot and print the delta")
    p.add_argument("--allow-cross-endpoint", action="store_true",
                   help="permit a diff between two different hosts")
    p.add_argument("--max-entries", type=int, default=200_000, help="shared sweep ceiling")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.explain:
        print("adr-discovery would collect:")
        for line in redact.explain():
            print(f"  - {line}")
        print()
        if args.dry_run and not args.json:
            return EXIT_OK

    here = os.path.dirname(os.path.abspath(__file__))
    try:
        with open(os.path.join(here, "catalog", "catalog.json"), encoding="utf-8") as fh:
            catalog = load_catalog(fh.read())
    except (OSError, CatalogError) as exc:
        print(f"catalog unusable: {exc}", file=sys.stderr)
        return EXIT_ERROR

    policy = Policy()
    if args.policy:
        try:
            policy = Policy.from_dict(_load_json_mapping(args.policy, "policy"))
        except (OSError, ValueError, TypeError) as exc:
            print(f"cannot read policy: {_terminal(exc)}", file=sys.stderr)
            return EXIT_ERROR

    telemetry = None
    if args.telemetry:
        try:
            telemetry = _telemetry(_load_json_mapping(args.telemetry, "telemetry"))
        except (OSError, ValueError, TypeError) as exc:
            print(f"cannot read telemetry: {_terminal(exc)}", file=sys.stderr)
            return EXIT_ERROR

    gate = Gate(
        root=args.root,
        ledger=Ledger(),
        budget=Budget(max_entries=args.max_entries),
        providers=for_host() if args.root == "/" else None,
        env=dict(os.environ),
    )

    snapshot = discover(
        gate, catalog, policy, telemetry,
        hostname=socket.gethostname(),
        username=getpass.getuser(),
        platform_name=platform.system().lower(),
        timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )

    if args.json:
        print(to_json(snapshot))
    else:
        _summary(snapshot)

    if args.diff:
        try:
            previous = from_dict(_load_json_mapping(args.diff, "snapshot"))
        except (OSError, ValueError, KeyError, TypeError) as exc:
            print(f"cannot read {_terminal(args.diff)}: {_terminal(exc)}", file=sys.stderr)
            return EXIT_ERROR
        try:
            _delta(diff(previous, snapshot, args.allow_cross_endpoint))
        except DifferentEndpoints as exc:
            print(f"\n{exc}", file=sys.stderr)
            return EXIT_ERROR

    if not args.dry_run:
        filename = f"snapshot-{snapshot.timestamp.replace(':', '')}.json"
        try:
            target = _write_private(args.output_dir, filename, to_json(snapshot))
        except OSError as exc:
            print(f"cannot write snapshot: {_terminal(exc)}", file=sys.stderr)
            return EXIT_ERROR
        print(f"\nwrote {_terminal(target)}", file=sys.stderr)

    # A scan that could not see everything says so in its exit code, because
    # a partial inventory must never be indistinguishable from a clean one.
    return EXIT_OK if snapshot.coverage.is_complete else EXIT_PARTIAL


def _delta(delta) -> None:
    print(f"\ndelta vs the previous snapshot of {_terminal(delta.endpoint)}")
    if delta.is_empty:
        print("  no change")
        return
    for change in delta.changes:
        detail = f"  ({_terminal(change.detail)})" if change.detail else ""
        print(f"  {_terminal(change.kind):<16} {_terminal(change.name)}{detail}")
    for note in delta.coverage_delta:
        print(f"  coverage         {_terminal(note)}")


def _summary(snapshot) -> None:
    counts = stats(snapshot)
    print(f"{_terminal(snapshot.hostname)} · {_terminal(snapshot.platform)} · "
          f"catalog {_terminal(snapshot.catalog_version)}")
    print(f"  assets {counts['asset_count']} · findings {counts['finding_count']} · "
          f"review queue {counts['review_queue_count']} · coverage gaps {counts['coverage_gaps']}")
    for asset in snapshot.assets:
        version = f" {_terminal(asset.version)}" if asset.version else ""
        print(f"    {asset.kind.value:<14} {_terminal(asset.name)}{version}  [{asset.liveness.value}, "
              f"{asset.confidence.label} confidence]")
    for finding in snapshot.findings:
        print(f"  ! {_terminal(finding.severity):<7} {_terminal(finding.rule)}: "
              f"{_terminal(finding.summary)}")
    cov = snapshot.coverage
    if not cov.is_complete:
        print(f"  coverage: {len(cov.denied)} denied · {len(cov.unavailable)} unavailable · "
              f"{len(cov.boundaries_hit)} boundaries · {len(cov.truncated)} truncated")


def _load_json_mapping(path: str, label: str) -> dict:
    """Load one bounded JSON object; optional CLI inputs are untrusted too."""
    with open(path, "rb") as fh:
        raw = fh.read(MAX_JSON_INPUT + 1)
    if len(raw) > MAX_JSON_INPUT:
        raise ValueError(f"{label} exceeds {MAX_JSON_INPUT} bytes")
    try:
        document = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"{label} is not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise ValueError(f"{label} root must be an object")
    return document


def _telemetry(document: dict) -> dict[str, str]:
    if not all(isinstance(key, str) and isinstance(value, str) for key, value in document.items()):
        raise ValueError("telemetry must map strings to strings")
    return document


def _write_private(output_dir: str, filename: str, text: str) -> str:
    """Create a new private snapshot without following a target symlink."""
    if os.path.basename(filename) != filename:
        raise OSError("snapshot filename must not contain a directory")
    os.makedirs(output_dir, mode=0o700, exist_ok=True)
    absolute = os.path.abspath(output_dir)
    if os.path.islink(absolute):
        raise OSError("output directory must not be a symlink")

    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory_fd = os.open(absolute, directory_flags)
    try:
        before = os.fstat(directory_fd)
        current = os.stat(absolute, follow_symlinks=False)
        if (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino):
            raise OSError("output directory changed during validation")

        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        if os.open in os.supports_dir_fd:
            fd = os.open(filename, flags, 0o600, dir_fd=directory_fd)
        else:  # Windows has no dir_fd variant; O_EXCL still prevents clobbering.
            fd = os.open(os.path.join(absolute, filename), flags, 0o600)
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fd = -1
                fh.write(text)
        finally:
            if fd >= 0:
                os.close(fd)
    finally:
        os.close(directory_fd)
    return os.path.join(output_dir, filename)


def _terminal(value: object) -> str:
    """Render untrusted text without terminal control or bidi characters."""
    out = []
    for char in str(value):
        if unicodedata.category(char).startswith("C"):
            code = ord(char)
            out.append(f"\\x{code:02x}" if code <= 0xFF else f"\\u{code:04x}")
        else:
            out.append(char)
    return "".join(out)


if __name__ == "__main__":
    raise SystemExit(main())
