"""Argument parsing and exit codes. Nothing else.

Everything this file knows how to do is delegated; keeping it thin is what
lets `discover()` be called from a test, a fixture harness or another
program without going through a command line.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
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
from .world import host_identity
from .world.budget import Budget
from .world.gate import Gate
from .world.platform import for_host
from .world.private_output import write_private
from .world.store import ArchiveStore

EXIT_OK, EXIT_ERROR, EXIT_PARTIAL = 0, 1, 2
MAX_JSON_INPUT = 16 * 1024 * 1024
ARCHIVE_DEFAULT = "<output-dir>/skill-archives"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="adr-discovery", description="Inventory the AI tools on this endpoint.")
    p.add_argument("--root", default="/", help="scan a fixture tree instead of the live machine")
    p.add_argument("--json", action="store_true", help="print the whole snapshot as JSON")
    p.add_argument("--dry-run", action="store_true", help="scan and print, write nothing")
    p.add_argument("--explain", action="store_true", help="print exactly what would leave the machine")
    p.add_argument("--output-dir", default="./output", help="where the snapshot lands")
    p.add_argument("--policy", help="tenant policy JSON: approved, forbidden, tenant_domains, approved_indicators, forbidden_indicators")
    p.add_argument("--telemetry", help="JSON mapping catalog id to last-used timestamp")
    p.add_argument("--diff", metavar="SNAPSHOT",
                   help="compare this scan against a previous snapshot and print the delta")
    p.add_argument("--allow-cross-endpoint", action="store_true",
                   help="permit a diff between two different hosts")
    p.add_argument("--resolve", action="store_true",
                   help="look up model-provider hostnames to match connections by address "
                        "(sends DNS queries; off by default)")
    p.add_argument("--archive-skills", nargs="?", const=ARCHIVE_DEFAULT, metavar="DIR",
                   help="also keep a zip of every skill, named by its folder hash, plus index.jsonl "
                        "(local only, owner-only; default <output-dir>/skill-archives)")
    p.add_argument("--max-entries", type=int, default=200_000, help="shared sweep ceiling")
    p.add_argument("--max-children", type=int, default=5_000,
                   help="largest directory whose subdirectories are still walked")
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
        budget=Budget(max_entries=args.max_entries, max_children=args.max_children),
        providers=for_host() if args.root == "/" else None,
        env=dict(os.environ),
        resolve_names=args.resolve,
    )

    archive_to = None
    if args.archive_skills and not args.dry_run:  # --dry-run writes nothing
        directory = args.archive_skills
        if directory == ARCHIVE_DEFAULT:
            directory = os.path.join(args.output_dir, "skill-archives")
        archive_to = ArchiveStore(directory)

    snapshot = discover(
        gate, catalog, policy, telemetry,
        # From the operating system, not USER/LOGNAME, and the same value
        # the Sensor reports for this host (Common/adr_common).
        hostname=host_identity.hostname(),
        username=host_identity.username(),
        platform_name=platform.system().lower(),
        timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        archive_to=archive_to,
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
    try:
        return write_private(output_dir, filename, text)
    except ValueError as exc:
        raise OSError(str(exc)) from exc


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
