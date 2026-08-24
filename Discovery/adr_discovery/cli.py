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
    p.add_argument("--no-subprocess", action="store_true", help="refuse the behaviour rung")
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
        with open(args.policy, encoding="utf-8") as fh:
            policy = Policy.from_dict(json.load(fh))

    telemetry = None
    if args.telemetry:
        with open(args.telemetry, encoding="utf-8") as fh:
            telemetry = json.load(fh)

    gate = Gate(
        root=args.root,
        ledger=Ledger(),
        budget=Budget(max_entries=args.max_entries),
        providers=for_host() if args.root == "/" else None,
        env=dict(os.environ),
        allow_subprocess=not args.no_subprocess,
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
            with open(args.diff, encoding="utf-8") as fh:
                previous = from_dict(json.load(fh))
        except (OSError, ValueError, KeyError) as exc:
            print(f"cannot read {args.diff}: {exc}", file=sys.stderr)
            return EXIT_ERROR
        try:
            _delta(diff(previous, snapshot, args.allow_cross_endpoint))
        except DifferentEndpoints as exc:
            print(f"\n{exc}", file=sys.stderr)
            return EXIT_ERROR

    if not args.dry_run:
        os.makedirs(args.output_dir, exist_ok=True)
        target = os.path.join(args.output_dir, f"snapshot-{snapshot.timestamp.replace(':', '')}.json")
        with open(target, "w", encoding="utf-8") as fh:
            fh.write(to_json(snapshot))
        print(f"\nwrote {target}", file=sys.stderr)

    # A scan that could not see everything says so in its exit code, because
    # a partial inventory must never be indistinguishable from a clean one.
    return EXIT_OK if snapshot.coverage.is_complete else EXIT_PARTIAL


def _delta(delta) -> None:
    print(f"\ndelta vs the previous snapshot of {delta.endpoint}")
    if delta.is_empty:
        print("  no change")
        return
    for change in delta.changes:
        detail = f"  ({change.detail})" if change.detail else ""
        print(f"  {change.kind:<16} {change.name}{detail}")
    for note in delta.coverage_delta:
        print(f"  coverage         {note}")


def _summary(snapshot) -> None:
    counts = stats(snapshot)
    print(f"{snapshot.hostname} · {snapshot.platform} · catalog {snapshot.catalog_version}")
    print(f"  assets {counts['asset_count']} · findings {counts['finding_count']} · "
          f"review queue {counts['review_queue_count']} · coverage gaps {counts['coverage_gaps']}")
    for asset in snapshot.assets:
        version = f" {asset.version}" if asset.version else ""
        print(f"    {asset.kind.value:<14} {asset.name}{version}  [{asset.liveness.value}, "
              f"{asset.confidence.label} confidence]")
    for finding in snapshot.findings:
        print(f"  ! {finding.severity:<7} {finding.rule}: {finding.summary}")
    cov = snapshot.coverage
    if not cov.is_complete:
        print(f"  coverage: {len(cov.denied)} denied · {len(cov.unavailable)} unavailable · "
              f"{len(cov.boundaries_hit)} boundaries · {len(cov.truncated)} truncated")


if __name__ == "__main__":
    raise SystemExit(main())
