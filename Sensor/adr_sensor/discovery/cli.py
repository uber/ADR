"""``adr-sensor discover`` - run Plane A against this machine.

``--dry-run --explain`` prints exactly what would leave the endpoint, per probe
and per field, so an employee can audit the collector before it reports.
"""

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from .catalog import Catalog
from .probes import ALL_PROBES
from .probes.openworld import PROVIDER_HOSTS, WEIGHTS
from .redact import DENY_PATH_PARTS, VALUE_BEARING_FLAGS
from .runner import discover, live_env


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="adr-sensor discover",
        description="Inventory the AI tools and agents present on this endpoint.")
    parser.add_argument("--output-dir", type=Path, default=None,
                        help="Directory to write the snapshot to (default: ./output)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Scan and print, but write nothing")
    parser.add_argument("--explain", action="store_true",
                        help="Print exactly what is collected and what is redacted, then continue")
    parser.add_argument("--json", action="store_true", help="Print the whole snapshot as JSON")
    args = parser.parse_args(argv)

    if args.explain:
        _explain()

    snapshot = discover(live_env())

    if args.json:
        print(snapshot.to_json())
    else:
        _summarize(snapshot)

    if not args.dry_run:
        target = args.output_dir or Path("output")
        target.mkdir(parents=True, exist_ok=True)
        path = target / ("discovery_%s.json" % snapshot.timestamp.replace(":", "").replace("-", ""))
        path.write_text(snapshot.to_json())
        print("\nWrote %s" % path)
    return 0


def _explain() -> None:
    catalog = Catalog.load()
    print("=" * 78)
    print("What this scan collects, and what it never does")
    print("=" * 78)
    print("\nProbes that will run:")
    for probe_class in ALL_PROBES:
        probe = probe_class(catalog)
        print("  %-12s %s" % (probe.name, (probe_class.__doc__ or "").strip().splitlines()[0]))
    print("\nCatalog version: %s (%d entries)" % (catalog.version, len(catalog.entries)))
    print("\nNever collected:")
    print("  - file contents, beyond allowlisted config keys")
    print("  - environment variable values (names only)")
    print("  - URL query strings, fragments and userinfo")
    print("  - values of these flags: %s" % ", ".join(sorted(VALUE_BEARING_FLAGS)))
    print("  - anything under: %s" % ", ".join(DENY_PATH_PARTS))
    print("\nOpen-world signals and weights:")
    for name, weight in sorted(WEIGHTS.items(), key=lambda item: -item[1]):
        print("  %-22s %.2f" % (name, weight))
    print("  provider hosts matched exactly: %s" % ", ".join(PROVIDER_HOSTS[:4]) + ", ...")
    print()


def _summarize(snapshot) -> None:
    print("\nADR Discovery - %s (%s)" % (snapshot.hostname, snapshot.platform))
    print("=" * 78)
    by_kind = {}
    for asset in snapshot.assets:
        by_kind.setdefault(asset.kind, []).append(asset)
    for kind in sorted(by_kind):
        print("\n%s (%d)" % (kind, len(by_kind[kind])))
        for asset in by_kind[kind]:
            factors = ",".join(asset.risk.get("factors", []))
            print("  %-28s %-10s %-12s %s%s" % (
                asset.name[:28], asset.version or "-", asset.confidence_band,
                asset.liveness, (" [%s]" % factors) if factors else ""))
    if snapshot.findings:
        print("\nFindings (%d)" % len(snapshot.findings))
        for finding in snapshot.findings:
            print("  %-24s %-8s %s" % (finding["finding"], finding["severity"], finding["name"]))
    if snapshot.review_queue:
        print("\nReview queue (%d) - probable AI, unclassified" % len(snapshot.review_queue))
        for item in snapshot.review_queue:
            print("  %-32s %.2f  %s" % (item["name"][:32], item["score"], ",".join(item["signals"])))
    print("\n%d assets, %d errors, %.0f ms"
          % (snapshot.stats["asset_count"], snapshot.stats["error_count"], snapshot.stats["wall_ms"]))


if __name__ == "__main__":
    sys.exit(main())
