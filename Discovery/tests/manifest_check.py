"""The manifest's static checks, as a command CI can run.

These are properties of the manifest and the catalog rather than of a machine,
so they belong in ordinary per-commit CI beside the fast tests - the expensive
instrument should never be the thing that discovers a typo.

    python3 -m tests.manifest_check [--catalog path/to/catalog.json]

The catalog is an input rather than something this package goes looking for:
the harness treats the collector as a black box and does not read its tree. When
no catalog is given the coverage check is reported as not run, because a check
that did not run is not a check that passed - and the difference matters when
this gates a merge.
"""

import argparse
import json
import sys
from typing import List, Optional

from .manifest import ManifestError, PLATFORMS, load


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="manifest_check", description=__doc__.splitlines()[0])
    parser.add_argument("--catalog", help="the collector's catalog.json, to check coverage against")
    args = parser.parse_args(argv)

    try:
        manifest = load()
    except ManifestError as exc:
        print(exc, file=sys.stderr)
        return 1

    print("manifest: %d entries" % len(manifest))
    for platform in PLATFORMS:
        print("  %-6s %d applicable" % (platform, len(manifest.for_platform(platform))))

    failures: List[str] = []
    failures.extend(manifest.check_ids())
    failures.extend(manifest.check_canaries())

    if args.catalog:
        with open(args.catalog, encoding="utf-8") as handle:
            catalog = json.load(handle)
        ids = [entry["id"] for entry in catalog.get("entries", catalog)]
        missing = manifest.check_catalog_coverage(ids)
        failures.extend(missing)
        print("  catalog: %d entries, %d without a manifest row" % (len(ids), len(missing)))
    else:
        print("  catalog: not checked (pass --catalog path/to/catalog.json)")

    # Reported rather than failed: an unresolved vendor url blocks one entry,
    # and is a gap in the harness rather than a broken manifest.
    pending = manifest.check_sources()
    if pending:
        print("  sources: %d vendor descriptors unresolved" % len(pending))

    for failure in failures:
        print("FAIL %s" % failure, file=sys.stderr)
    print("check: %s" % ("failed" if failures else "passed"))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
