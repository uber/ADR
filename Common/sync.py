"""Copy shared source from Common/ into each package that ships it.

The packages are installed independently (the Sensor is published to PyPI
and supports Python 3.9; Discovery requires 3.11), so neither can depend on
a shared distribution. Each carries a checked-in, generated copy instead.

    python Common/sync.py           # rewrite the copies
    python Common/sync.py --check   # exit 1 and show a diff if a copy drifted
"""

from __future__ import annotations

import argparse
import difflib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

#: shared source -> generated copies, all relative to the repository root
COPIES = {
    "Common/adr_common/host_identity.py": (
        "Sensor/adr_sensor/host_identity.py",
        "Discovery/adr_discovery/world/host_identity.py",
    ),
}


def generated(source: str) -> str:
    header = f"# Generated from {source} by Common/sync.py. Do not edit.\n"
    return header + (ROOT / source).read_text(encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="report drift instead of rewriting")
    args = parser.parse_args(argv)

    drifted = 0
    for source, targets in COPIES.items():
        want = generated(source)
        for target in targets:
            path = ROOT / target
            have = path.read_text(encoding="utf-8") if path.exists() else ""
            if have == want:
                continue
            if args.check:
                drifted += 1
                sys.stdout.writelines(difflib.unified_diff(
                    have.splitlines(keepends=True), want.splitlines(keepends=True),
                    fromfile=target, tofile=f"{target} (from {source})",
                ))
            else:
                path.write_text(want, encoding="utf-8")
                print(f"wrote {target}")
    if drifted:
        print(f"{drifted} generated file(s) out of date; run: python Common/sync.py", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
