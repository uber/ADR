"""python3 -m tests.cli — the harness from one command.

Subcommands exist along the file boundaries the design is built on: a run can
be synthesized, scored, and reported independently, so a failed run is
re-scored without re-running it and a scoring change is replayed against every
run ever recorded.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Optional, Sequence

from . import manifest as manifest_module
from .install import runner as runner_module
from .provision.driver import DryDriver
from .report import html as report_html
from .scoring import schema, snapshot
from .scoring.score import score as score_run
from .tools import synthesize as synthesize_tool

RECORDED = os.path.join(os.path.dirname(os.path.abspath(__file__)), "recorded")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if not getattr(args, "handler", None):
        parser.print_help()
        return 2
    return args.handler(args)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tests.cli", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command")

    check = sub.add_parser("check", help="static manifest checks; no guest needed")
    check.set_defaults(handler=_check)

    synth = sub.add_parser("synthesize", help="build a run directory without a guest")
    synth.add_argument("directory")
    synth.add_argument("--os", dest="platform", default="linux", choices=manifest_module.PLATFORMS)
    synth.add_argument("--fault", action="append", default=[], choices=synthesize_tool.FAULTS)
    synth.add_argument("--seed", type=int, default=7)
    synth.set_defaults(handler=_synthesize)

    score = sub.add_parser("score", help="score a run directory")
    score.add_argument("directory")
    score.add_argument("--os", dest="platform", default=None)
    score.add_argument("--json", dest="json_out", default=None)
    score.add_argument("--html", dest="html_out", default=None)
    score.add_argument("--baseline", default=None, help="previous accepted score.json")
    score.set_defaults(handler=_score)

    run = sub.add_parser("run", help="restore, install, scan and score")
    run.add_argument("--os", dest="platform", default="linux", choices=manifest_module.PLATFORMS)
    run.add_argument("--dry", action="store_true", help="record commands, touch no guest")
    run.add_argument("--out", default=None)
    run.set_defaults(handler=_run)

    return parser


def _check(args: argparse.Namespace) -> int:
    manifest = manifest_module.load()
    try:
        manifest.validate()
    except manifest_module.ManifestError as broken:
        print(str(broken), file=sys.stderr)
        return 1
    print(f"manifest ok — {len(manifest)} entries, {len(manifest.canary_names())} canaries")
    for platform in manifest_module.PLATFORMS:
        print(f"  {platform:6s} {len(manifest.for_platform(platform))} applicable")
    return 0


def _synthesize(args: argparse.Namespace) -> int:
    plan = synthesize_tool.Plan(platform=args.platform, faults=tuple(args.fault), seed=args.seed)
    written = synthesize_tool.build(args.directory, plan=plan)
    print(f"wrote {len(written)} files to {args.directory}")
    for name in sorted(written):
        print(f"  {name}")
    return 0


def _score(args: argparse.Namespace) -> int:
    run = snapshot.load(args.directory)
    manifest = manifest_module.load()
    result = score_run(run, manifest, platform=args.platform or run.os)

    previous = None
    if args.baseline and os.path.isfile(args.baseline):
        with open(args.baseline, encoding="utf-8") as handle:
            previous = json.load(handle)
    gate = schema.gate(result, previous)

    if args.json_out:
        _write(args.json_out, schema.to_json(result))
    if args.html_out:
        _write(args.html_out, report_html.render(result, gate))

    _print(result, gate)
    return 0 if gate.passed else 1


def _run(args: argparse.Namespace) -> int:
    if not args.dry:
        print("only --dry is implemented: the QEMU and tart drivers are not built yet",
              file=sys.stderr)
        return 2

    manifest = manifest_module.load()
    driver = DryDriver()
    driver.restore()
    actual = runner_module.run(driver, manifest, platform=args.platform,
                               image="dry", collector="dry")
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        runner_module.write(actual, os.path.join(args.out, snapshot.ACTUAL))

    print(f"{args.platform}: {actual['applicable']} applicable, "
          f"{actual['installed']} installed, {actual['unavailable']} unavailable, "
          f"{actual['failed']} failed")
    print(f"{len(driver.commands)} commands recorded; no guest was touched")
    return 0


def _print(result, gate) -> None:
    totals = result.totals
    print(f"{result.os}: tp {totals.tp}  fp {totals.fp}  fn {totals.fn}  dup {totals.dup}")
    print(f"  recall {_ratio(totals.recall)}  precision {_ratio(totals.precision)}")
    print(f"  canaries planted {result.canaries.planted} leaked {result.canaries.leaked}")
    print("  gate: " + ("pass" if gate.passed else "FAIL"))
    for reason in gate.reasons:
        print(f"    - {reason}")


def _ratio(value: Optional[float]) -> str:
    return "—" if value is None else f"{value:.4g}"


def _write(path: str, body: str) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(body if body.endswith("\n") else body + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
