"""``adr-e2e`` - the harness from a terminal.

    python3 -m tests.cli check                     # static checks, no VM
    python3 -m tests.cli run --os linux --out DIR  # restore, install, scan, score
    python3 -m tests.cli score DIR                 # re-score a recorded run
    python3 -m tests.cli report DIR                # scorecard from score.json

``score`` and ``report`` never touch a VM, which is the property that matters
day to day: a scoring change is replayed over every recorded run in
milliseconds, and somebody debugging a false positive needs nothing but the run
directory.
"""

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional

from . import manifest as manifest_module
from . import manifest_check
from .report import html as report_html
from .scoring import score_run

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="adr-e2e", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="static manifest checks - no VM, per-commit safe")
    check.add_argument("--catalog", help="path to the collector's catalog.json, to check coverage")

    run = sub.add_parser("run", help="restore a guest, install, scan and score")
    run.add_argument("--os", dest="platform", required=True, choices=("mac", "linux", "win"))
    run.add_argument("--out", required=True, help="run directory to write")
    run.add_argument("--driver", default="dry", choices=("dry", "lima", "tart"))
    run.add_argument("--image", default="", help="backing image or golden VM name")
    run.add_argument("--collector", default="", help="version of the collector under test")
    run.add_argument("--ssh-port", type=int, default=2222)
    run.add_argument("--user", default="tester")
    run.add_argument("--identity", default=None, help="ssh key for the guest")
    run.add_argument("--home", default="")

    score = sub.add_parser("score", help="score a run directory")
    score.add_argument("run_dir")
    score.add_argument("--previous", help="score.json of the last accepted run, for the gate")
    score.add_argument("--report", action="store_true", help="also write report.html")

    report = sub.add_parser("report", help="render report.html from an existing score.json")
    report.add_argument("run_dir")

    args = parser.parse_args(argv)
    return {"check": _check, "run": _run, "score": _score, "report": _report}[args.command](args)


# -- commands ----------------------------------------------------------


def _check(args: Any) -> int:
    """The static checks, which are also a module of their own.

    CI runs them directly as ``python3 -m tests.manifest_check`` and does not
    need the rest of this file, so the checks live there and this delegates.
    Two copies of the same rules would eventually disagree, and the copy CI
    runs is the one that matters.
    """
    return manifest_check.main(["--catalog", args.catalog] if args.catalog else [])


def _run(args: Any) -> int:
    from .install import Context, Runner
    from .install.runner import write_actual

    manifest = manifest_module.load()
    driver = _driver(args)
    home = args.home or _default_home(args.platform, args.user)

    os.makedirs(args.out, exist_ok=True)
    print("restore  %s" % args.driver)
    driver.restore()

    print("baseline scan")
    before = _scan(driver, os.path.join(args.out, "before.json"))

    context = Context(driver, manifest, args.platform, home)
    _write_json(os.path.join(args.out, "canaries.json"), context.canaries)

    print("install  %d applicable entries" % len(manifest.for_platform(args.platform)))
    actual = Runner(context).run()
    actual["collector"] = args.collector
    actual["run_id"] = os.path.basename(os.path.normpath(args.out))
    write_actual(actual, args.out)
    print("         %d installed, %d unavailable, %d failed, %d unimplemented"
          % (actual["installed"], actual["unavailable"], actual["failed"], actual["unimplemented"]))

    print("scan")
    _scan(driver, os.path.join(args.out, "after.json"))
    del before

    return _score(argparse.Namespace(run_dir=args.out, previous=None, report=True))


def _score(args: Any) -> int:
    manifest = manifest_module.load()
    previous = None
    if getattr(args, "previous", None):
        with open(args.previous, encoding="utf-8") as handle:
            previous = json.load(handle)
    result = score_run(args.run_dir, manifest, previous=previous)
    _write_json(os.path.join(args.run_dir, "score.json"), result)

    totals = result["totals"]
    print("score    tp=%d fp=%d fn=%d dup=%d recall=%s precision=%s"
          % (totals["tp"], totals["fp"], totals["fn"], totals["dup"],
             totals["recall"], totals["precision"]))
    print("canaries %d planted, %d leaked" % (result["canaries"]["planted"],
                                              result["canaries"]["leaked"]))
    if getattr(args, "report", False):
        print("report   %s" % report_html.write(result, args.run_dir))
    if result["gate"]["passed"]:
        print("gate     passed")
        return 0
    print("gate     FAILED: %s" % ", ".join(result["gate"]["reasons"]), file=sys.stderr)
    return 2


def _report(args: Any) -> int:
    with open(os.path.join(args.run_dir, "score.json"), encoding="utf-8") as handle:
        result = json.load(handle)
    print(report_html.write(result, args.run_dir))
    return 0


# -- plumbing ----------------------------------------------------------


def _driver(args: Any) -> Any:
    if args.driver == "dry":
        from .provision import DryRunDriver
        return DryRunDriver(args.platform, args.home or _default_home(args.platform, args.user))
    if args.driver == "lima":
        from .provision.lima import LimaDriver
        return LimaDriver(instance=args.image or "adr-disco-linux")
    from .provision.tart import TartDriver
    return TartDriver(golden=args.image, user=args.user, identity=args.identity)


def _scan(driver: Any, destination: str) -> Dict[str, Any]:
    """Run the collector in the guest and bring its snapshot back.

    The collector under test is whatever the guest has been given - built
    locally and pushed in by whoever provisioned the image, never installed from
    a registry, because a run that fetched a published artifact would be testing
    a release rather than the change in front of it.
    """
    result = driver.run(["adr-discovery", "--json"], timeout=900)
    if result.ok and result.text():
        payload = json.loads(result.text())
    else:
        # A guest that cannot scan is a failed run, not an empty inventory: a
        # host that reported nothing and a host that never reported are
        # different facts, and conflating them would score every entry a miss.
        payload = {"hostname": "", "assets": [], "errors": [
            {"probe": "harness", "path": "", "message": "scan failed: %s" % result.stderr[:200]}],
            "stats": {"asset_count": 0, "error_count": 1}}
    _write_json(destination, payload)
    return payload


def _default_home(platform: str, user: str) -> str:
    return {"mac": "/Users/%s", "win": "C:/Users/%s"}.get(platform, "/home/%s") % user


def _write_json(path: str, payload: Any) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


if __name__ == "__main__":
    raise SystemExit(main())
