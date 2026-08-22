"""Does the scorer respond to known faults - and only to those faults?

The unit tests check that each piece behaves. This checks the instrument as a
whole, the way you would check any instrument: feed it a known input, then
change one known thing, and see whether the reading moves by the amount it
should.

    python3 -m tests.tools.faultcheck

It builds a defect-free control run, confirms the control scores a clean sheet,
then injects one defect at a time and asserts the predicted signal appears. Both
halves matter equally. A scorer that misses a planted duplicate is broken; so is
one that reports defects nobody planted, because every false alarm it raises
costs somebody the afternoon it takes to prove the collector was fine.

The faults below are the real failure modes, not arbitrary mutations: a missed
declaration site, one tool reported twice, an invention, a lookalike believed, a
wrong version, a wrong scope, a mutable tag read as pinned, a leaked credential,
silence about an unknown tool, and an error nothing explains.
"""

import argparse
import copy
import json
import os
import sys
import tempfile
from typing import Any, Callable, Dict, List, Tuple

from ..manifest import load
from ..scoring import score
from ..scoring.snapshot import Snapshot
from .synthesize import build


def _find(assets: List[Dict[str, Any]], **fields: Any) -> Dict[str, Any]:
    for asset in assets:
        if all(asset.get(key) == value for key, value in fields.items()):
            return asset
    raise KeyError(fields)


# -- the faults --------------------------------------------------------


def _miss_a_declared_server(after, planted):
    """The collector stops reporting a server that is declared on disk."""
    after["assets"].remove(_find(after["assets"], name="adr-probe-jetbrains"))


def _report_one_tool_twice(after, planted):
    """usr-merge: one binary, two spellings, two assets."""
    twin = copy.deepcopy(_find(after["assets"], catalog_id="claude-code"))
    twin["asset_id"] = "duplicate0000001"
    twin["install_path"] = "/bin/claude"
    after["assets"].append(twin)


def _invent_an_asset(after, planted):
    """An asset nothing in the manifest installed."""
    after["assets"].append({"kind": "cli_agent", "name": "ghost", "identity": "ghost",
                            "asset_id": "ghost00000000001", "install_path": "/opt/ghost",
                            "install_method": "unknown", "evidence": [],
                            "risk": {"factors": []}, "network": {}})


def _fall_for_a_lookalike(after, planted, home="/home/tester"):
    """N-07: a script whose path contains "mcp" believed to be an MCP server.

    The path has to be the one the control actually wrote. Hard-coding a Linux
    home made this case fail on macOS and Windows for a reason that had nothing
    to do with the scorer - which is the same mistake, in the instrument, that
    the harness exists to catch in the collector.
    """
    after["assets"].append({"kind": "mcp_server", "name": "mcp-backup.sh", "identity": "mcp:x",
                            "asset_id": "lookalike0000001", "install_method": "unknown",
                            "install_path": "%s/bin/mcp-backup.sh" % home, "evidence": [],
                            "risk": {"factors": []}, "network": {}})


def _report_a_wrong_version(after, planted):
    _find(after["assets"], catalog_id="claude-code")["version"] = "0.0.0-wrong"


def _report_a_wrong_scope(after, planted):
    """Precedence: a managed server reported as if the user controlled it."""
    _find(after["assets"], name="adr-probe-managed")["config_scope"] = "user"


def _call_a_mutable_tag_pinned(after, planted):
    """`docker run mcp/memory:latest` is not pinned; `latest` is mutable."""
    _find(after["assets"], name="memory")["risk"]["pinned"] = True


def _leak_a_credential(after, planted):
    _find(after["assets"], catalog_id="claude-code")["risk"]["args"] = [planted["hook_token"]]


def _go_silent_on_the_unknown_tool(after, planted):
    """The in-house wrapper is neither classified nor queued for review."""
    after["review_queue"] = []


def _trip_over_something(after, planted):
    after["errors"].append({"probe": "app", "path": "/opt/mystery", "message": "denied"})


#: (label, injector, expected signal, predicate over the resulting score).
CASES: List[Tuple[str, Callable, str, Callable]] = [
    ("misses a declared server", _miss_a_declared_server, "fn +1, named M-SITE-08",
     lambda base, r: r["totals"]["fn"] == base["totals"]["fn"] + 1
     and "M-SITE-08" in [row["id"] for row in r["misses"]]),
    ("reports one tool twice", _report_one_tool_twice, "dup on every entry keyed to it",
     lambda base, r: r["totals"]["dup"] > base["totals"]["dup"]
     and "duplicates" in r["gate"]["reasons"]),
    ("invents an asset", _invent_an_asset, "fp +1, unattributed",
     lambda base, r: r["totals"]["fp"] == base["totals"]["fp"] + 1
     and any(row["attributed_to"] is None for row in r["inventions"])),
    ("falls for a lookalike", _fall_for_a_lookalike, "fp +1, blamed on N-07",
     lambda base, r: r["totals"]["fp"] == base["totals"]["fp"] + 1
     and any(row["attributed_to"] == "N-07" for row in r["inventions"])),
    ("reports a wrong version", _report_a_wrong_version, "version accuracy < 1",
     lambda base, r: r["fields"]["version"]["accuracy"] < 1
     and r["fields"]["version"]["wrong"][0]["id"] == "T-CLI-01"),
    ("reports a wrong config scope", _report_a_wrong_scope, "config_scope accuracy < 1",
     lambda base, r: r["fields"]["config_scope"]["accuracy"] < 1),
    ("calls a mutable tag pinned", _call_a_mutable_tag_pinned, "pinned accuracy < 1",
     lambda base, r: r["fields"]["pinned"]["accuracy"] < 1
     and r["fields"]["pinned"]["wrong"][0]["id"] == "M-PIN-06"),
    ("leaks a planted credential", _leak_a_credential, "canary leaked, gate fails",
     lambda base, r: r["canaries"]["leaked"] == 1 and "canary_leaked" in r["gate"]["reasons"]),
    ("goes silent on the unknown tool", _go_silent_on_the_unknown_tool, "review queue fails",
     lambda base, r: not r["review_queue"]["passed"]),
    ("trips over something unexplained", _trip_over_something, "errors.unexplained +1",
     lambda base, r: r["errors"]["unexplained"] == base["errors"]["unexplained"] + 1),
]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--os", dest="platform", default="linux", choices=("mac", "linux", "win"))
    parser.add_argument("--json", action="store_true", help="machine-readable result")
    args = parser.parse_args(argv)

    manifest = load()
    control = build(manifest, args.platform, defects={})
    before, after = control["before"], control["after"]
    actual, planted = control["manifest.actual"], control["canaries"]

    def run(mutated=None, previous=None):
        return score(Snapshot(before), Snapshot(mutated or after), actual, manifest,
                     planted=planted, previous=previous)

    base = run()
    rows = []

    # The control has to be clean, or nothing below means anything: a scorer
    # that already reports two misses cannot demonstrate that it found a third.
    control_clean = (base["totals"]["fn"] == 0 and base["totals"]["fp"] == 0
                     and base["totals"]["dup"] == 0 and base["gate"]["passed"])

    home = actual["home"]
    for label, inject, expectation, predicate in CASES:
        mutated = copy.deepcopy(after)
        if inject is _fall_for_a_lookalike:
            inject(mutated, planted, home)
        else:
            inject(mutated, planted)
        result = run(mutated)
        moved = sorted(key for key in ("tp", "fp", "fn", "dup")
                       if result["totals"][key] != base["totals"][key])
        rows.append({"fault": label, "expected": expectation,
                     "detected": bool(predicate(base, result)),
                     "gate": "pass" if result["gate"]["passed"] else "fail",
                     "totals_moved": moved})

    # A regression the gate can only see with history: recall is compared
    # against the last accepted run rather than an absolute threshold, because a
    # real endpoint is not perfectly reproducible.
    mutated = copy.deepcopy(after)
    _miss_a_declared_server(mutated, planted)
    with_history = run(mutated, previous=base)
    rows.append({"fault": "recall below the last accepted run", "expected": "gate fails",
                 "detected": "recall_regressed" in with_history["gate"]["reasons"],
                 "gate": "fail" if not with_history["gate"]["passed"] else "pass",
                 "totals_moved": ["fn", "tp"]})

    passed = control_clean and all(row["detected"] for row in rows)
    if args.json:
        print(json.dumps({"control_clean": control_clean, "control": base["totals"],
                          "cases": rows, "passed": passed}, indent=2))
    else:
        _print(base, control_clean, rows, passed)
    return 0 if passed else 1


def _print(base, control_clean, rows, passed) -> None:
    totals = base["totals"]
    print("control, no fault injected:  tp=%d fp=%d fn=%d dup=%d  recall=%s precision=%s  gate=%s"
          % (totals["tp"], totals["fp"], totals["fn"], totals["dup"], totals["recall"],
             totals["precision"], "passed" if base["gate"]["passed"] else "FAILED"))
    print("control is clean:            %s\n" % ("yes" if control_clean else "NO - stop here"))
    print("%-36s %-32s %-9s %-6s %s" % ("injected fault", "expected signal", "detected",
                                        "gate", "totals that moved"))
    print("-" * 104)
    for row in rows:
        print("%-36s %-32s %-9s %-6s %s" % (
            row["fault"], row["expected"], "yes" if row["detected"] else "NO",
            row["gate"], ",".join(row["totals_moved"]) or "none"))
    print("-" * 104)
    print("%d/%d faults detected - %s" % (sum(1 for row in rows if row["detected"]),
                                          len(rows), "PASS" if passed else "FAIL"))


if __name__ == "__main__":
    raise SystemExit(main())
