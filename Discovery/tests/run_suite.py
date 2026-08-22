"""Run the fidelity suite and print a scorecard."""

import sys
from collections import OrderedDict

sys.path.insert(0, ".")

from tests.framework import run_cases  # noqa: E402


def load():
    cases = OrderedDict()
    from tests import cases_tools
    cases.update(cases_tools.CASES)
    for module_name in ("cases_mcp", "cases_skills", "cases_agents", "cases_hardening"):
        try:
            module = __import__("tests.%s" % module_name, fromlist=["CASES"])
        except ImportError:
            continue
        cases.update(module.CASES)
    return cases


def main():
    only = sys.argv[1] if len(sys.argv) > 1 else None
    verbose = "-v" in sys.argv
    cases = load()
    results, failures = run_cases(cases, only=only)
    for case_id, label, ok, detail in results:
        if not ok or verbose:
            print("%-5s %-7s %s%s" % ("PASS" if ok else "FAIL", case_id, label,
                                      ("  -> " + detail) if detail else ""))
    groups = {}
    for case_id, _, ok, _ in results:
        group = case_id.split("-")[0]
        passed, total = groups.get(group, (0, 0))
        groups[group] = (passed + (1 if ok else 0), total + 1)
    print("\nchecks by group:")
    for group in sorted(groups):
        passed, total = groups[group]
        print("  %-3s %3d/%-3d" % (group, passed, total))
    cases_failed = {r[0] for r in failures}
    print("\n%d/%d checks pass, %d cases with failures%s"
          % (len(results) - len(failures), len(results), len(cases_failed),
             (": " + " ".join(sorted(cases_failed))) if cases_failed else ""))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
