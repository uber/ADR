"""End-to-end fidelity harness for ADR Discovery.

Implements the method in ``Discovery/tests/README.md``: install a known set of
AI tools on a clean VM, scan, and score what the collector reported against
what was actually installed.

The package boundary is deliberately a file on disk rather than a function
call. ``manifest.actual.json`` and the two snapshots are plain files, so a
failed run can be re-scored without re-running it, a scoring fix can be
replayed against every historical run, and nobody debugging a false positive
needs a VM to do it.
"""

__all__ = ["manifest", "scoring", "install", "provision", "report"]
