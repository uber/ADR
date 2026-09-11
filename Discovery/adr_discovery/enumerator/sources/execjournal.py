"""Exec events -- what ran between scans.

A snapshot finds an agent that happens to be running when the scan fires.
An agent that runs forty seconds a night is absent from every daily scan
and present on the machine the whole time.

This source is conditional on a privileged collector. Its absence is a
coverage fact and must never read as "nothing ran" -- which is what the
`unavailable` record written by the provider guarantees (U2-10).
"""

from __future__ import annotations

from ...contracts.records import Candidate, Priority
from ...redact.rules import scrub_argv


def from_exec_journal(gate) -> tuple[Candidate, ...]:
    result = gate.exec_journal()
    if not result.ok:
        gate.ledger.probe("exec_journal", "degraded", result.reason)
        return ()
    gate.ledger.probe("exec_journal", "ran", f"{len(result.value)} events")
    out = []
    for ev in result.value:
        argv = scrub_argv(ev.argv)
        out.append(Candidate(
            kind="exec_event",
            path=ev.exe,
            source="exec_journal",
            priority=Priority.HOME,
            detail={
                "argv": argv, "ppid": ev.ppid,
                "parent_exe": ev.parent_exe, "started": ev.started,
                "unattended": bool(set(argv) & {
                    "--dangerously-skip-permissions", "--yolo", "--auto-approve", "--no-confirm",
                }),
            },
        ))
    return tuple(out)
