"""Ask the system first.

Package databases, application registries and the kernel have already
catalogued most of what is installed, with provenance attached. Querying
them is cheaper and more complete than searching for it, and every hit
arrives with the provenance M4 needs anyway.

Each function returns candidates and leaves a coverage record when its
surface could not be read -- an unavailable registry is never an empty one.
"""

from __future__ import annotations

from ...contracts.records import Candidate, Priority
from ...redact.rules import scrub_argv


def from_packages(gate) -> tuple[Candidate, ...]:
    result = gate.packages()
    if not result.ok:
        return ()
    gate.ledger.probe("packages", "ran", f"{len(result.value)} records")
    return tuple(
        Candidate(
            kind="package",
            path=pkg.path or pkg.name,
            source=f"package:{pkg.manager}",
            priority=Priority.HOME,
            detail={"manager": pkg.manager, "name": pkg.name, "version": pkg.version},
        )
        for pkg in result.value
    )


def from_applications(gate) -> tuple[Candidate, ...]:
    result = gate.applications()
    if not result.ok:
        return ()
    gate.ledger.probe("applications", "ran", f"{len(result.value)} records")
    return tuple(
        Candidate(
            kind="application",
            path=app.path or app.ident,
            source="app_registry",
            priority=Priority.HOME,
            detail={"ident": app.ident, "name": app.name, "version": app.version, "vendor": app.vendor},
        )
        for app in result.value
    )


def from_kernel(gate) -> tuple[Candidate, ...]:
    """What is running, from which binary, and what it is serving.

    The exe path is carried through verbatim. Resolving a process *name*
    against PATH is the defect this source exists to avoid.
    """
    out: list[Candidate] = []
    procs = gate.processes()
    if procs.ok:
        gate.ledger.probe("processes", "ran", f"{len(procs.value)} pids")
        for p in procs.value:
            argv = scrub_argv(p.argv)
            out.append(
                Candidate(
                    kind="process",
                    path=p.exe,
                    source="kernel",
                    priority=Priority.HOME,
                    detail={
                        "pid": p.pid, "ppid": p.ppid, "argv": argv, "cwd": p.cwd,
                        "user": p.user, "env_names": p.env_names,
                        "unattended": _is_unattended(argv),
                    },
                )
            )
    socks = gate.sockets()
    if socks.ok:
        gate.ledger.probe("sockets", "ran", f"{len(socks.value)} sockets")
        for s in socks.value:
            if s.state != "LISTEN":
                continue
            out.append(
                Candidate(
                    kind="listening_socket",
                    path=f"tcp:{s.local_port}",
                    source="kernel",
                    priority=Priority.HOME,
                    detail={"port": s.local_port, "pid": s.pid},
                )
            )
    return tuple(out)


def _is_unattended(argv: tuple[str, ...]) -> bool:
    flags = set(argv)
    return bool(flags & {
        "--dangerously-skip-permissions", "--yolo", "--auto-approve", "--no-confirm",
    })
