"""PowerShell's exact profile files, without enumerating personal folders."""

from __future__ import annotations

from ...contracts.records import Candidate, Priority


def from_profiles(gate) -> tuple[Candidate, ...]:
    provider = getattr(gate.providers, "powershell_profile_paths", None)
    if not callable(provider):
        if getattr(gate.providers, "command_syntax", "") == "windows":
            gate.ledger.unavailable("powershell_profiles", "known profile locations unavailable")
        return ()
    out = []
    failed = 0
    for path in provider(gate):
        info = gate.stat_profile(path)
        if info.ok:
            out.append(Candidate("shell_profile", path, "app_state:powershell_profile", Priority.HOME))
        elif info.reason != "absent":
            failed += 1
    gate.ledger.probe("powershell_profiles", "degraded" if failed else "ran",
                      f"{len(out)} known profiles; {failed} unreadable; direct env assignments only")
    return tuple(out)
