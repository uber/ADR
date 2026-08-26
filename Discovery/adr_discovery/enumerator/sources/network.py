"""Network -- what the machine talks to.

Listening sockets find a *server*. Almost every AI tool is a *client*, and
the connection it opens is the one piece of evidence it cannot suppress and
still function -- which makes this the only source that yields anything at
all for a tool the catalog has never heard of.

The resolver cache matters more than the connection table, because it
covers a window rather than an instant and so survives a tool that ran an
hour before the scan.
"""

from __future__ import annotations

from ...contracts.records import Candidate, Priority
from ..markers import LOCAL_MODEL_PORTS, is_model_provider


def from_network(gate, kernel_candidates: tuple[Candidate, ...] = ()) -> tuple[Candidate, ...]:
    out: list[Candidate] = []
    processes = {
        c.detail.get("pid"): c
        for c in kernel_candidates
        if c.kind == "process" and c.detail.get("pid") is not None
    }

    socks = gate.sockets()
    if socks.ok:
        for s in socks.value:
            if s.state == "ESTABLISHED" and is_model_provider(s.remote_host):
                process = processes.get(s.pid)
                out.append(
                    Candidate(
                        kind="network_peer",
                        path=process.path if process is not None else s.remote_host,
                        source="network:established",
                        priority=Priority.HOME,
                        detail={
                            "pid": s.pid, "port": s.remote_port, "provider": True,
                            "remote_host": s.remote_host,
                            "env_names": process.detail.get("env_names", ()) if process else (),
                            "unattended": process.detail.get("unattended", False) if process else False,
                        },
                    )
                )
            elif s.state == "LISTEN" and s.local_port in LOCAL_MODEL_PORTS:
                out.append(
                    Candidate(
                        kind="model_port",
                        path=f"tcp:{s.local_port}",
                        source="network:listening",
                        priority=Priority.HOME,
                        detail={"port": s.local_port, "pid": s.pid},
                    )
                )

    cache = gate.dns_cache()
    if cache.ok:
        gate.ledger.probe("dns_cache", "ran", f"{len(cache.value)} entries")
        for entry in cache.value:
            if is_model_provider(entry.hostname):
                out.append(
                    Candidate(
                        kind="dns_peer",
                        path=entry.hostname,
                        source="network:resolver_cache",
                        priority=Priority.HOME,
                        detail={"provider": True},
                    )
                )
    return tuple(out)
