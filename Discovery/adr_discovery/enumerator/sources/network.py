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

import ipaddress

from ...contracts.records import Candidate, Priority
from ..markers import LOCAL_MODEL_PORTS, RESOLVABLE_PROVIDER_HOSTS, is_model_provider


def from_network(gate, kernel_candidates: tuple[Candidate, ...] = ()) -> tuple[Candidate, ...]:
    out: list[Candidate] = []
    processes = {
        c.detail.get("pid"): c
        for c in kernel_candidates
        if c.kind == "process" and c.detail.get("pid") is not None
    }

    socks = gate.sockets()
    if socks.ok:
        by_address = _provider_addresses(gate, socks.value)
        for s in socks.value:
            provider = _provider_of(s.remote_host, by_address) if s.state == "ESTABLISHED" else None
            if provider is not None:
                process = processes.get(s.pid)
                out.append(
                    Candidate(
                        kind="network_peer",
                        path=process.path if process is not None else s.remote_host,
                        source="network:established",
                        priority=Priority.HOME,
                        detail={
                            "pid": s.pid, "port": s.remote_port, "provider": True,
                            "remote_host": s.remote_host, "provider_host": provider,
                            "env_names": process.detail.get("env_names", ()) if process else (),
                            "unattended": process.detail.get("unattended", False) if process else False,
                        },
                    )
                )
            elif s.state == "LISTEN" and s.local_port in LOCAL_MODEL_PORTS:
                # Attributed to the serving process when it is known, so an
                # identified runtime carries the port as evidence instead of
                # the port standing alone and being dropped.
                process = processes.get(s.pid)
                out.append(
                    Candidate(
                        kind="model_port",
                        path=process.path if process is not None else f"tcp:{s.local_port}",
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


def _provider_of(host: str, by_address: dict[str, str]) -> str | None:
    if is_model_provider(host):
        return host
    return by_address.get(_address(host) or "")


def _address(host: str) -> str | None:
    """A peer as a canonical IP literal, or None for a hostname."""
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None
    mapped = getattr(address, "ipv4_mapped", None)
    return str(mapped or address)


def _provider_addresses(gate, sockets) -> dict[str, str]:
    """Address -> provider hostname, for the peers that are bare addresses.

    Socket tables carry numbers and the provider list carries names, so
    without this no live connection ever matched. The names are resolved
    once, and only when some established peer needs it. An address shared
    by a CDN with other tenants can be attributed wrongly; that is why this
    yields a review candidate, never a finding on its own.
    """
    if not any(s.state == "ESTABLISHED" and _address(s.remote_host) for s in sockets):
        return {}
    resolved = gate.resolve(RESOLVABLE_PROVIDER_HOSTS)
    if not resolved.ok:
        return {}
    out: dict[str, str] = {}
    for row in resolved.value:
        address = _address(row.address)
        if address is not None:
            out.setdefault(address, row.hostname)
    gate.ledger.probe("resolver", "ran", f"{len(out)} provider addresses")
    return out
