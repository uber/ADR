"""Connections are matched to model providers by address, not only by name.

A socket table never carries a hostname, so before this every live
connection was invisible to the network channel and the review queue,
which only that channel can fill, stayed empty.
"""

from __future__ import annotations

import pytest

from adr_discovery.contracts.evidence import Channel
from adr_discovery.enumerator.markers import RESOLVABLE_PROVIDER_HOSTS
from adr_discovery.enumerator.sources.network import from_network
from adr_discovery.pipeline import discover
from adr_discovery.world.platform.linux import _hex_ip

AGENT = "/opt/agent/bin/agent"
OPENAI = "162.159.140.245"


def _connected(world, exe=AGENT, remote=OPENAI, user="a"):
    world.dir("/home/a")
    world.surface("processes", [{"pid": 41, "exe": exe, "user": user}])
    world.surface("sockets", [{"proto": "tcp", "state": "ESTABLISHED", "local_port": 50000,
                               "remote_host": remote, "remote_port": 443, "pid": 41}])
    return world


def _resolves(world, **names):
    world.surface("resolver", [{"hostname": h.replace("_", "."), "address": a}
                               for h, a in names.items()])
    return world


@pytest.mark.parametrize(("raw", "expected"), [
    ("0100007F", "127.0.0.1"),
    ("00000000000000000000000001000000", "::1"),
    ("0000000000000000FFFF00000100007F", "127.0.0.1"),
    ("B80D0120000000000000000001000000", "2001:db8::1"),
    ("nothex", "nothex"),
])
def test_proc_net_addresses_decode_for_both_families(raw, expected):
    assert _hex_ip(raw) == expected


def test_an_unknown_process_talking_to_a_provider_address_is_queued_for_review(world, catalog):
    _resolves(_connected(world), api_openai_com=OPENAI)

    snapshot = discover(world.gate(resolve_names=True), catalog)

    (item,) = [r for r in snapshot.review_queue if r.path == AGENT]
    assert "network_intent" in item.signals
    assert any(p.name == "resolver" and p.status == "ran" for p in snapshot.coverage.probes)


def test_an_address_no_provider_resolves_to_is_not_a_peer(world):
    _resolves(_connected(world, remote="10.1.2.3"), api_openai_com=OPENAI)

    assert [c for c in from_network(world.gate(resolve_names=True)) if c.kind == "network_peer"] == []


def test_a_bracketed_ipv6_peer_matches(world):
    _resolves(_connected(world, remote="[2606:4700::6810:1]"), api_anthropic_com="2606:4700::6810:1")

    (peer,) = [c for c in from_network(world.gate(resolve_names=True)) if c.kind == "network_peer"]
    assert peer.detail["provider_host"] == "api.anthropic.com"


def test_a_catalogued_install_carries_the_connection_as_evidence(world, catalog):
    versions = "/home/a/.local/share/claude/versions"
    world.binary(f"{versions}/2.1.287", "\x7fELF")
    _resolves(_connected(world, exe=f"{versions}/2.1.287"), api_anthropic_com="160.79.104.10")
    world.surface("sockets", [{"proto": "tcp", "state": "ESTABLISHED", "local_port": 50000,
                               "remote_host": "160.79.104.10", "remote_port": 443, "pid": 41}])

    snapshot = discover(world.gate(resolve_names=True), catalog)

    (asset,) = [a for a in snapshot.assets if a.catalog_id == "claude-code"]
    network = [e for e in asset.evidence if e.channel is Channel.NETWORK]
    assert network and "api.anthropic.com" in network[0].proof
    assert snapshot.review_queue == ()


def test_resolution_unavailable_is_recorded_not_silent(world):
    _connected(world)  # no resolver.json

    gate = world.gate(resolve_names=True)
    assert [c for c in from_network(gate) if c.kind == "network_peer"] == []
    assert "resolver" in [u.provider for u in gate.ledger.freeze().unavailable]


def test_no_lookup_is_made_unless_asked_for(world):
    """A scan sends nothing over the network by default; the gap is recorded."""
    _resolves(_connected(world), api_openai_com=OPENAI)

    gate = world.gate()
    assert [c for c in from_network(gate) if c.kind == "network_peer"] == []
    assert any(u.provider == "resolver" and "--resolve" in u.reason
               for u in gate.ledger.freeze().unavailable)


def test_only_hosts_with_fixed_addresses_are_resolved(world):
    """Rotating pools would return a sample and share addresses with other services."""
    asked: list[tuple[str, ...]] = []
    _connected(world)
    gate = world.gate(resolve_names=True)
    real = gate.providers.resolve
    gate.providers.resolve = lambda g, names: asked.append(names) or real(g, names)

    from_network(gate)

    (names,) = asked
    assert names == RESOLVABLE_PROVIDER_HOSTS
    assert "api.anthropic.com" in names and "api.openai.com" in names
    assert not any("googleapis" in n or "huggingface" in n or "azure" in n for n in names)


def test_no_lookup_when_every_peer_is_already_a_name(world):
    _connected(world, remote="api.openai.com")

    gate = world.gate()
    (peer,) = [c for c in from_network(gate) if c.kind == "network_peer"]
    assert peer.detail["provider_host"] == "api.openai.com"
    assert "resolver" not in [u.provider for u in gate.ledger.freeze().unavailable]


def test_the_host_resolver_answers_from_the_local_resolver(world):
    from adr_discovery.world.platform.base import HostResolver, NullProviders

    class Local(HostResolver, NullProviders):
        pass

    result = Local().resolve(world.gate(), ("localhost", "name.invalid"))

    assert result.ok
    assert {r.hostname for r in result.value} == {"localhost"}
    assert {r.address for r in result.value} & {"127.0.0.1", "::1"}
