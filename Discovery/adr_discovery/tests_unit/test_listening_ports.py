"""A local model runtime's listening port reaches the snapshot as evidence."""

from __future__ import annotations

from adr_discovery.contracts.evidence import Channel
from adr_discovery.contracts.records import Liveness
from adr_discovery.pipeline import discover

OLLAMA = "/opt/homebrew/bin/ollama"


def _serving(world, port=11434):
    world.dir("/home/a")
    world.binary(OLLAMA, "\x7fELF")
    world.surface("packages", [{"manager": "brew", "name": "ollama", "path": OLLAMA}])
    world.surface("processes", [{"pid": 9, "exe": OLLAMA, "user": "a"}])
    world.surface("sockets", [{"proto": "tcp", "state": "LISTEN", "local_port": port, "pid": 9}])
    return world


def test_the_port_is_evidence_on_the_runtime_serving_it(world, catalog):
    snapshot = discover(_serving(world).gate(), catalog)

    (asset,) = [a for a in snapshot.assets if a.catalog_id == "ollama"]
    assert asset.liveness is Liveness.RUNNING
    assert any(e.channel is Channel.NETWORK and "local model port 11434" in e.proof
               for e in asset.evidence)


def test_a_port_outside_the_model_port_set_is_not_evidence(world, catalog):
    snapshot = discover(_serving(world, port=22).gate(), catalog)

    (asset,) = [a for a in snapshot.assets if a.catalog_id == "ollama"]
    assert not any(e.channel is Channel.NETWORK for e in asset.evidence)
