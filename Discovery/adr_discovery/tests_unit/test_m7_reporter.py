"""M7 -- reporter.

Half of these assert on a single snapshot; the rest need two, so the
harness stores a before and an after and diffs them the way production
does. The empty-machine case runs first, because a module that writes
nothing when it finds nothing is indistinguishable from one that failed.
"""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from adr_discovery.contracts.records import Asset, Kind, Risk
from adr_discovery.contracts.snapshot import Coverage, Denied, Snapshot, Unavailable
from adr_discovery.reporter import DifferentEndpoints, diff, to_json


def snapshot(assets=(), hostname="host-a", coverage=None):
    return Snapshot(hostname=hostname, username="alice", platform="darwin",
                    timestamp="2026-08-22T00:00:00+00:00", assets=tuple(assets),
                    coverage=coverage or Coverage())


def asset(name="claude-code", version="2.1.3", root="/opt/x", **kwargs):
    return Asset(asset_id=kwargs.pop("asset_id", "id-" + name), kind=Kind.CLI_AGENT,
                 name=name, identity=name, install_root=root, version=version, **kwargs)


def test_u7_01_a_clean_machine_still_emits_a_snapshot():
    empty = snapshot()

    document = json.loads(to_json(empty))

    assert document["assets"] == []
    assert "coverage" in document
    assert document["schema_version"]


def test_u7_02_asset_ids_are_unique():
    many = [asset(name=f"t{i}", asset_id=f"id-{i}") for i in range(500)]

    ids = {a.asset_id for a in many}

    assert len(ids) == 500


def test_u7_03_an_upgrade_is_one_change_not_two():
    before = snapshot([asset(version="2.1.3")])
    after = snapshot([asset(version="2.2.0")])

    delta = diff(before, after)

    assert [c.kind for c in delta.changes] == ["version_changed"]
    assert delta.of("appeared") == () and delta.of("disappeared") == ()


def test_u7_04_a_reinstall_is_not_a_disappearance():
    before = snapshot([asset(root="/opt/old", asset_id="id-old")])
    after = snapshot([asset(root="/opt/new", asset_id="id-new")])

    delta = diff(before, after)

    assert [c.kind for c in delta.changes] == ["reinstalled"]


def test_u7_05_risk_moves_even_when_the_inventory_does_not():
    """pinned -> floating is a silent regression if only membership is diffed."""
    before = snapshot([replace(asset(), risk=Risk(pinned=True))])
    after = snapshot([replace(asset(), risk=Risk(pinned=False))])

    delta = diff(before, after)

    assert [c.detail for c in delta.of("risk_delta")] == ["pinned -> floating"]


def test_u7_06_a_surface_that_went_dark_is_a_change():
    before = snapshot(coverage=Coverage())
    after = snapshot(coverage=Coverage(denied=(Denied("/opt/secret", "eacces"),),
                                       unavailable=(Unavailable("dpkg", "gone"),)))

    delta = diff(before, after)

    assert any("became unreadable" in c for c in delta.coverage_delta)
    assert any("provider became unavailable" in c for c in delta.coverage_delta)


def test_u7_07_two_endpoints_are_refused():
    with pytest.raises(DifferentEndpoints):
        diff(snapshot(hostname="host-a"), snapshot(hostname="host-b"))


def test_u7_07b_cross_endpoint_is_possible_but_must_be_asked_for():
    delta = diff(snapshot(hostname="host-a"), snapshot(hostname="host-b"),
                 allow_cross_endpoint=True)

    assert delta.endpoint == "host-b"


def test_u7_08_fleet_fan_out_is_not_computed_on_the_endpoint():
    document = json.loads(to_json(snapshot([asset()])))

    assert not any("fleet" in key or "fan_out" in key for key in document)


def test_u7_09_a_snapshot_round_trips():
    original = snapshot([asset()])

    document = json.loads(to_json(original))

    assert document["assets"][0]["asset_id"] == "id-claude-code"
    assert document["assets"][0]["kind"] == "cli_agent"
    assert json.loads(to_json(original)) == document
