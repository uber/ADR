"""Native installers: identity from the directory the vendor's updater owns."""

from __future__ import annotations

import json

import pytest

from adr_discovery.catalog.load import CatalogError, loads
from adr_discovery.contracts.evidence import Channel, Rung
from adr_discovery.contracts.records import Kind, Liveness
from adr_discovery.pipeline import discover

VERSIONS = "/home/a/.local/share/claude/versions"


def _claude(snapshot):
    return [a for a in snapshot.assets if a.catalog_id == "claude-code"]


def _installed(world, *versions: str, link: str | None = "2.1.287"):
    for version in versions:
        world.binary(f"{VERSIONS}/{version}", "\x7fELF")
    if link:
        world.symlink("/home/a/.local/bin/claude", f"{VERSIONS}/{link}")
    return world


def test_launcher_link_into_the_layout_identifies_the_release(world, catalog):
    _installed(world, "2.1.287")

    (asset,) = _claude(discover(world.gate(), catalog))

    assert asset.kind is Kind.CLI_AGENT
    assert asset.version == "2.1.287"
    assert asset.verification == (Rung.PROVENANCE,)
    assert asset.install_root == VERSIONS
    assert any("installer-managed layout" in e.proof for e in asset.evidence)


def test_a_claude_outside_the_layout_is_not_concluded(world, catalog):
    world.binary("/opt/tools/claude", "\x7fELF")
    world.dir("/home/a")

    assert _claude(discover(world.gate(), catalog)) == []


def test_a_process_running_a_release_merges_into_the_install(world, catalog):
    _installed(world, "2.1.287", "2.1.296")
    world.surface("processes", [{"pid": 7, "exe": f"{VERSIONS}/2.1.296", "user": "a"}])

    (asset,) = _claude(discover(world.gate(), catalog))

    assert asset.liveness is Liveness.RUNNING
    # The launcher's release is what runs next; the process is the previous one.
    assert asset.version == "2.1.287"
    assert asset.running_versions == ("2.1.296",)


def test_every_running_release_is_recorded(world, catalog):
    _installed(world, "2.1.287", "2.1.296", "2.1.1000")
    world.surface("processes", [
        {"pid": 7, "exe": f"{VERSIONS}/2.1.296", "user": "a"},
        {"pid": 8, "exe": f"{VERSIONS}/2.1.287", "user": "a"},
        {"pid": 9, "exe": f"{VERSIONS}/2.1.1000", "user": "a"},
        {"pid": 10, "exe": f"{VERSIONS}/2.1.287", "user": "a"},
    ])

    (asset,) = _claude(discover(world.gate(), catalog))

    assert asset.version == "2.1.287"
    assert asset.running_versions == ("2.1.287", "2.1.296", "2.1.1000")


def test_an_idle_install_has_no_running_versions(world, catalog):
    (asset,) = _claude(discover(_installed(world, "2.1.287").gate(), catalog))

    assert asset.running_versions == ()


def test_a_running_install_is_seen_through_two_channels(world, catalog):
    _installed(world, "2.1.287")
    idle, = _claude(discover(world.gate(), catalog))
    world.surface("processes", [{"pid": 7, "exe": f"{VERSIONS}/2.1.287", "user": "a"}])

    running, = _claude(discover(world.gate(), catalog))

    assert idle.confidence.channels == (Channel.FILESYSTEM,)
    assert running.confidence.channels == (Channel.FILESYSTEM, Channel.RUNTIME)
    assert running.confidence.label == "medium"


def test_install_identity_is_the_same_whether_or_not_it_runs(world, catalog):
    _installed(world, "2.1.287")
    idle = _claude(discover(world.gate(), catalog))
    world.surface("processes", [{"pid": 7, "exe": f"{VERSIONS}/2.1.287", "user": world_owner(world)}])
    running = _claude(discover(world.gate(), catalog))

    assert [a.asset_id for a in idle] == [a.asset_id for a in running]


def test_a_name_without_the_version_shape_identifies_but_carries_no_version(world, catalog):
    _installed(world, "nightly", link="nightly")

    (asset,) = _claude(discover(world.gate(), catalog))

    assert asset.version is None


def test_a_dangling_launcher_concludes_nothing(world, catalog):
    world.dir(VERSIONS)
    world.symlink("/home/a/.local/bin/claude", f"{VERSIONS}/2.1.999")

    assert _claude(discover(world.gate(), catalog)) == []


def world_owner(world) -> str:
    """The account owning the fixture files, as the gate reports it."""
    return world.gate().stat(f"{VERSIONS}/2.1.287").value.owner


def _catalog(layout) -> str:
    return json.dumps({"version": "t", "entries": [
        {"id": "x", "name": "X", "vendor": "V", "kind": "cli_agent",
         "fingerprints": {"install_layouts": [layout]}},
    ]})


@pytest.mark.parametrize("layout", [
    {"target": "~/*/versions/*"},
    {"target": "relative/versions/*"},
    {"target": "~/.x/versions/*", "version_from": "argv"},
    {"no_target": True},
])
def test_malformed_layouts_are_rejected_at_load(layout):
    with pytest.raises(CatalogError):
        loads(_catalog(layout))


def test_two_entries_claiming_one_layout_is_ambiguous():
    layout = {"target": "~/.x/versions/*"}
    document = {"version": "t", "entries": [
        {"id": i, "name": i, "vendor": "V", "kind": "cli_agent",
         "fingerprints": {"install_layouts": [layout]}} for i in ("a", "b")
    ]}
    with pytest.raises(CatalogError, match="ambiguous install layout"):
        loads(json.dumps(document))
