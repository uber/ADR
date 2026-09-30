"""Home discovery keeps the caller fallback without leaving the Gate boundary."""

import pytest

from adr_discovery.enumerator import enumerate_candidates
from adr_discovery.enumerator.roots import homes, ordered_roots
from adr_discovery.enumerator.sources.appstate import from_app_state
from adr_discovery.world.platform.darwin import DarwinProviders
from adr_discovery.world.platform.linux import LinuxProviders


class _LegacyProviders:
    """A provider predating both homes() and direct_homes()."""

    def __init__(self, roots):
        self._roots = roots

    def home_roots(self):
        return self._roots

    def owner_of(self, uid):
        return "fixture-user"


class _LegacyDirectProviders(_LegacyProviders):
    """A provider exposing direct homes without the homes() convenience method."""

    def __init__(self, roots, direct):
        super().__init__(roots)
        self._direct = direct

    def direct_homes(self):
        return self._direct


@pytest.fixture(
    params=[
        (LinuxProviders(), "/home", "/root"),
        (DarwinProviders(), "/Users", "/var/root"),
        (_LegacyProviders(("/home", "/root")), "/home", "/root"),
        (_LegacyProviders(("/Users", "/var/root")), "/Users", "/var/root"),
        (_LegacyDirectProviders(("/home",), ("/root",)), "/home", "/root"),
        (_LegacyDirectProviders(("/Users",), ("/var/root",)), "/Users", "/var/root"),
    ],
    ids=["linux", "macos", "legacy-linux", "legacy-macos", "direct-linux", "direct-macos"],
)
def home_world(world, request):
    provider, container, root_home = request.param
    world.dir(container).dir(root_home)
    return world, provider, container, root_home


def test_direct_root_home_does_not_suppress_home_fallback(home_world):
    world, provider, _, root_home = home_world
    world.json("/data/alice/.claude.json", {})
    gate = world.gate(providers=provider, env={"HOME": "/data/alice"})

    discovered = homes(gate)
    assert discovered == ("/data/alice", root_home)
    assert "/data/alice" in {path for path, _ in ordered_roots(gate)}
    assert "/data/alice/.claude.json" in {
        candidate.path for candidate in from_app_state(gate, discovered)
    }


def test_home_fallback_is_deduplicated_against_direct_homes(home_world):
    world, provider, _, root_home = home_world
    gate = world.gate(providers=provider, env={"HOME": root_home})

    assert homes(gate) == (root_home,)


def test_regular_homes_keep_existing_fallback_behavior(home_world):
    world, provider, container, root_home = home_world
    world.dir(container + "/alice").dir("/data/other")
    gate = world.gate(providers=provider, env={"HOME": "/data/other"})

    assert homes(gate) == (container + "/alice", root_home)


@pytest.mark.parametrize("is_file", [False, True], ids=["missing", "file"])
def test_home_fallback_requires_an_existing_directory(home_world, is_file):
    world, provider, _, root_home = home_world
    if is_file:
        world.file("/data/alice", "not a home directory")
    gate = world.gate(providers=provider, env={"HOME": "/data/alice"})

    assert homes(gate) == (root_home,)


def test_home_fallback_cannot_escape_fixture_root(home_world, tmp_path_factory):
    world, provider, _, root_home = home_world
    outside = tmp_path_factory.mktemp("outside-home")
    world.symlink("/data/alice", str(outside), outside=True)
    gate = world.gate(providers=provider, env={"HOME": "/data/alice"})

    assert homes(gate) == (root_home,)
    assert any(
        denied.path == "/data/alice" and denied.reason == "outside_root"
        for denied in gate.ledger.freeze().denied
    )


@pytest.mark.parametrize(
    ("provider", "container", "root_home"),
    [(LinuxProviders(), "/home", "/root"), (DarwinProviders(), "/Users", "/var/root")],
    ids=["linux", "macos"],
)
def test_nonstandard_home_config_reaches_full_enumeration(world, provider, container, root_home):
    world.dir(container).dir(root_home).json("/data/alice/.claude.json", {})
    gate = world.gate(providers=provider, env={"HOME": "/data/alice"})

    assert "/data/alice/.claude.json" in {
        candidate.path for candidate in enumerate_candidates(gate)
    }
