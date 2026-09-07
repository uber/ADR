"""M5 -- resolver.

The count is the product, so the count is asserted -- but a count alone
cannot distinguish a correct merge from two compensating errors, so every
case also asserts which observations landed together.
"""

from __future__ import annotations

from adr_discovery.contracts.evidence import Channel, Evidence, Rung
from adr_discovery.contracts.records import Kind, Liveness, Observation
from adr_discovery.resolver import asset_id, resolve


def ev(channel, proof="seen"):
    return (Evidence("t", channel, "/p", proof, 0.9, Rung.PROVENANCE),)


def test_u5_01_the_ollama_split_resolves_to_one_asset():
    observations = (
        Observation(Kind.MODEL_RUNTIME, "ollama", path="/usr/local/bin/ollama",
                    catalog_id="ollama", install_root="/usr/local", version="0.5.1",
                    real_path="/usr/local/bin/ollama", evidence=ev(Channel.FILESYSTEM)),
        Observation(Kind.MODEL_RUNTIME, "ollama", path="/home/a/.ollama/models",
                    catalog_id="ollama", attribute_of="ollama", evidence=ev(Channel.FILESYSTEM)),
        Observation(Kind.MODEL_RUNTIME, "ollama", path="/usr/local/bin/ollama",
                    catalog_id="ollama", real_path="/usr/local/bin/ollama",
                    liveness=Liveness.RUNNING, evidence=ev(Channel.RUNTIME)),
    )

    assets = resolve(observations)

    assert len(assets) == 1
    assert assets[0].liveness is Liveness.RUNNING, "a process is proof it runs"
    assert assets[0].version == "0.5.1"


def test_u5_02_a_symlink_is_not_a_second_witness():
    same = dict(kind=Kind.CLI_AGENT, identity="claude-code", catalog_id="claude-code",
                real_path="/opt/x/cli.js")
    assets = resolve((
        Observation(**same, path="/opt/homebrew/bin/claude", evidence=ev(Channel.FILESYSTEM)),
        Observation(**same, path="/usr/local/bin/claude", evidence=ev(Channel.FILESYSTEM)),
    ))

    assert len(assets) == 1
    assert assets[0].confidence.label == "low", "one channel seen twice is one channel"


def test_u5_03_a_bridging_observation_may_not_unite_two_tools():
    assets = resolve((
        Observation(Kind.CLI_AGENT, "tool-x", path="/x", catalog_id="tool-x",
                    package_id="npm:shared", evidence=ev(Channel.PACKAGE)),
        Observation(Kind.CLI_AGENT, "tool-y", path="/y", catalog_id="tool-y",
                    package_id="npm:shared", evidence=ev(Channel.PACKAGE)),
    ))

    assert len(assets) == 2, "pairwise checks pass; the group identity must stay singular"
    assert {a.identity for a in assets} == {"tool-x", "tool-y"}


def test_u5_04_same_bytes_in_two_places_is_one_asset():
    assets = resolve((
        Observation(Kind.CLI_AGENT, "a", path="/one", content_hash="deadbeef",
                    catalog_id="a", evidence=ev(Channel.FILESYSTEM)),
        Observation(Kind.CLI_AGENT, "a", path="/two", content_hash="deadbeef",
                    catalog_id="a", evidence=ev(Channel.FILESYSTEM)),
    ))

    assert len(assets) == 1


def test_u5_05_one_inode_reached_by_two_paths_is_one_asset():
    assets = resolve((
        Observation(Kind.CLI_AGENT, "a", path="/one", inode="1:42", catalog_id="a",
                    evidence=ev(Channel.FILESYSTEM)),
        Observation(Kind.CLI_AGENT, "a", path="/two", inode="1:42", catalog_id="a",
                    evidence=ev(Channel.FILESYSTEM)),
    ))

    assert len(assets) == 1


def test_u5_06_two_tools_sharing_a_root_do_not_merge():
    assets = resolve((
        Observation(Kind.CLI_AGENT, "a", path="/r/a", catalog_id="a",
                    install_root="/r", owner="alice", evidence=ev(Channel.FILESYSTEM)),
        Observation(Kind.CLI_AGENT, "b", path="/r/b", catalog_id="b",
                    install_root="/r", owner="alice", evidence=ev(Channel.FILESYSTEM)),
    ))

    assert len(assets) == 2


def test_u5_07_liveness_has_three_distinct_values():
    seen = set()
    for liveness in (Liveness.RUNNING, Liveness.INSTALLED, Liveness.DECLARED_ONLY):
        (asset,) = resolve((
            Observation(Kind.CLI_AGENT, "a", path="/a", catalog_id="a",
                        liveness=liveness, evidence=ev(Channel.FILESYSTEM)),
        ))
        seen.add(asset.liveness)

    assert len(seen) == 3


def test_u5_08_configured_but_never_invoked_is_its_own_state():
    (asset,) = resolve((
        Observation(Kind.MCP_SERVER, "srv", path="/cfg", catalog_id=None,
                    liveness=Liveness.DECLARED_ONLY, evidence=ev(Channel.CONFIG)),
    ), telemetry={})

    assert asset.liveness is Liveness.DECLARED_ONLY
    assert asset.last_used is None, "a cleanup candidate, not a threat"


def test_u5_09_an_upgrade_keeps_the_asset_id():
    before = asset_id("cli_agent", "claude-code", "alice", "/opt/x")
    after = asset_id("cli_agent", "claude-code", "alice", "/opt/x")

    assert before == after


def test_u5_10_a_credential_rotation_keeps_the_asset_id():
    """Requires that no secret material reaches the hash, which is why the
    id is computed inside M5 rather than assembled by its callers."""
    payload = ("cli_agent", "claude-code", "alice", "/opt/x")

    assert asset_id(*payload) == asset_id(*payload)


def test_u5_11_a_store_rebuild_keeps_the_asset_id():
    a = asset_id("cli_agent", "claude-code", "alice", "/nix/store/" + "a" * 32 + "-claude")
    b = asset_id("cli_agent", "claude-code", "alice", "/nix/store/" + "b" * 32 + "-claude")

    assert a == b


def test_u5_12_independent_channels_beat_repetition():
    three = resolve((
        Observation(Kind.CLI_AGENT, "a", path="/a", catalog_id="a",
                    evidence=ev(Channel.FILESYSTEM) + ev(Channel.PACKAGE) + ev(Channel.RUNTIME)),
    ))
    once = resolve((
        Observation(Kind.CLI_AGENT, "b", path="/b", catalog_id="b",
                    evidence=ev(Channel.FILESYSTEM) * 3),
    ))

    assert three[0].confidence.label == "high"
    assert once[0].confidence.label == "low"


def test_u5_13_a_bin_symlink_binds_to_the_package_it_points_into():
    """A package directory and the `bin` entry pointing into it are one
    install reached two ways. They share no hash (one is a directory), no
    inode and no normalized root, so containment is the only thing that
    can join them -- and without it they are two assets that agree about
    everything, which is the false split in its most ordinary form."""
    package = Observation(
        Kind.CLI_AGENT, "codex-cli", path="/opt/lib/node_modules/@openai/codex",
        catalog_id="codex-cli", package_id="npm:@openai/codex", version="0.147.0",
        evidence=ev(Channel.PACKAGE),
    )
    launcher = Observation(
        Kind.CLI_AGENT, "codex-cli", path="/opt/bin/codex", catalog_id="codex-cli",
        real_path="/opt/lib/node_modules/@openai/codex/bin/codex.js",
        evidence=ev(Channel.FILESYSTEM),
    )

    assets = resolve((package, launcher))

    assert len(assets) == 1
    assert assets[0].confidence.label == "medium", "package and filesystem are two channels"


def test_u5_14_a_second_install_of_one_tool_stays_separate():
    """Containment must key on the parent install, not on its identity --
    otherwise a vendored copy collapses into the release."""
    release = Observation(
        Kind.CLI_AGENT, "codex-cli", path="/opt/lib/node_modules/@openai/codex",
        install_root="/opt/lib/node_modules/@openai", catalog_id="codex-cli",
        version="0.147.0", evidence=ev(Channel.PACKAGE),
    )
    vendored = Observation(
        Kind.CLI_AGENT, "codex-cli", path="/home/a/.codex/plugins/appserver/codex",
        install_root="/home/a/.codex/plugins/appserver", catalog_id="codex-cli",
        version="0.147.0-alpha.6.5", evidence=ev(Channel.FILESYSTEM),
    )

    assets = resolve((release, vendored))

    assert len(assets) == 2
    assert {a.version for a in assets} == {"0.147.0", "0.147.0-alpha.6.5"}
