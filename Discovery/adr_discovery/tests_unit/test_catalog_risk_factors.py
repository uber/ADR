"""What the catalog knows a tool can do reaches the asset's risk."""

from __future__ import annotations

from adr_discovery.contracts.records import Asset, Kind, Risk
from adr_discovery.judge import judge
from adr_discovery.pipeline import discover


def test_an_identified_catalogued_tool_carries_its_catalog_risk_factors(world, catalog):
    release = "/home/a/.local/share/claude/versions/2.1.287"
    world.binary(release, "\x7fELF")
    world.symlink("/home/a/.local/bin/claude", release)

    (asset,) = [a for a in discover(world.gate(), catalog).assets if a.catalog_id == "claude-code"]

    assert asset.risk.factors == catalog.by_id["claude-code"].risk_factors


def test_catalog_factors_add_to_derived_ones_without_duplicates():
    asset = Asset(asset_id="x", kind=Kind.CLI_AGENT, name="t", identity="t", catalog_id="t",
                  risk=Risk(factors=("plaintext_transport", "executes_shell")))

    (judged,), _ = judge((asset,), {}, catalog_factors={"t": ("executes_shell", "local_inference")})

    assert judged.risk.factors == ("plaintext_transport", "executes_shell", "local_inference")


def test_uncatalogued_assets_get_no_catalog_factors(world, catalog):
    world.file("/home/a/proj/CLAUDE.md", "# x\n")

    (asset,) = discover(world.gate(), catalog).assets

    assert asset.risk.factors == ()
