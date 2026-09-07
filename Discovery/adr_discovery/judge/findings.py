"""The findings worth surfacing.

Findings are the narrow end on purpose. Every one an operator dismisses
costs the ones that follow it, so the gate below is deliberately strict and
the strictness is recovered by correlation elsewhere: a server a config
declares is recognized even when its name says nothing.

Two lessons already paid for, both caught on real machines and neither by
the suite: a loose runtime heuristic put a high-severity finding on
`npx eslint .`, and a command that merely mentioned a path containing "mcp"
became an undeclared server. Hence the first rule below.
"""

from __future__ import annotations

from ..contracts.evidence import Channel, Evidence
from ..contracts.records import Asset, Finding, Kind
from .sanction import Policy, is_third_party


#: A finding may only be raised about an asset whose identity was
#: established by evidence -- never about one inferred from a command line.
#: This is the precision gate, and it is what `npx eslint .` fails.
def _may_be_judged(asset: Asset) -> bool:
    if asset.kind is Kind.MCP_SERVER:
        # Declared in a config, or correlated with one. A bare process whose
        # argv merely resembles a server does not reach this branch.
        return bool(asset.catalog_id) or "declared" in asset.flags or asset.confidence.label != "none"
    return bool(asset.catalog_id)


def findings_for(asset: Asset, policy: Policy) -> tuple[Finding, ...]:
    if not _may_be_judged(asset):
        return ()

    out: list[Finding] = []

    def ev(proof: str) -> tuple[Evidence, ...]:
        return (Evidence("judge", Channel.CONFIG, asset.install_path or "", proof, 0.9),)

    if asset.kind is Kind.MCP_SERVER and asset.risk.pinned is False:
        out.append(
            Finding(
                rule="unpinned_mcp_server",
                severity="medium",
                asset_id=asset.asset_id,
                summary=f"{asset.name} resolves its package at launch time",
                evidence=ev("no version in the resolved operand"),
            )
        )

    if asset.kind is Kind.MCP_SERVER and "undeclared" in asset.flags:
        out.append(
            Finding(
                rule="undeclared_mcp_server",
                severity="high",
                asset_id=asset.asset_id,
                summary=f"{asset.name} is running but no configuration declares it",
                evidence=ev("running server correlated with no declaration"),
            )
        )

    if "plaintext_transport" in asset.risk.factors:
        out.append(
            Finding(
                rule="plaintext_transport",
                severity="medium",
                asset_id=asset.asset_id,
                summary=f"{asset.name} is reached over http://",
                evidence=ev("declared url uses a plaintext scheme"),
            )
        )

    if asset.risk.unattended:
        out.append(
            Finding(
                rule="unattended_execution",
                severity="high",
                asset_id=asset.asset_id,
                summary=f"{asset.name} launches with permission checks bypassed",
                evidence=ev("bypass flag present in the agent's own launch"),
            )
        )

    third_party = [d for d in asset.risk.destinations if is_third_party(d, policy)]
    if third_party and policy.tenant_domains:
        out.append(
            Finding(
                rule="third_party_destination",
                severity="medium",
                asset_id=asset.asset_id,
                summary=f"{asset.name} reaches {', '.join(sorted(third_party))}",
                evidence=ev("destination outside the tenant domain list"),
            )
        )

    return tuple(out)
