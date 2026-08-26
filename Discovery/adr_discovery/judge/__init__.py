"""M6 -- turns an inventory into something a policy can act on.

Its currency is operator trust, and it spends that on every finding it
raises. Ambiguity resolves toward the safe verdict: a shape the parser
cannot read confidently produces no finding and a recorded ambiguity,
rather than a guess dressed as a verdict.
"""

from __future__ import annotations

from dataclasses import replace

from ..contracts.records import Asset, Declaration, Finding, Risk
from .findings import findings_for
from .risk import credential_reach, pinning, transport_of, unattended
from .sanction import EMPTY, Policy, state_for

__all__ = ["judge", "Policy", "EMPTY"]


def judge(assets: tuple[Asset, ...], declarations: dict[str, Declaration],
          policy: Policy = EMPTY, ledger=None) -> tuple[tuple[Asset, ...], tuple[Finding, ...]]:
    """Attach risk facts and sanction state, then raise what is worth raising."""
    judged: list[Asset] = []
    findings: list[Finding] = []

    for asset in assets:
        declaration = declarations.get(asset.asset_id)
        risk = _risk_for(asset, declaration, ledger)
        with_risk = replace(asset, risk=risk, sanction=state_for(asset.catalog_id, policy))
        judged.append(with_risk)
        findings.extend(findings_for(with_risk, policy))

    return tuple(judged), tuple(findings)


def _risk_for(asset: Asset, declaration: Declaration | None, ledger) -> Risk:
    if declaration is None:
        # Nothing new to say. Keep whatever earlier stages established
        # rather than overwriting it with an empty verdict.
        return asset.risk

    pinned, factors = pinning(declaration.command, declaration.args)
    # A shape we could not read confidently: record the ambiguity and raise
    # nothing, which is the safe verdict.
    if pinned is None and declaration.command and not declaration.url and ledger is not None:
        ledger.probe("judge", "degraded", f"unreadable launch shape: {declaration.name}")

    env_declared = bool(declaration.env_names) or "env" in declaration.raw
    env_names, kinds = credential_reach(declaration.env_names, env_declared)
    transport, transport_factors = transport_of(declaration.raw, declaration.url)

    destinations = ()
    if declaration.url:
        host = declaration.url.split("//", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        destinations = (host,)

    return Risk(
        pinned=pinned,
        factors=tuple(factors) + transport_factors,
        credential_kinds=kinds,
        env_names=env_names,
        transport=transport,
        destinations=destinations,
        unattended=asset.risk.unattended or unattended(declaration.args),
    )
