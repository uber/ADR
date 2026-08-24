"""Sanction state, from tenant policy.

Tenant-specific values come from configuration, never from code. The test
for this is to run one world against two policies and require two verdicts
-- a value reachable from code alone cannot pass it.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Policy:
    approved: frozenset[str] = frozenset()
    forbidden: frozenset[str] = frozenset()
    #: Domains the tenant owns. A destination outside this set is third
    #: party; there is no default, because a default would be somebody's
    #: wrong answer shipped as a constant.
    tenant_domains: frozenset[str] = frozenset()

    @staticmethod
    def from_dict(raw: dict) -> "Policy":
        return Policy(
            approved=frozenset(raw.get("approved") or ()),
            forbidden=frozenset(raw.get("forbidden") or ()),
            tenant_domains=frozenset(raw.get("tenant_domains") or ()),
        )


EMPTY = Policy()


def state_for(catalog_id: str | None, policy: Policy) -> str:
    if catalog_id is None:
        return "unknown"
    if catalog_id in policy.forbidden:
        return "forbidden"
    if catalog_id in policy.approved:
        return "approved"
    return "unsanctioned" if policy.approved else "unknown"


def is_third_party(host: str, policy: Policy) -> bool:
    h = host.lower().rstrip(".")
    return not any(h == d or h.endswith("." + d) for d in policy.tenant_domains)
