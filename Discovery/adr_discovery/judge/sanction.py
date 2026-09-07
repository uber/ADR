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
        if not isinstance(raw, dict):
            raise ValueError("policy root must be an object")

        def string_set(field: str) -> frozenset[str]:
            value = raw.get(field) or ()
            if isinstance(value, str) or not isinstance(value, (list, tuple, set, frozenset)):
                raise ValueError(f"policy {field!r} must be an array of strings")
            if not all(isinstance(item, str) and item for item in value):
                raise ValueError(f"policy {field!r} must contain non-empty strings")
            return frozenset(value)

        return Policy(
            approved=string_set("approved"),
            forbidden=string_set("forbidden"),
            tenant_domains=frozenset(domain.lower().rstrip(".") for domain in string_set("tenant_domains")),
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
