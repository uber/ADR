"""The open-world half.

Everything the catalog rejects is scored on properties rather than
identity. Above threshold it becomes a review-queue item -- triage, never a
finding -- and a repeated one is what grows the catalog without shipping a
collector.
"""

from __future__ import annotations

from types import MappingProxyType

from ..contracts.records import Candidate

#: Signal -> weight. Properties, not names: nothing here asks what a thing
#: is called, which is the whole point of scoring the uncatalogued.
WEIGHTS = MappingProxyType({
    "network_intent": 0.35,      # talks to a model provider
    "credential_affinity": 0.25,  # holds provider credentials
    "mcp_participation": 0.20,    # speaks MCP, or is declared as a server
    "state_shape": 0.15,          # keeps conversation-shaped state
    "runtime_shape": 0.05,        # answers a model-serving protocol
})

THRESHOLD = 0.40


def score(candidate: Candidate, signals: set[str]) -> tuple[float, tuple[str, ...]]:
    fired = tuple(sorted(s for s in signals if s in WEIGHTS))
    return round(sum(WEIGHTS[s] for s in fired), 3), fired


def signals_for(candidate: Candidate, credential_kinds: tuple[str, ...] = ()) -> set[str]:
    found: set[str] = set()
    detail = candidate.detail

    if candidate.kind in ("network_peer", "dns_peer") and detail.get("provider"):
        found.add("network_intent")
    if candidate.kind == "model_port":
        found.add("runtime_shape")
    if credential_kinds:
        found.add("credential_affinity")
    if candidate.kind in ("marker_file", "state_dir") and "mcp" in candidate.path.lower():
        found.add("mcp_participation")
    if candidate.kind == "state_dir":
        found.add("state_shape")

    env_names = detail.get("env_names") or ()
    if any("API_KEY" in str(n).upper() or "TOKEN" in str(n).upper() for n in env_names):
        found.add("credential_affinity")
    return found


def is_reviewable(value: float) -> bool:
    return value >= THRESHOLD
