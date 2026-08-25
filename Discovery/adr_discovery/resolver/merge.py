"""Group formation, and the refusal to bridge two identities.

Checking conflict pairwise is not enough. A bridging observation shares a
key with each of two unrelated tools, passes both pairwise checks, and
transitivity then unites them -- one tool silently disappears, and the
count, which is the product, is wrong in the direction nobody notices.

So conflict is evaluated on the *group*: a merge is applied only if the
union's identity set stays singular.
"""

from __future__ import annotations

from ..contracts.records import Observation
from .keys import identity_of, keys_for


class _Groups:
    """Union-find, with the union guarded by the group identity rule."""

    def __init__(self, n: int) -> None:
        self.parent = list(range(n))
        self.identities: list[set[str]] = [set() for _ in range(n)]

    def find(self, i: int) -> int:
        while self.parent[i] != i:
            self.parent[i] = self.parent[self.parent[i]]
            i = self.parent[i]
        return i

    def union(self, a: int, b: int) -> bool:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return True
        merged = self.identities[ra] | self.identities[rb]
        if len(merged) > 1:
            return False  # would make the group's identity plural
        self.parent[rb] = ra
        self.identities[ra] = merged
        return True


def group(observations: tuple[Observation, ...]) -> tuple[tuple[int, ...], ...]:
    """Return index groups. Order within a group follows input order."""
    groups = _Groups(len(observations))
    for i, obs in enumerate(observations):
        ident = identity_of(obs)
        if ident:
            groups.identities[i].add(ident)

    # Strongest key kind first, so a strong merge is applied before a weak
    # one can be refused for a conflict the strong merge would have settled.
    by_kind: dict[str, dict[str, list[int]]] = {}
    for i, obs in enumerate(observations):
        for kind, value in keys_for(obs):
            by_kind.setdefault(kind, {}).setdefault(value, []).append(i)

    refused = 0
    for kind in ("content", "realpath", "inode", "package", "signature",
                 "install", "catalog", "identity"):
        for members in by_kind.get(kind, {}).values():
            anchor = members[0]
            for other in members[1:]:
                if not groups.union(anchor, other):
                    refused += 1

    buckets: dict[int, list[int]] = {}
    for i in range(len(observations)):
        buckets.setdefault(groups.find(i), []).append(i)
    return tuple(tuple(v) for v in buckets.values()), refused


def group_only(observations: tuple[Observation, ...]) -> tuple[tuple[int, ...], ...]:
    grouped, _ = group(observations)
    return grouped
