"""Evidence — why we believe a claim.

Every verdict, observation and asset carries these. A claim with an empty
evidence list is a bug, not a low-confidence answer.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Sequence


class Channel(str, Enum):
    """Where a piece of evidence came from.

    Independence matters more than count: a binary and the symlink pointing
    at it are one FILESYSTEM observation of one fact, and M5 must not treat
    them as two agreeing channels.
    """

    FILESYSTEM = "filesystem"
    PACKAGE = "package"
    REGISTRY = "registry"
    SIGNATURE = "signature"
    CONFIG = "config"
    RUNTIME = "runtime"
    NETWORK = "network"
    EXEC_JOURNAL = "exec_journal"
    TELEMETRY = "telemetry"


class Rung(str, Enum):
    """The evidence ladder, cheapest and strongest first (M4).

    A candidate stops climbing as soon as it has proof. CONVENTION raises
    priority and never concludes -- see `Verdict.is_concluded`.
    """

    PROVENANCE = "provenance"
    CONTENT = "content"
    BEHAVIOUR = "behaviour"
    CONVENTION = "convention"


#: The rungs that may, on their own, establish an identity.
CONCLUSIVE_RUNGS = frozenset({Rung.PROVENANCE, Rung.CONTENT, Rung.BEHAVIOUR})


@dataclass(frozen=True, slots=True)
class Evidence:
    stage: str
    channel: Channel
    path: str
    proof: str
    confidence: float = 0.0
    rung: Rung | None = None

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence out of range: {self.confidence}")


@dataclass(frozen=True, slots=True)
class Band:
    """Confidence, reported as a band with the evidence that produced it.

    A band rather than a number because the underlying quantity -- how many
    independent channels agree -- is small and discrete, and a float invites
    a precision the input does not have.
    """

    label: str
    channels: tuple[Channel, ...] = ()

    @staticmethod
    def from_channels(channels: Sequence[Channel]) -> "Band":
        distinct = tuple(sorted({c for c in channels}, key=lambda c: c.value))
        n = len(distinct)
        label = "high" if n >= 3 else "medium" if n == 2 else "low" if n == 1 else "none"
        return Band(label, distinct)
