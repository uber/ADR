"""Confidence counts independent channels, never repeated observations.

A binary and the symlink pointing at it are one FILESYSTEM sighting of one
fact. Multiplying their confidences manufactures certainty out of a single
look, which is how an inventory becomes confidently wrong.
"""

from __future__ import annotations

from ..contracts.evidence import Band, Channel, Evidence


def band_for(evidence: tuple[Evidence, ...]) -> Band:
    """Distinct channels only -- repetition inside one channel adds nothing."""
    return Band.from_channels([e.channel for e in evidence])


def independent_channels(evidence: tuple[Evidence, ...]) -> tuple[Channel, ...]:
    return tuple(sorted({e.channel for e in evidence}, key=lambda c: c.value))
