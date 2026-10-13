"""M4 -- decides what a candidate actually is.

No verdict rests on a filename alone. Every verdict carries the proof that
produced it, so a reviewer can check it and M5 can weigh it.
"""

from __future__ import annotations

from .ladder import content_hash, identify
from .openworld import THRESHOLD, is_reviewable, score, signals_for

__all__ = ["identify", "content_hash", "score", "signals_for", "is_reviewable", "THRESHOLD"]
