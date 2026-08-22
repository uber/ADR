"""VM lifecycle: build a golden image, restore it, and reach inside it.

One interface, three hypervisors. Nothing above :class:`Driver` knows which one
is in play, which is what keeps the Linux phase from hard-coding assumptions
that the macOS and Windows phases later have to unpick.
"""

from .driver import Driver, DryRunDriver, Result

__all__ = ["Driver", "DryRunDriver", "Result"]
