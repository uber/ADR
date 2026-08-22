"""What every recipe is, and the three answers it may give."""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

#: The four statuses `manifest.actual.json` records, and what each means to the
#: scorer. Only `installed` is scoreable. The rest leave the denominator - but
#: they leave it *visibly*, because a silently shrinking denominator flatters
#: every recall number computed after it.
STATUSES = ("installed", "unavailable", "failed", "unimplemented")


@dataclass
class Outcome:
    """What actually happened to one entry, as the runner will record it."""

    id: str
    status: str
    catalog_id: Optional[str] = None
    family: str = ""
    version: Optional[str] = None
    path: Optional[str] = None
    method: Optional[str] = None
    reason: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        row = {"id": self.id, "status": self.status, "family": self.family}
        for key in ("catalog_id", "version", "path", "method", "reason"):
            value = getattr(self, key)
            if value is not None:
                row[key] = value
        row.update(self.extra)
        return row


class Recipe:
    """One way something reaches a machine.

    ``execute`` installs, verifies and locates in a single call, because the
    three are inseparable: a recipe that installed without verifying would let
    the runner record a version it never saw, and the scorer would then compare
    the collector's answer against the manifest's intention rather than against
    the disk.
    """

    family = ""

    def execute(self, context: Any, entry: Any) -> Outcome:
        raise NotImplementedError

    # -- helpers shared by the implementations -------------------------

    def _outcome(self, entry: Any, status: str, **fields: Any) -> Outcome:
        return Outcome(id=entry.id, status=status, catalog_id=entry.catalog_id,
                       family=entry.family, **fields)


class Unimplemented(Recipe):
    """A family the manifest declares and the harness cannot yet execute.

    Deliberately not an error. The manifest is complete before the harness is,
    which is the right way round - the inventory is the specification - and an
    entry nobody has automated yet must be visible as exactly that rather than
    as a vendor that stopped shipping or a collector that missed something.
    """

    def __init__(self, family: str, reason: str):
        self.family = family
        self.reason = reason

    def execute(self, context: Any, entry: Any) -> Outcome:
        return self._outcome(entry, "unimplemented",
                             reason="%s recipe not implemented: %s" % (self.family, self.reason))
