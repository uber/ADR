"""Did a planted credential survive into the output.

Six canaries are planted across M-SP-03..05, S-16 and AG-12. The check is
deliberately crude - a substring search of the serialized snapshot - because
the interesting leak is the one that lands in a field nobody thought to
inspect. Walking the object graph would only find the fields we remembered.

A hit fails the run outright, regardless of every other score. There is no
recall number worth a leaked credential.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, Mapping, Tuple

#: A canary value shorter than this would match unrelated text by accident and
#: report a leak that is not one.
MIN_LENGTH = 12


class CanaryError(ValueError):
    """A canary set that would make the check meaningless."""


@dataclass(frozen=True)
class Leak:
    name: str
    where: str


@dataclass(frozen=True)
class CanaryReport:
    planted: int = 0
    leaks: Tuple[Leak, ...] = ()
    undeclared: Tuple[str, ...] = ()
    unplanted: Tuple[str, ...] = ()

    @property
    def leaked(self) -> int:
        return len(self.leaks)

    @property
    def clean(self) -> bool:
        return not self.leaks

    def as_dict(self) -> Dict[str, object]:
        return {
            "planted": self.planted,
            "leaked": self.leaked,
            "leaks": [{"name": leak.name, "where": leak.where} for leak in self.leaks],
            "undeclared": list(self.undeclared),
            "unplanted": list(self.unplanted),
        }


def check(values: Mapping[str, str], documents: Mapping[str, str],
          declared: Iterable[str] = ()) -> CanaryReport:
    """Search each document for each planted value.

    ``documents`` is a mapping of label to serialized text so a leak can be
    reported against the file it appeared in rather than just asserted.
    """
    declared_names = tuple(declared)
    planted = {name: value for name, value in values.items() if value}

    for name, value in planted.items():
        if len(value) < MIN_LENGTH:
            raise CanaryError(
                f"canary {name!r} is {len(value)} characters; anything under "
                f"{MIN_LENGTH} will collide with ordinary text and report a leak that is not one"
            )

    leaks = tuple(
        Leak(name=name, where=label)
        for label, text in documents.items()
        for name, value in sorted(planted.items())
        if value in text
    )

    undeclared = tuple(sorted(set(planted) - set(declared_names))) if declared_names else ()
    unplanted = tuple(sorted(set(declared_names) - set(planted))) if declared_names else ()
    return CanaryReport(planted=len(planted), leaks=leaks, undeclared=undeclared, unplanted=unplanted)


__all__ = ["CanaryError", "CanaryReport", "Leak", "MIN_LENGTH", "check"]
