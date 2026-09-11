"""The per-record try boundary, written once and applied everywhere.

The whole of M3's change lives here. Under per-*file* isolation one bad
record abandons the file and four valid siblings vanish -- and the reported
count is silently wrong, which is worse than the loss. Under per-*record*
isolation the survivors survive, the bad one becomes an error, and the
count reported is the count that was in the file.
"""

from __future__ import annotations

from typing import Callable, Iterable, Sequence

from ..contracts.records import Declaration, ExtractError, Extraction


def per_record(
    records: Sequence[object],
    parse_one: Callable[[int, object], Declaration],
    path: str,
    cap: int | None = None,
) -> Extraction:
    """Parse each record behind its own boundary.

    `declared` is the number of records *present*, taken before parsing and
    before the cap, so a truncated or partially-failed read still reports
    what was really there.
    """
    declared = len(records)
    window: Iterable[tuple[int, object]] = enumerate(records)
    truncated = False
    if cap is not None and declared > cap:
        window = list(enumerate(records))[:cap]
        truncated = True

    good: list[Declaration] = []
    bad: list[ExtractError] = []
    for index, record in window:
        try:
            good.append(parse_one(index, record))
        except Exception as exc:  # one record, one boundary
            bad.append(ExtractError(path, index, f"{type(exc).__name__}: {exc}"))

    return Extraction(tuple(good), tuple(bad), declared, truncated)


# --------------------------------------------------------------- shape rules
#
# A string where an array belongs is one argument, not one argument per
# character -- and it changes both the identity and the pinning verdict.


def as_args(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        raise TypeError("args must be an array of scalars, not a string")
    if not isinstance(value, (list, tuple)):
        raise TypeError(f"args must be an array, got {type(value).__name__}")
    out: list[str] = []
    for item in value:
        if isinstance(item, (dict, list, tuple)):
            raise TypeError("args must contain scalars only")
        out.append(str(item))
    return tuple(out)


def as_env(value: object) -> dict[str, object]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise TypeError(f"env must be a mapping, got {type(value).__name__}")
    return value


def as_text(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a string, got {type(value).__name__}")
    return value
