"""The redaction check: did any planted credential survive serialization?

Deliberately the crudest test in the harness. It does not know how redaction is
implemented, does not walk the asset model, and does not care which field a
value came from. It searches the serialized snapshot - every byte the collector
would have written to a file or posted to a server - for each planted string.

A hit fails the run outright, regardless of every other score. A collector that
finds every tool and leaks one token has not had a good run.
"""

import json
from typing import Any, Dict, Iterable, List

from .snapshot import Snapshot


def check_canaries(snapshot: Snapshot, planted: Dict[str, str],
                   also: Iterable[Any] = ()) -> Dict[str, Any]:
    """Search the serialized snapshot for every planted canary value.

    ``also`` takes any extra documents the run publishes - the report, a fleet
    payload - because a value redacted out of the snapshot and copied into the
    scorecard has still left the machine.
    """
    haystacks = [snapshot.serialized()]
    haystacks.extend(json.dumps(document, default=str) for document in also)
    leaked: List[Dict[str, str]] = []
    for name, value in sorted(planted.items()):
        if not value:
            # A canary with no value was never planted, and reporting it clean
            # would be reporting a check that never ran.
            leaked.append({"canary": name, "where": "unplanted",
                           "detail": "no value recorded for this run"})
            continue
        for index, haystack in enumerate(haystacks):
            if value in haystack:
                leaked.append({"canary": name, "where": "snapshot" if index == 0 else "document:%d" % index,
                               "detail": _context(haystack, value)})
    return {"planted": len(planted), "leaked": len(leaked), "clean": not leaked, "hits": leaked}


def _context(haystack: str, value: str) -> str:
    """A window around the hit, with the canary itself masked.

    The point of the detail line is to say *where* a value surfaced. Printing
    the value again into a report that then gets shared would repeat exactly the
    mistake being reported.
    """
    start = max(0, haystack.find(value) - 60)
    end = min(len(haystack), haystack.find(value) + len(value) + 60)
    window = haystack[start:end]
    return window.replace(value, "<CANARY>")
