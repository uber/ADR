"""Scoring: a pure function from three JSON files to a verdict.

No VMs, no network, no clock. That is what lets the engine be developed before
any VM exists, replayed against every recorded run after a change, and reasoned
about by somebody who has never provisioned a guest.
"""

from .canary import check_canaries
from .match import load_snapshot, match_all
from .schema import SCORE_VERSION
from .score import score, score_run
from .snapshot import Asset, Snapshot, added_assets

__all__ = ["Asset", "Snapshot", "added_assets", "load_snapshot", "match_all", "score",
           "score_run", "check_canaries", "SCORE_VERSION"]
