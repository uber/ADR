"""Scoring: a pure function from three JSON files to a verdict.

No VMs, no network, no clock. That is what lets the engine be developed before
any VM exists, replayed against every recorded run after a change, and reasoned
about by somebody who has never provisioned a guest.
"""

from .snapshot import Asset, Snapshot, added_assets, duplicate_ids

__all__ = ["Asset", "Snapshot", "added_assets", "duplicate_ids"]
