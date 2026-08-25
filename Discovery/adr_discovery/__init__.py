"""ADR Discovery -- the endpoint collector.

Find the AI binaries, agents, MCP servers and skills present on an employee
endpoint, accurately enough that a security team can act on the answer and
honestly enough that they can tell when it is incomplete.
"""

from __future__ import annotations

from .contracts.snapshot import SCHEMA_VERSION, Coverage, Snapshot
from .pipeline import discover
from .reporter import diff, to_dict, to_json

__version__ = "0.2.0"
__all__ = ["discover", "diff", "to_dict", "to_json", "Snapshot", "Coverage", "SCHEMA_VERSION"]
