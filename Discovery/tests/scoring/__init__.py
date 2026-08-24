"""The scoring engine: a pure function from three JSON files to a verdict.

No VM, no network, no clock. That is what lets a failed run be re-scored
without re-running it, and a scoring bug be fixed and replayed against every
run ever recorded.
"""
