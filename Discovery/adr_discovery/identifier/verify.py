"""Verified behaviour, not credulous behaviour.

The collector this replaces ran `--version` and recorded whatever came
back. That is how a copy of GNU `sleep` named `gemini` acquired version
9.4. Each catalog entry therefore carries the *shape* its version output
takes, and output that does not match produces no version and no
catalogued verdict.
"""

from __future__ import annotations

import re

MAX_OUTPUT = 4096

#: A version we will actually record, once the shape has matched.
_VERSION = re.compile(r"(\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.\-]+)?)")


def check_version(gate, binary: str, probe: tuple[str, ...], shape: str | None) -> tuple[str | None, str]:
    """Run the probe and judge its output against the expected shape.

    Returns (version, proof). A `None` version is a refusal to believe the
    output, and the proof says why -- which is what sends the candidate to
    open-world scoring instead of into the inventory.
    """
    if not probe:
        return None, "no version probe declared"
    if not shape:
        # Enforced at catalog load; belt and braces, because an unverified
        # probe is worse than no probe.
        return None, "no version shape declared"

    ran = gate.run((binary,) + tuple(probe))
    if not ran.ok:
        return None, f"probe refused: {ran.reason}"
    output = ran.value.stdout.strip()[:MAX_OUTPUT]
    if not output:
        return None, "probe produced no output"

    first = output.splitlines()[0].strip()
    if not re.search(shape, first):
        return None, f"output {first!r} does not match the declared shape"

    match = _VERSION.search(first)
    return (match.group(1) if match else first), f"probe output matched {shape!r}"
