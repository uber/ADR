"""Compatibility refusal for the removed executable-probe API."""

from __future__ import annotations


def check_version(gate, binary: str, probe: tuple[str, ...], shape: str | None) -> tuple[str | None, str]:
    """Refuse executable probes; discovered artifacts are untrusted input."""
    del gate, binary, probe, shape
    return None, "executable probes are disabled"
