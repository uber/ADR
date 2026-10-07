"""Compatibility adapter for artifact API v1 and the Desktop-owned baseline.

Reusable validation/matching lives in adr_protection. Resource selection and
policy authority remain with the host; importing the library never scans or
opens this application's profile.
"""

from pathlib import Path

from adr_protection.api_v1 import (
    BUNDLED_FEED_ID,
    KINDS,
    MAX_DEPTH,
    MAX_FEED_BYTES,
    MAX_GENERATION_BYTES,
    MAX_INDICATORS,
    MAX_VERSIONS,
    CompiledGeneration,
    compile_generation,
    compose_generation,
    generation_summary,
    match_subject,
    normalize_endpoint,
    normalize_package_name,
    normalize_registry,
    parse_feed_json,
    validate_feed,
    validate_generation,
)

__all__ = [
    "BUNDLED_FEED_ID", "KINDS", "MAX_DEPTH", "MAX_FEED_BYTES", "MAX_GENERATION_BYTES",
    "MAX_INDICATORS", "MAX_VERSIONS", "CompiledGeneration", "compile_generation",
    "compose_generation", "generation_summary", "load_bundled_feed", "match_subject",
    "normalize_endpoint", "normalize_package_name", "normalize_registry",
    "parse_feed_json", "validate_feed", "validate_generation",
]


def load_bundled_feed():
    """Load only the application-owned baseline, never a user-specified path."""
    path = Path(__file__).parent / "data" / "malicious_artifacts.json"
    with path.open("rb") as handle:
        return parse_feed_json(handle.read(MAX_FEED_BYTES + 1))
