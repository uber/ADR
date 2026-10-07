"""Stable artifact-intelligence API v1. No host, filesystem, or service access.

Obtain CompiledGeneration from compile_generation(); its private indexes and
constructor layout are implementation details, not part of the v1 contract.
"""

from .artifacts import (
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
from .contracts import (
    CONTRACT_VERSION,
    ArtifactMatchV1,
    FeedV1,
    GenerationSummaryV1,
    GenerationV1,
)

__all__ = [
    "CONTRACT_VERSION", "BUNDLED_FEED_ID", "KINDS", "MAX_DEPTH", "MAX_FEED_BYTES",
    "MAX_GENERATION_BYTES", "MAX_INDICATORS", "MAX_VERSIONS",
    "ArtifactMatchV1", "FeedV1", "GenerationV1", "GenerationSummaryV1", "CompiledGeneration",
    "parse_feed_json", "validate_feed", "compose_generation", "validate_generation",
    "compile_generation", "match_subject", "generation_summary",
    "normalize_endpoint", "normalize_package_name", "normalize_registry",
]
