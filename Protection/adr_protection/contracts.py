"""Typed JSON shapes for artifact contract v1.

Types describe records; api_v1's validators enforce the closed schemas and
cross-field constraints. Callers must validate untrusted input before use.
"""

from typing import Literal, NotRequired, TypedDict

CONTRACT_VERSION = 1
ArtifactKind = Literal["file_sha256", "skill_sha256", "package", "mcp_endpoint"]
Ecosystem = Literal["npm", "pypi"]


class DigestTargetV1(TypedDict):
    sha256: str


class EndpointTargetV1(TypedDict):
    url: str


class PackageTargetV1(TypedDict):
    ecosystem: Ecosystem
    registry: str
    name: str
    versions: NotRequired[list[str]]
    all_versions: NotRequired[Literal[True]]


class IndicatorV1(TypedDict):
    id: str
    status: Literal["active", "revoked"]
    kind: ArtifactKind
    summary: str
    references: list[str]
    target: DigestTargetV1 | EndpointTargetV1 | PackageTargetV1
    revoked_reason: NotRequired[str]


class FeedV1(TypedDict):
    schema_version: Literal[1]
    feed_id: str
    revision: int
    published_at: str
    indicators: list[IndicatorV1]


class GenerationV1(TypedDict):
    schema_version: Literal[1]
    feeds: list[FeedV1]
    digest: str


class ArtifactMatchV1(TypedDict):
    indicator_id: str
    source_id: str
    feed_id: str
    kind: ArtifactKind
    summary: str
    references: list[str]
    target_display: str
    generation_digest: str


class FeedSummaryV1(TypedDict):
    feed_id: str
    revision: int
    published_at: str
    active: int
    revoked: int


class GenerationSummaryV1(TypedDict):
    file_sha256: int
    skill_sha256: int
    npm: int
    pypi: int
    mcp_endpoint: int
    package_versions: int
    total: int
    revoked: int
    digest: str
    feeds: list[FeedSummaryV1]
