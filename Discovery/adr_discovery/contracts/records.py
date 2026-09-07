"""The records the stages hand each other.

One type per stage boundary. A stage is a function from its input type to
its output type, so these are the whole of the coupling between modules.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from ..redact import rules as redact
from .evidence import Band, Evidence, Rung


class Kind(str, Enum):
    """Asset kinds. A category with no member here cannot be reported."""

    CLI_AGENT = "cli_agent"
    APP = "app"
    AI_BROWSER = "ai_browser"
    MODEL_RUNTIME = "model_runtime"
    MODEL_WEIGHTS = "model_weights"
    EXTENSION = "extension"
    MCP_SERVER = "mcp_server"
    MCP_BUNDLE = "mcp_bundle"
    SKILL = "skill"
    COMMAND = "command"
    PLUGIN = "plugin"
    OUTPUT_STYLE = "output_style"
    AGENT_DEFINITION = "agent_definition"
    HOOK = "hook"
    INSTRUCTIONS = "instructions"
    CI_AGENT = "ci_agent"
    CLOUD_AGENT = "cloud_agent"
    AGENT_PLATFORM = "agent_platform"


class Liveness(str, Enum):
    RUNNING = "running"
    INSTALLED = "installed"
    DECLARED_ONLY = "declared_only"


class Priority(int, Enum):
    """Known roots order the sweep; they no longer decide what exists."""

    HOME = 0
    CODE_ROOT = 1
    SYSTEM = 2
    BREADTH = 3


@dataclass(frozen=True, slots=True)
class Candidate:
    """M2 output. Deliberately tool-agnostic: nothing here knows what any
    particular tool is, which is why M2 can be tested with an empty catalog."""

    kind: str
    path: str
    source: str
    priority: Priority = Priority.BREADTH
    detail: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Declaration:
    """M3 output. One record from one config surface.

    Redaction is carried by this type rather than applied by whoever
    constructs it. A final pass is something a stage added tomorrow can be
    placed behind; a constructor is not. `__post_init__` scrubs the fields
    that can hold a secret, so a new extractor that never heard of C2 still
    cannot emit one.
    """

    kind: Kind
    name: str
    path: str
    scope: str = "user"
    command: str | None = None
    args: tuple[str, ...] = ()
    env_names: tuple[str, ...] = ()
    url: str | None = None
    raw: dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "args", redact.scrub_argv(self.args))
        if self.url is not None:
            object.__setattr__(self, "url", redact.strip_url(self.url))
        # An env *mapping* must never survive as one: names only.
        env = self.raw.get("env")
        if isinstance(env, dict):
            scrubbed = dict(self.raw)
            scrubbed["env"] = redact.env_names(env)
            object.__setattr__(self, "raw", scrubbed)


@dataclass(frozen=True, slots=True)
class ExtractError:
    """A record that failed to parse. Isolation is per record, so this
    coexists with its valid siblings rather than replacing them."""

    path: str
    index: int | None
    reason: str


@dataclass(frozen=True, slots=True)
class Extraction:
    """Declarations plus the true count -- which is what makes the isolation
    claim measurable. `declared` counts records present in the file, not
    records that survived parsing."""

    declarations: tuple[Declaration, ...] = ()
    errors: tuple[ExtractError, ...] = ()
    declared: int = 0
    truncated: bool = False


@dataclass(frozen=True, slots=True)
class Verdict:
    """M4 output. `rung` says which evidence established identity, so a
    reader can tell a package-owned binary from a filename that looked right."""

    catalog_id: str | None
    kind: Kind | None
    name: str | None = None
    vendor: str | None = None
    version: str | None = None
    rung: Rung | None = None
    evidence: tuple[Evidence, ...] = ()
    signals: tuple[str, ...] = ()
    score: float = 0.0
    conflict: str | None = None

    @property
    def is_concluded(self) -> bool:
        """True only when a conclusive rung produced the identity.

        Convention raises priority and never concludes, so a verdict resting
        on it alone is not an identification however plausible it reads.
        """
        from .evidence import CONCLUSIVE_RUNGS

        return self.kind is not None and self.rung in CONCLUSIVE_RUNGS


@dataclass(frozen=True, slots=True)
class Observation:
    """What M5 merges. One sighting of one thing, by one channel."""

    kind: Kind
    identity: str
    path: str | None = None
    install_root: str | None = None
    owner: str | None = None
    version: str | None = None
    catalog_id: str | None = None
    content_hash: str | None = None
    real_path: str | None = None
    inode: str | None = None
    package_id: str | None = None
    signature_id: str | None = None
    liveness: Liveness = Liveness.INSTALLED
    attribute_of: str | None = None
    evidence: tuple[Evidence, ...] = ()
    detail: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Risk:
    pinned: bool | None = None
    factors: tuple[str, ...] = ()
    credential_kinds: tuple[str, ...] = ()
    env_names: tuple[str, ...] = ()
    transport: str | None = None
    destinations: tuple[str, ...] = ()
    unattended: bool = False


@dataclass(frozen=True, slots=True)
class Asset:
    """M5 output, judged by M6, serialized by M7."""

    asset_id: str
    kind: Kind
    name: str
    identity: str
    catalog_id: str | None = None
    vendor: str | None = None
    version: str | None = None
    install_path: str | None = None
    install_root: str | None = None
    install_method: str | None = None
    owner: str = "system"
    location: str = "local"
    liveness: Liveness = Liveness.INSTALLED
    last_used: str | None = None
    confidence: Band = field(default_factory=lambda: Band("none"))
    verification: tuple[Rung, ...] = ()
    evidence: tuple[Evidence, ...] = ()
    risk: Risk = field(default_factory=Risk)
    sanction: str = "unknown"
    flags: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Finding:
    """M6 output. Precision is asserted here, not just recall -- every
    finding an operator dismisses costs the ones that follow it."""

    rule: str
    severity: str
    asset_id: str
    summary: str
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True, slots=True)
class ReviewItem:
    """Probable AI, unclassified. Triage, never a finding."""

    path: str
    score: float
    signals: tuple[str, ...]
    evidence: tuple[Evidence, ...] = ()
