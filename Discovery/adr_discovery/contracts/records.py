"""The records the stages hand each other.

One type per stage boundary. A stage is a function from its input type to
its output type, so these are the whole of the coupling between modules.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from ..redact import rules as redact
from .evidence import Band, Evidence, Rung
from .paths import logical


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

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", logical(self.path))


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
        object.__setattr__(self, "path", logical(self.path))
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
    #: The directory an installer manages, when that is what proved identity:
    #: every version in it, and every process running one, is one install.
    install_root: str | None = None

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
    #: Last modification of the observed file, ISO-8601 UTC.
    modified: str | None = None
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
class SourceRef:
    """Where a marketplace or plugin comes from, reduced to what identifies it.

    `kind` is the host's own word (`github`, `git`, `url`, `git-subdir`,
    `directory`, ...). `repo` is `host/owner/repo` for a git remote; `url`
    has no userinfo, query or fragment; `path` is home-relative where it can be.
    """

    kind: str
    repo: str | None = None
    url: str | None = None
    path: str | None = None


@dataclass(frozen=True, slots=True)
class Provenance:
    """Where a plugin, or something shipped inside one, came from.

    `state` is what the host's own registries say about the directory:
    `installed` (an install record names it), `available` (it sits in a
    marketplace clone, offered but not installed from there), `stale` (a
    cached version no install record names) or `unregistered` (a plugin no
    registry mentions). `enabled` is None when no settings file says.
    """

    state: str
    host: str | None = None
    marketplace: str | None = None
    marketplace_source: SourceRef | None = None
    plugin: str | None = None
    plugin_version: str | None = None
    install_scope: str | None = None
    installed_at: str | None = None
    enabled: bool | None = None


@dataclass(frozen=True, slots=True)
class ArchiveRef:
    """A local zip of the asset's files, named and verified by its folder hash."""

    path: str
    sha256: str


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
    #: Hooks only: the lifecycle event and tool matcher. The command stays private.
    hook_event: str | None = None
    hook_matcher: str | None = None
    #: Skills, commands, agent definitions and output styles: the tools the
    #: frontmatter permits and the model it pins. Never the prose.
    allowed_tools: tuple[str, ...] = ()
    model: str | None = None
    #: Skills only: the folder hash of the skill directory (every regular
    #: file, its relative path and execute bit; see `Gate.hash_tree`), the
    #: identity a known-bad/approved artifact list uses. Absent when the
    #: tree was over the caps or not fully readable.
    skill_sha256: str | None = None
    #: sha256 of the identified file, when one was read within the size cap.
    content_hash: str | None = None
    #: "<manager>:<package>" when a package record owns the asset.
    package_id: str | None = None
    #: Latest modification time of any file behind the asset, ISO-8601 UTC.
    #: For a skill, its SKILL.md; for a declaration, the declaring file.
    modified: str | None = None
    #: Versions some process is executing right now. `version` is what the
    #: install runs next; after an update an older or newer release can
    #: still be running, and that is worth seeing.
    running_versions: tuple[str, ...] = ()
    #: Plugins and everything inside one: marketplace, install and state.
    provenance: Provenance | None = None
    #: The plugin asset whose directory holds this one.
    plugin_asset_id: str | None = None
    #: Skills archived with --archive-skills: the zip and its sha256.
    archive: ArchiveRef | None = None


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
