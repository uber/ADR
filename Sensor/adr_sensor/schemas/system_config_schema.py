"""
System Configuration Schema.
Defines data structures for system configuration and version information
collected by the system config parser.
"""

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from .. import host_identity


@dataclass(frozen=True)
class SystemInfo:
    """Basic system information."""

    platform: str
    system: str
    release: str
    version: str
    machine: str
    processor: str
    python_version: str
    python_implementation: str


@dataclass(frozen=True)
class MCPConfig:
    """MCP configuration file information."""

    path: str
    size: int
    modified: str
    content: Dict[str, Any]
    content_type: str
    error: Optional[str] = None
    readable: Optional[bool] = None


@dataclass(frozen=True)
class MCPConfigs:
    """MCP configuration discovery results."""

    found_configs: List[MCPConfig] = field(default_factory=list)
    config_locations_checked: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class PipInfo:
    """PIP package manager information."""

    pip_version: Optional[str] = None
    pip3_version: Optional[str] = None
    installed_packages: List[Dict[str, Any]] = field(default_factory=list)
    pip3_installed_packages: List[Dict[str, Any]] = field(default_factory=list)
    pip_executable: Optional[str] = None
    pip3_executable: Optional[str] = None
    error: Optional[str] = None
    pip_packages_error: Optional[str] = None
    pip3_packages_error: Optional[str] = None


@dataclass(frozen=True)
class NpmInfo:
    """NPM package manager information."""

    npm_version: Optional[str] = None
    node_version: Optional[str] = None
    installed_packages: Dict[str, Any] = field(default_factory=dict)
    global_packages: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    local_packages_error: Optional[str] = None
    global_packages_error: Optional[str] = None


@dataclass(frozen=True)
class HomebrewInfo:
    """Homebrew package manager information."""

    installed_packages: List[Dict[str, str]] = field(default_factory=list)
    error: Optional[str] = None
    cellar_path: Optional[str] = None


@dataclass(frozen=True)
class PackageManagers:
    """All package manager information."""

    pip: PipInfo
    npm: NpmInfo
    homebrew: HomebrewInfo


@dataclass(frozen=True)
class DockerInfo:
    """Docker version information."""

    docker_version: Optional[str] = None
    docker_compose_version: Optional[str] = None
    error: Optional[str] = None


@dataclass(frozen=True)
class PythonEnvironment:
    """Individual Python environment information."""

    path: str
    version: str
    packages: List[Dict[str, Any]] = field(default_factory=list)
    pip_error: Optional[str] = None


@dataclass(frozen=True)
class PythonEnvironments:
    """All Python environments information."""

    discovered_pythons: List[PythonEnvironment] = field(default_factory=list)
    total_environments: int = 0


@dataclass(frozen=True)
class CursorRuleFile:
    """Cursor rule file information."""

    name: str
    modified: str
    content: Optional[str] = None
    line_count: Optional[int] = None
    error: Optional[str] = None


@dataclass(frozen=True)
class CursorRulesInWorkspace:
    """Cursor rules found in a workspace."""

    workspace: str
    rules_directory: str
    rule_files: List[CursorRuleFile] = field(default_factory=list)


@dataclass(frozen=True)
class NpmProject:
    """NPM project information in a workspace."""

    workspace: str
    package_json: str
    has_node_modules: bool
    name: Optional[str] = None
    installed_packages: Dict[str, str] = field(default_factory=dict)
    declared_dependencies: Dict[str, Any] = field(default_factory=dict)
    npm_ls_error: Optional[str] = None
    error: Optional[str] = None


@dataclass(frozen=True)
class DetectedWorkspace:
    """Detected workspace information."""

    path: str
    name: str
    last_accessed: str
    uri: str


@dataclass(frozen=True)
class OpenCursorWorkspaces:
    """Open Cursor/VSCode workspaces information."""

    detected_workspaces: List[DetectedWorkspace] = field(default_factory=list)
    cursor_rules_in_workspaces: List[CursorRulesInWorkspace] = field(default_factory=list)
    npm_projects: List[NpmProject] = field(default_factory=list)
    detection_method: str = "workspace_storage"
    workspace_storage_path: Optional[str] = None
    error: Optional[str] = None


@dataclass(frozen=True)
class ClaudeSkill:
    """Individual Claude Code skill information."""

    name: str
    skill_path: str
    modified: str
    content: Optional[str] = None
    line_count: Optional[int] = None
    description: Optional[str] = None
    version: Optional[str] = None
    is_truncated: bool = False
    error: Optional[str] = None


@dataclass(frozen=True)
class ClaudeCommand:
    """Claude Code command."""

    name: str
    command_path: str
    modified: str
    content: Optional[str] = None
    line_count: Optional[int] = None
    description: Optional[str] = None
    is_truncated: bool = False
    error: Optional[str] = None


@dataclass(frozen=True)
class ClaudeAgent:
    """Claude Code agent definition."""

    name: str
    agent_path: str
    modified: str
    content: Optional[str] = None
    line_count: Optional[int] = None
    description: Optional[str] = None
    is_truncated: bool = False
    error: Optional[str] = None


@dataclass(frozen=True)
class ClaudeHook:
    """Claude Code hook script."""

    name: str
    hook_path: str
    modified: str
    content: Optional[str] = None
    line_count: Optional[int] = None
    hook_type: Optional[str] = None
    is_truncated: bool = False
    error: Optional[str] = None


@dataclass(frozen=True)
class ClaudePlugin:
    """Claude Code plugin information."""

    name: str
    plugin_path: str
    description: Optional[str] = None
    author: Optional[str] = None
    skills: List[ClaudeSkill] = field(default_factory=list)
    commands: List[ClaudeCommand] = field(default_factory=list)
    agents: List[ClaudeAgent] = field(default_factory=list)
    hooks: List[ClaudeHook] = field(default_factory=list)
    error: Optional[str] = None


@dataclass(frozen=True)
class ClaudeSkills:
    """Claude Code skills discovery results."""

    plugins: List[ClaudePlugin] = field(default_factory=list)
    personal_skills: List[ClaudeSkill] = field(default_factory=list)
    legacy_commands: List[ClaudeCommand] = field(default_factory=list)
    total_skills: int = 0
    total_plugins: int = 0
    total_personal_skills: int = 0
    total_legacy_commands: int = 0
    plugins_path: Optional[str] = None
    personal_skills_path: Optional[str] = None
    commands_path: Optional[str] = None
    error: Optional[str] = None


@dataclass(frozen=True)
class SystemConfiguration:
    """Complete system configuration information."""

    timestamp: datetime
    system_info: SystemInfo
    mcp_configs: MCPConfigs
    package_managers: PackageManagers
    docker: DockerInfo
    python_environments: PythonEnvironments
    open_cursor_workspaces: OpenCursorWorkspaces
    claude_skills: ClaudeSkills = field(default_factory=ClaudeSkills)

    # Metadata
    hostname: Optional[str] = None
    username: Optional[str] = None

    # Operating system of the capturing host (platform.system() name), populated automatically
    host_os: Optional[str] = None

    # UUID for this configuration
    uuid: str = field(init=False)

    def __post_init__(self):
        """Generate UUID after initialization and populate hostname/username/host_os."""
        if self.username is None:
            object.__setattr__(self, "username", host_identity.username())
        if self.hostname is None:
            object.__setattr__(self, "hostname", host_identity.hostname())
        if self.host_os is None:
            object.__setattr__(self, "host_os", host_identity.host_os())

        device_name = self.hostname or self.system_info.machine
        timestamp_str = self.timestamp.isoformat()

        payload_parts = [
            device_name,
            self.username or "unknown_user",
            timestamp_str,
            "system_configuration",
            self.system_info.platform,
            self.system_info.python_version,
            str(len(self.mcp_configs.found_configs)),
            str(self.python_environments.total_environments),
            str(len(self.open_cursor_workspaces.detected_workspaces)),
            str(self.claude_skills.total_skills),
        ]
        event_payload = "|".join(payload_parts)
        uuid_hash = hashlib.sha256(event_payload.encode()).hexdigest()
        object.__setattr__(self, "uuid", uuid_hash)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        return data

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)
