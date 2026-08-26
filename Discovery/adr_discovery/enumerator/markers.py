"""The marker set, as data.

Traversal is keyed on markers rather than on remembered paths, which is
what lets a repository in /opt/checkouts be found by the same rule that
finds one in ~/Projects.

Nothing here names a tool. A marker says *where an agent works*; deciding
what the agent is belongs to M4, and M2 must stay passable with an empty
catalog (U2-03).
"""

from __future__ import annotations

#: Directory names that mark a surface worth reading.
DIR_MARKERS: frozenset[str] = frozenset(
    {
        ".git", ".claude", ".cursor", ".windsurf", ".aider", ".continue",
        ".codeium", ".gemini", ".goose", ".opencode", ".zed",
        "agents", "skills", "commands", "prompts", "output-styles", "plugins",
        ".github", ".devcontainer", ".vscode",
    }
)

#: File names that mark a surface worth reading.
FILE_MARKERS: frozenset[str] = frozenset(
    {
        ".mcp.json", ".claude.json", "mcp.json", "settings.json", "settings.local.json",
        "config.toml", "config.yaml", "mcp_settings.json", "mcp_config.json",
        "cline_mcp_settings.json", "managed-settings.json", "managed-mcp.json",
        "claude_desktop_config.json", "opencode.json",
    }
)

#: Workflow files are read by suffix rather than by name -- nobody agrees
#: on what a workflow is called, only on where it lives.
WORKFLOW_DIR = "/.github/workflows/"
WORKFLOW_SUFFIXES = (".yml", ".yaml")

#: Instruction filenames are programmable-surface records. Their contents are
#: never collected; only path, scope and host-facing name leave the endpoint.
INSTRUCTION_MARKERS: frozenset[str] = frozenset(
    {
        "CLAUDE.md", "AGENTS.md", "GEMINI.md", "AGENT.md",
        ".cursorrules", ".windsurfrules", "copilot-instructions.md",
    }
)

LOCATOR_ONLY: frozenset[str] = frozenset({".cursorrules", ".windsurfrules"})

#: State directories a host application keeps per user.
STATE_ROOTS: tuple[str, ...] = (
    "~/.claude", "~/.codex", "~/.cursor", "~/.aider", "~/.continue",
    "~/.gemini", "~/.config/goose", "~/.config/opencode", "~/.ollama",
    "~/Library/Application Support/Claude",
    "~/Library/Application Support/Code/User",
    "~/.config/Code/User",
    "~/.vscode/extensions", "~/.vscode-server/extensions",
)

#: Config files loaded directly by known agent hosts. These are enumerated
#: independently of the breadth sweep so a dependency cache cannot hide them.
CONFIG_FILE_TEMPLATES: tuple[str, ...] = (
    "~/.claude.json",
    "~/.config/claude-desktop/claude_desktop_config.json",
    "~/.cursor/mcp.json",
    "~/.codeium/windsurf/mcp_config.json",
    "~/.config/Code/User/mcp.json",
    "~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
    "~/.config/zed/settings.json",
    "~/.config/JetBrains/options/mcp.json",
    "~/.config/opencode/opencode.json",
    "~/.codex/config.toml",
    "~/.config/goose/config.yaml",
    "~/.bashrc",
    "~/.zshrc",
    "/etc/claude-code/managed-settings.json",
    "/etc/adr/managed-mcp.json",
)

#: Browser profile parents. Every profile, not just the default -- a large
#: share of real shadow AI lives on a second profile.
BROWSER_PROFILE_ROOTS: tuple[str, ...] = (
    "~/Library/Application Support/Google/Chrome",
    "~/Library/Application Support/BraveSoftware/Brave-Browser",
    "~/Library/Application Support/Microsoft Edge",
    "~/Library/Application Support/Arc/User Data",
    "~/.config/google-chrome",
    "~/.config/chromium",
    "~/.config/microsoft-edge",
)

FIREFOX_PROFILE_ROOTS: tuple[str, ...] = (
    "~/Library/Application Support/Firefox/Profiles",
    "~/.mozilla/firefox",
)

EDITOR_EXTENSION_ROOTS: tuple[str, ...] = (
    "~/.vscode/extensions", "~/.vscode-server/extensions",
    "~/.cursor/extensions", "~/.windsurf/extensions",
    "~/.trae/extensions", "~/.kilo/extensions",
)

#: Hosts that answer for a model provider. Landscape data, not identity:
#: a connection here says *something on this machine talks to a model*,
#: which is a candidate. What it is remains M4's question.
MODEL_PROVIDER_SUFFIXES: tuple[str, ...] = (
    "api.anthropic.com", "api.openai.com", "openai.azure.com",
    "generativelanguage.googleapis.com", "aiplatform.googleapis.com",
    "bedrock-runtime.amazonaws.com", "api.mistral.ai", "api.cohere.ai",
    "api.groq.com", "api.together.xyz", "api.deepseek.com",
    "api.x.ai", "openrouter.ai", "huggingface.co",
)

#: Bundles and portable executables carry their own runtime, so nothing
#: else on disk reveals them.
BUNDLE_SUFFIXES: tuple[str, ...] = (".AppImage", ".app", ".exe")

#: Ports a local model runtime answers on.
LOCAL_MODEL_PORTS: frozenset[int] = frozenset({11434, 1234, 8080, 8000, 5000, 7860})


def is_model_provider(host: str) -> bool:
    h = host.lower().rstrip(".")
    return any(h == s or h.endswith("." + s) for s in MODEL_PROVIDER_SUFFIXES)


def is_loose_executable(entry, name: str) -> bool:
    """An executable nothing else on disk accounts for.

    Extensionless is the test that keeps this from matching every script in
    every repository: real CLI tools ship as `claude`, not `claude.sh`.
    """
    if entry.is_dir:
        return name.endswith(BUNDLE_SUFFIXES)
    if name.endswith(BUNDLE_SUFFIXES):
        return True
    return entry.is_exec and "." not in name


def marker_kind(name: str, path: str = "") -> str | None:
    if WORKFLOW_DIR in path and path.endswith(WORKFLOW_SUFFIXES):
        return "marker_file"
    if name in DIR_MARKERS:
        return "marker_dir"
    if name in FILE_MARKERS:
        return "marker_file"
    if name in INSTRUCTION_MARKERS:
        return "instruction_file"
    if name in (".bashrc", ".zshrc"):
        return "shell_profile"
    if name == "manifest.json" and "/.mcpb/" in path:
        return "marker_file"
    if name in LOCATOR_ONLY:
        return "locator"
    return None
