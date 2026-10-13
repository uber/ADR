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
    "~/.claude/settings.json",
    "~/.claude/settings.local.json",
    # Claude Desktop: Linux (community builds), macOS, Windows.
    "~/.config/claude-desktop/claude_desktop_config.json",
    "~/Library/Application Support/Claude/claude_desktop_config.json",
    "~/AppData/Roaming/Claude/claude_desktop_config.json",
    "~/.cursor/mcp.json",
    "~/.codeium/windsurf/mcp_config.json",
    # VS Code user MCP config, and the Cline extension's settings beside it.
    "~/.config/Code/User/mcp.json",
    "~/Library/Application Support/Code/User/mcp.json",
    "~/AppData/Roaming/Code/User/mcp.json",
    "~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
    "~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
    "~/AppData/Roaming/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
    # Zed reads ~/.config/zed on Linux and macOS; Windows uses %APPDATA%.
    "~/.config/zed/settings.json",
    "~/AppData/Roaming/Zed/settings.json",
    "~/.config/JetBrains/options/mcp.json",
    "~/.config/opencode/opencode.json",
    "~/.codex/config.toml",
    "~/.config/goose/config.yaml",
    "~/.bashrc",
    "~/.zshrc",
    "/etc/claude-code/managed-settings.json",
    "/Library/Application Support/ClaudeCode/managed-settings.json",
    "/Library/Application Support/ClaudeCode/managed-mcp.json",
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

#: The provider hosts worth resolving to match a connection by address.
#: Each answers from a small fixed set of addresses (one published block, or
#: a CDN anycast pair), so the address a client connected to is the one a
#: later lookup returns. Hosts served from rotating pools or per-region edges
#: (Google APIs, CloudFront) are left out: a lookup there returns a sample,
#: and their addresses are shared with unrelated services. Per-tenant hosts
#: (`<resource>.openai.azure.com`, regional Bedrock) have no single name.
RESOLVABLE_PROVIDER_HOSTS: tuple[str, ...] = (
    "api.anthropic.com", "api.openai.com", "api.mistral.ai",
    "api.groq.com", "api.together.xyz", "api.x.ai", "openrouter.ai",
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
