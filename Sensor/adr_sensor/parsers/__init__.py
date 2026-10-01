"""Log parsers for supported AI coding agents.

Each parser implements :class:`~adr_sensor.parsers.base_parser.BaseParser` and
normalizes one agent's on-disk logs into ``AgentEvent`` objects.
"""

from .antigravity_parser import AntigravityParser
from .base_parser import BaseParser
from .claude_desktop_parser import ClaudeDesktopParser
from .claude_parser import ClaudeParser
from .cline_parser import ClineParser
from .codex_parser import CodexParser
from .copilot_parser import CopilotParser
from .cursor_parser import CursorParser
from .dsh_parser import DshParser
from .gemini_parser import GeminiParser
from .opencode_parser import OpencodeParser
from .warp_parser import WarpParser

__all__ = [
    "AntigravityParser",
    "BaseParser",
    "ClaudeDesktopParser",
    "ClaudeParser",
    "ClineParser",
    "CodexParser",
    "GeminiParser",
    "CopilotParser",
    "CursorParser",
    "DshParser",
    "OpencodeParser",
    "WarpParser",
]
