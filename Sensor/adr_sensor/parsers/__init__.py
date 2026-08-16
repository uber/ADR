"""Log parsers for supported AI coding agents.

Each parser implements :class:`~adr_sensor.parsers.base_parser.BaseParser` and
normalizes one agent's on-disk logs into ``AgentEvent`` objects.
"""

from .base_parser import BaseParser
from .claude_desktop_parser import ClaudeDesktopParser
from .claude_parser import ClaudeParser
from .cline_parser import ClineParser
from .copilot_parser import CopilotParser
from .codex_parser import CodexParser
from .cursor_parser import CursorParser
from .opencode_parser import OpencodeParser
from .warp_parser import WarpParser

__all__ = [
    "BaseParser",
    "ClaudeDesktopParser",
    "ClaudeParser",
    "ClineParser",
    "CopilotParser",
    "CodexParser",
    "CursorParser",
    "OpencodeParser",
    "WarpParser",
]
