"""
ADR Sensor - Agentic Detection & Response

Security observability library for AI coding agents. Collects telemetry from
Claude Code, Cursor, Cline, OpenAI Codex CLI, Warp Terminal, opencode, and
Claude Desktop Agent Mode (including Dispatch sessions) to enable threat
detection and security monitoring.

Usage:
    from adr_sensor import AgentObserver

    observer = AgentObserver()
    events, configs = observer.ingest_all()
    observer.display_summary(events, configs)
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("adr-sensor")
except PackageNotFoundError:
    __version__ = "0+unknown"

from .observer import AgentObserver
from .schemas.agent_event_schema import AgentEvent, ChatMessage, ToolUsage
from .schemas.system_config_schema import SystemConfiguration

__all__ = [
    "AgentObserver",
    "AgentEvent",
    "ChatMessage",
    "ToolUsage",
    "SystemConfiguration",
]
