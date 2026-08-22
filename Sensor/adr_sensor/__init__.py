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

# Imported lazily. Plane A (discovery) depends on nothing outside the
# standard library, and an eager import here drags in `tabulate` via
# .observer, which makes the collector un-deployable on an endpoint that
# cannot reach PyPI. Attribute access below keeps `from adr_sensor import
# AgentObserver` working unchanged.
_LAZY = {
    "AgentObserver": ".observer",
    "AgentEvent": ".schemas.agent_event_schema",
    "ChatMessage": ".schemas.agent_event_schema",
    "ToolUsage": ".schemas.agent_event_schema",
    "SystemConfiguration": ".schemas.system_config_schema",
}


def __getattr__(name):
    module = _LAZY.get(name)
    if module is None:
        raise AttributeError("module %r has no attribute %r" % (__name__, name))
    from importlib import import_module
    return getattr(import_module(module, __name__), name)


def __dir__():
    return sorted(list(globals()) + list(_LAZY))

__all__ = [
    "AgentObserver",
    "AgentEvent",
    "ChatMessage",
    "ToolUsage",
    "SystemConfiguration",
]
