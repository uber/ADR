"""Probe families: tool-agnostic enumeration in Stage 0, catalog-aware in Stage 1."""

from .agent_artifact import AgentArtifactProbe
from .app import AppProbe
from .cli_agent import CliAgentProbe
from .extension import ExtensionProbe
from .identity import IdentityProbe
from .location import LocationProbe
from .mcp import McpProbe
from .openworld import OpenWorldProbe
from .process import ProcessProbe
from .runtime import RuntimeProbe
from .scheduler import SchedulerProbe

#: Run order. Process observation lands before resolution so runtime evidence
#: can join the assets the static probes found.
ALL_PROBES = (McpProbe, CliAgentProbe, AppProbe, RuntimeProbe, ExtensionProbe,
              AgentArtifactProbe, SchedulerProbe, IdentityProbe, LocationProbe, ProcessProbe)

__all__ = ["ALL_PROBES", "AgentArtifactProbe", "AppProbe", "CliAgentProbe", "ExtensionProbe", "LocationProbe",
           "IdentityProbe", "McpProbe", "OpenWorldProbe", "ProcessProbe", "RuntimeProbe",
           "SchedulerProbe"]
