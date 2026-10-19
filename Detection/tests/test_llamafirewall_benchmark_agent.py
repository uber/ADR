"""Tests for the AgentDojo LlamaFirewall baseline agent graph.

The llamafirewall package is replaced with a stub so the graph logic can be
exercised without PromptGuard weights or an AlignmentCheck LLM.
"""

import enum
import importlib.util
import sys
import types
from dataclasses import dataclass
from pathlib import Path

import pytest

pytest.importorskip("langgraph")

from langchain_core.messages import AIMessage, HumanMessage  # noqa: E402
from langchain_core.tools import tool  # noqa: E402

AGENT_FILE = (
    Path(__file__).resolve().parent.parent
    / "benchmark/agentdojo/benchmark_agents/llamafirewall_agent/llamafirewall_agent_creation.py"
)


class Role(enum.Enum):
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


class ScannerType(enum.Enum):
    PROMPT_GUARD = "prompt_guard"
    AGENT_ALIGNMENT = "agent_alignment"


class ScanDecision(enum.Enum):
    ALLOW = "allow"
    BLOCK = "block"
    HUMAN_IN_THE_LOOP_REQUIRED = "human_in_the_loop_required"


@dataclass
class Message:
    role: Role
    content: str


@dataclass
class ScanResult:
    decision: ScanDecision
    reason: str = "ok"
    score: float = 0.0


class StubFirewall:
    traces: list = []

    def __init__(self, scanners):
        pass

    def scan_replay_build_trace(self, message, trace):
        new_trace = trace + [message]
        StubFirewall.traces.append(new_trace)
        return ScanResult(ScanDecision.ALLOW), new_trace


@pytest.fixture
def agent_module(monkeypatch):
    # create_llamafirewall_agent copies OPENAI_API_KEY into TOGETHER_API_KEY.
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    lf = types.ModuleType("llamafirewall")
    lf.LlamaFirewall = StubFirewall
    lf.UserMessage = lambda content: Message(Role.USER, content)
    lf.AssistantMessage = lambda content: Message(Role.ASSISTANT, content)
    lf.Message = Message
    lf.Role = Role
    lf.ScannerType = ScannerType
    lf.ScanDecision = ScanDecision
    core = types.ModuleType("llamafirewall.llamafirewall")
    core.create_scanner = lambda scanner_type: None
    lf.llamafirewall = core
    base_llm = types.ModuleType("llamafirewall.utils.base_llm")
    base_llm.LLMClient = object
    alignment = types.ModuleType("llamafirewall.scanners.experimental.alignmentcheck_scanner")
    alignment.AlignmentCheckScanner = object
    stubs = {
        "llamafirewall": lf,
        "llamafirewall.llamafirewall": core,
        "llamafirewall.utils": types.ModuleType("llamafirewall.utils"),
        "llamafirewall.utils.base_llm": base_llm,
        "llamafirewall.scanners": types.ModuleType("llamafirewall.scanners"),
        "llamafirewall.scanners.experimental": types.ModuleType("llamafirewall.scanners.experimental"),
        "llamafirewall.scanners.experimental.alignmentcheck_scanner": alignment,
    }
    for name, module in stubs.items():
        monkeypatch.setitem(sys.modules, name, module)

    spec = importlib.util.spec_from_file_location("llamafirewall_agent_under_test", AGENT_FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    StubFirewall.traces = []
    return module


@tool
def get_weather(city: str) -> str:
    """Get the weather for a city."""
    return "sunny"


class OneToolCallLLM:
    def __init__(self):
        self.calls = 0

    def bind_tools(self, tools):
        return self

    def invoke(self, messages):
        self.calls += 1
        if self.calls == 1:
            return AIMessage(
                content="",
                tool_calls=[{"name": "get_weather", "args": {"city": "Paris"}, "id": "call_1"}],
            )
        return AIMessage(content="It is sunny.")


def test_user_input_scanned_once_across_tool_steps(agent_module):
    app = agent_module.create_llamafirewall_agent(OneToolCallLLM(), [get_weather])

    out = app.invoke({"messages": [HumanMessage(content="Weather in Paris?")]})

    prompt_guard = [w for w in out["warnings"] if w.scanner == "PromptGuard"]
    assert len(prompt_guard) == 1
    final_trace = StubFirewall.traces[-1]
    assert [m.role for m in final_trace] == [Role.USER, Role.ASSISTANT, Role.TOOL, Role.ASSISTANT]
