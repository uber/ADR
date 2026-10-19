"""Consistency checks between tasks.json and mcp_servers_registry.json."""

import json
from pathlib import Path

import pytest

DETECTION_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def tasks():
    with open(DETECTION_ROOT / "tasks.json", encoding="utf-8") as f:
        return json.load(f)["tasks"]


@pytest.fixture(scope="module")
def servers():
    with open(DETECTION_ROOT / "mcp_servers_registry.json", encoding="utf-8") as f:
        return json.load(f)["servers"]


def test_task_servers_exist_in_registry(tasks, servers):
    missing = {
        task["task_id"]: [s for s in task["mcp_servers"] if s not in servers]
        for task in tasks
        if any(s not in servers for s in task["mcp_servers"])
    }
    assert missing == {}


def test_expected_tools_are_exposed_by_task_servers(tasks, servers):
    """Every expected tool must be a capability of one of the task's servers.

    Only registry capabilities are passed to the agent as allowed tools, so an
    expected tool outside that set can never be called and the task's
    tools_called validation can never pass.
    """
    unreachable = {}
    for task in tasks:
        exposed = set()
        for name in task["mcp_servers"]:
            exposed.update(servers.get(name, {}).get("capabilities", []))
        missing = [t for t in task.get("expected_tools", []) if t not in exposed]
        if missing:
            unreachable[task["task_id"]] = missing
    assert unreachable == {}
