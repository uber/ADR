import json
import subprocess
import sys

import pytest

from adr_desktop.mcp_server import TOOLS, validate_arguments


def test_mcp_lists_only_scoped_tools(runtime):
    grant = runtime.create_grant("MCP test", "/workspace", [])
    access = runtime.state_dir / "agents" / f"{grant['id']}.json"
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    ]
    result = subprocess.run(
        [sys.executable, "-m", "adr_desktop", "mcp", "--access-file", str(access)],
        input="".join(json.dumps(message) + "\n" for message in messages),
        text=True,
        capture_output=True,
        timeout=10,
    )
    replies = [json.loads(line) for line in result.stdout.splitlines()]
    assert result.returncode == 0
    assert len(replies) == 2
    assert replies[0]["result"]["protocolVersion"] == "2025-06-18"
    names = {tool["name"] for tool in replies[1]["result"]["tools"]}
    assert names == {
        "adr_status",
        "adr_list_sessions",
        "adr_search_history",
        "adr_get_session",
        "adr_list_credentials",
        "adr_request_service",
        "adr_service_result",
    }
    assert not any("approve" in name or "secret" in name or "policy" in name for name in names)


@pytest.mark.parametrize(
    "arguments", [{"limit": True}, {"limit": 999999}, {"offset": -1}, {"project": "/other"}]
)
def test_tool_arguments_cannot_expand_access(arguments):
    tool = next(tool for tool in TOOLS if tool["name"] == "adr_list_sessions")
    with pytest.raises(ValueError):
        validate_arguments(tool, arguments)
