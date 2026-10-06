"""Inert subprocess fixture: speaks CLI protocols, never calls a model or tool."""

import json
import os
import sys
import time


def emit(value):
    print(json.dumps(value), flush=True)


provider, scenario, *arguments = sys.argv[1:]
if scenario == "announce_hang":
    emit({"pid": os.getpid()})
    time.sleep(30)
    raise SystemExit(0)
if scenario == "hang":
    time.sleep(30)
    raise SystemExit(0)
if scenario == "oversize":
    print("x" * (1024 * 1024 + 2), flush=True)
    raise SystemExit(0)
report = {"summary": "Synthetic review completed.", "findings": []}
if provider == "claude":
    if arguments[:2] == ["auth", "status"]:
        # Actual `claude auth status --json` is a pretty-printed JSON document,
        # unlike the JSONL inference stream.
        print(
            json.dumps(
                {
                    "loggedIn": True,
                    "authMethod": "apiKey" if scenario == "paid" else "claude.ai",
                    "apiProvider": "firstParty",
                    "email": "synthetic@example.invalid",
                },
                indent=2,
            ),
            flush=True,
        )
        raise SystemExit(0)
    assert "-p" in arguments and "--safe-mode" in arguments
    assert arguments[arguments.index("--tools") + 1] == ""
    assert "--strict-mcp-config" in arguments and "--no-session-persistence" in arguments
    assert "--max-budget-usd" in arguments
    prompt = sys.stdin.read()
    assert "UNTRUSTED EVIDENCE" in prompt
    emit({"type": "system", "subtype": "init", "tools": [], "session_id": "synthetic-review"})
    if scenario == "slow":
        time.sleep(30)
    if scenario == "finding":
        evidence = json.loads(prompt.split("UNTRUSTED EVIDENCE (JSON):\n", 1)[1])["messages"][0]
        report = {
            "summary": "Synthetic UI fixture: one finding for navigation testing.",
            "findings": [
                {
                    "title": "Synthetic finding",
                    "category": "unauthorized_action",
                    "severity": "medium",
                    "confidence": "low",
                    "message_index": evidence["message_index"],
                    "evidence": evidence["content"][:100],
                    "explanation": "Inert test result, not a real detection.",
                    "suggestion": "Open the cited session to inspect this synthetic evidence.",
                }
            ],
        }
    emit(
        {
            "type": "assistant",
            "message": {
                "id": "one",
                "content": [],
                "usage": {
                    "input_tokens": 100,
                    "output_tokens": 20,
                    "cache_read_input_tokens": 30,
                    "cache_creation_input_tokens": 10,
                },
            },
        }
    )
    if scenario == "tool":
        emit({"type": "assistant", "message": {"content": [{"type": "tool_use", "name": "Bash"}]}})
        time.sleep(30)
    elif scenario == "failed":
        emit(
            {
                "type": "result",
                "subtype": "error_during_execution",
                "is_error": True,
                "usage": {"input_tokens": 100},
                "total_cost_usd": 0.01,
            }
        )
    else:
        emit(
            {
                "type": "result",
                "subtype": "success",
                "is_error": False,
                "usage": {
                    "input_tokens": 100,
                    "output_tokens": 20,
                    "cache_read_input_tokens": 30,
                    "cache_creation_input_tokens": 10,
                },
                "total_cost_usd": 0.01,
                "structured_output": report,
            }
        )
else:
    for line in sys.stdin:
        request = json.loads(line)
        method = request.get("method")
        params = request.get("params", {})
        result = {}
        if method == "account/read":
            result = {"account": {"type": "chatgpt", "email": "synthetic@example.invalid"}}
        elif method == "account/rateLimits/read":
            result = {
                "rateLimitsByLimitId": {
                    "codex": {
                        "primary": {
                            "usedPercent": 10,
                            "windowDurationMins": 300,
                            "resetsAt": time.time() + 3600,
                        },
                        "secondary": {
                            "usedPercent": 20,
                            "windowDurationMins": 10080,
                            "resetsAt": time.time() + 86400,
                        },
                    },
                }
            }
        elif method == "config/read":
            result = {"config": {"model_provider": "openai", "mcp_servers": {"synthetic": {}}}}
        elif method == "mcpServerStatus/list":
            result = {"data": [{"name": "unexpected"}] if scenario == "mcp" else [], "nextCursor": None}
        elif method == "thread/start":
            assert params["ephemeral"] is True and params["sandbox"] == "read-only"
            assert params["config"]["features.shell_tool"] is False
            assert params["config"]["features.plugins"] is False
            assert params["config"]["mcp_servers.synthetic.enabled"] is False
            result = {"thread": {"id": "synthetic-codex-review"}}
        elif method == "turn/start":
            assert params["outputSchema"]["type"] == "object"
            assert params["sandboxPolicy"] == {"type": "readOnly", "networkAccess": False}
            emit({"id": request["id"], "result": {"turn": {"id": "turn", "status": "inProgress"}}})
            emit({"method": "item/started", "params": {"item": {"type": "userMessage"}}})
            emit(
                {
                    "method": "thread/tokenUsage/updated",
                    "params": {
                        "tokenUsage": {
                            "total": {"inputTokens": 100, "cachedInputTokens": 30, "outputTokens": 20}
                        },
                    },
                }
            )
            if scenario == "tool":
                emit({"method": "item/started", "params": {"item": {"type": "commandExecution"}}})
                time.sleep(30)
            elif scenario == "approval":
                emit({"id": 77, "method": "item/commandExecution/requestApproval", "params": {}})
                time.sleep(30)
            else:
                emit(
                    {
                        "method": "item/completed",
                        "params": {
                            "item": {
                                "type": "agentMessage",
                                "text": json.dumps(report),
                            }
                        },
                    }
                )
                emit({"method": "turn/completed", "params": {"turn": {"status": "completed"}}})
            continue
        if "id" in request:
            emit({"id": request["id"], "result": result})
