"""Check the actual bundled core, resources, scoped MCP, and standalone guardian."""

import argparse
import http.client
import json
import shlex
import subprocess
import tempfile
import time
from pathlib import Path

import httpx

from adr_desktop.config import atomic_json, prepare_state_dir, read_private_json
from adr_desktop.store import Store

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path, default=ROOT / "dist" / "ADR.app")
    args = parser.parse_args()
    core = args.app.resolve() / "Contents" / "Resources" / "core" / "ADRCore"
    guard = core.parent / "_internal" / "adr_desktop" / "bin" / "adr-hook"
    with tempfile.TemporaryDirectory(prefix="adr-package-smoke-") as folder:
        state = prepare_state_dir(Path(folder) / "state")
        project = str(Path(folder) / "synthetic-project")
        store = Store(state)
        store.ingest(
            {
                "source": "claude",
                "session_id": "packaged-smoke",
                "username": "synthetic",
                "timestamp": "2026-09-30T12:00:00Z",
                "project_path": project,
                "chat_history": [{"role": "user", "content": "Synthetic packaging check", "tools": []}],
            }
        )
        store.close()
        child = subprocess.Popen(
            [str(core), "serve", "--state-dir", str(state)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            for _ in range(200):
                if (state / "runtime.json").exists():
                    break
                if child.poll() is not None:
                    raise RuntimeError("Packaged core failed: " + child.stderr.read())
                time.sleep(0.05)
            runtime = read_private_json(state / "runtime.json")
            owner = read_private_json(state / "owner-access.json")["token"]

            def call(method, path, body=None, authenticated=True):
                connection = http.client.HTTPConnection("127.0.0.1", runtime["port"], timeout=5)
                headers = {"Content-Type": "application/json"}
                if authenticated:
                    headers["Authorization"] = "Bearer " + owner
                connection.request(method, path, json.dumps(body) if body is not None else None, headers)
                response = connection.getresponse()
                content = response.read()
                connection.close()
                return response.status, content

            for _ in range(100):
                try:
                    status, _ = call("GET", "/api/health", authenticated=False)
                    if status == 200:
                        break
                except OSError:
                    pass
                time.sleep(0.05)
            assert call("GET", "/", authenticated=False)[0] == 200
            assert b"Agent Security and Observability" in call("GET", "/", authenticated=False)[1]
            assert call("GET", "/assets/app.js", authenticated=False)[0] == 200
            assert b"Security reviews" in call("GET", "/assets/app.js", authenticated=False)[1]
            assert b"Malicious artifacts" in call("GET", "/assets/app.js", authenticated=False)[1]
            assert call("GET", "/reviews", authenticated=False)[0] == 200
            assert call("GET", "/api/reviews", authenticated=False)[0] == 401
            review_status, review_body = call("GET", "/api/reviews")
            assert review_status == 200
            reviews = json.loads(review_body)
            assert not reviews["settings"]["background"]
            assert not reviews["settings"]["consented"]
            assert reviews["jobs"] == []
            assert call("GET", "/api/sessions", authenticated=False)[0] == 401
            assert json.loads(call("GET", "/api/sessions")[1])["total"] == 1
            assert call("GET", "/api/threats", authenticated=False)[0] == 401
            threat_status, threat_body = call("GET", "/api/threats")
            assert threat_status == 200
            threat_feed = json.loads(threat_body)
            assert threat_feed["enabled"] is True and threat_feed["feed"]["counts"]["package_versions"] >= 8
            # Evaluate only. Never execute an installer or contact the registry.
            threat_guard = subprocess.run(
                [str(guard), "codex", str(state)],
                input=json.dumps({
                    "tool_name": "Bash",
                    "tool_input": {"command": (
                        "npm install --registry=https://registry.npmjs.org postmark-mcp@1.0.16"
                    )},
                    "cwd": project,
                }),
                capture_output=True, text=True, timeout=6,
            )
            assert threat_guard.returncode == 0
            threat_decision = json.loads(threat_guard.stdout)["hookSpecificOutput"]
            assert threat_decision["permissionDecision"] == "deny"
            assert "known malicious artifact" in threat_decision["permissionDecisionReason"]
            status, content = call("GET", "/api/environment-credentials")
            assert status == 200 and json.loads(content)["items"] == []
            assert call("POST", "/api/environment-credentials", {
                "name": "Synthetic unavailable native value", "env_name": "MY_PASSWORD",
            })[0] == 503
            prompt_marker = "synthetic-packaged-prompt-password-123"
            prompt_block = subprocess.run(
                [str(guard), "codex", str(state), "prompt"],
                input=json.dumps({"prompt": "My password is " + prompt_marker}),
                capture_output=True, text=True, timeout=6,
            )
            assert prompt_block.returncode == 0
            assert json.loads(prompt_block.stdout)["decision"] == "block"
            assert prompt_marker not in prompt_block.stdout
            prompt_reference = subprocess.run(
                [str(guard), "codex", str(state), "prompt"],
                input=json.dumps({"prompt": "Use $MY_PASSWORD from ADR Vault"}),
                capture_output=True, text=True, timeout=6,
            )
            assert json.loads(prompt_reference.stdout) == {}
            with httpx.Client(base_url=f"http://127.0.0.1:{runtime['port']}", trust_env=False) as browser:

                def open_tab():
                    status, content = call("POST", "/api/control/open")
                    assert status == 200
                    ticket = json.loads(content)["url"].partition("#ticket=")[2]
                    response = browser.post("/api/auth/bootstrap", json={"ticket": ticket})
                    assert response.status_code == 200
                    return response.json()["csrf"]

                csrf = open_tab()
                assert open_tab() == csrf
                settings = browser.get("/api/status").json()["settings"]
                assert settings["interval_seconds"] == 300
                assert settings["recording"] is False
                # Pause is safe here; never start real collectors in package QA.
                assert browser.post("/api/collector/pause").status_code == 403
                assert browser.post("/api/collector/pause", headers={"X-ADR-CSRF": csrf}).status_code == 200
                for seconds in (300, 900, 1800, 3600):
                    assert (
                        browser.patch(
                            "/api/settings",
                            json={"interval_seconds": seconds},
                            headers={"X-ADR-CSRF": csrf},
                        ).status_code
                        == 200
                    )
                    settings = browser.get("/api/status").json()["settings"]
                    assert settings["interval_seconds"] == seconds
                    assert settings["recording"] is False
                preview = browser.get("/api/protection/starter")
                assert preview.status_code == 200
                # This profile is temporary and no hooks are installed. The
                # catalog checks path metadata only, never credential contents.
                pending = preview.json()["available"]
                assert pending > 0
                # This profile has no installed hook. Never edit the user's real
                # harness configuration merely to make a package smoke test pass.
                added = browser.post("/api/protection/starter", json={}, headers={"X-ADR-CSRF": csrf})
                assert added.status_code == 400
                protected = next(item for item in preview.json()["items"] if item["kind"] == "file")
                cached = read_private_json(state / "policy.json")
                cached["rules"] = [
                    {
                        "id": "synthetic-rule",
                        "path": protected["path"],
                        "kind": protected["kind"],
                        "action": "block",
                        "label": "Synthetic starter rule",
                    }
                ]
                atomic_json(state / "policy.json", cached)
                result = subprocess.run(
                    [str(guard), "claude", str(state)],
                    input=json.dumps(
                        {
                            "tool_name": "Read",
                            "tool_input": {"file_path": protected["path"]},
                            "cwd": project,
                        }
                    ),
                    text=True,
                    capture_output=True,
                    timeout=6,
                )
                assert result.returncode == 0
                assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
                assert "protected file" in result.stdout
                literal_read = subprocess.run(
                    [str(guard), "codex", str(state)],
                    input=json.dumps({
                        "tool_name": "Bash",
                        "tool_input": {"command": "/bin/cat " + shlex.quote(protected["path"])},
                        "cwd": project,
                    }),
                    text=True, capture_output=True, timeout=6,
                )
                assert literal_read.returncode == 0
                assert json.loads(literal_read.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
                assert cached["strict_execution"] is False
                for tool in ("Bash", "exec_command", "collaborationsend_message"):
                    ordinary = subprocess.run(
                        [str(guard), "codex", str(state)],
                        input=json.dumps({
                            "tool_name": tool,
                            "tool_input": {"command": "pwd"},
                            "cwd": project,
                        }),
                        text=True, capture_output=True, timeout=6,
                    )
                    assert ordinary.returncode == 0
                    assert json.loads(ordinary.stdout) == {}
                assert call("PATCH", "/api/protection", {"strict_execution": True})[0] == 200
                unavailable = subprocess.run(
                    [str(guard), "codex", str(state)],
                    input=json.dumps({
                        "tool_name": "Bash",
                        "tool_input": {"command": "pwd"},
                        "cwd": project,
                    }),
                    text=True, capture_output=True, timeout=6,
                )
                output = json.loads(unavailable.stdout)["hookSpecificOutput"]
                assert output["permissionDecision"] == "deny"
                assert "approval dialog is unavailable" in output["permissionDecisionReason"]
                assert call("PATCH", "/api/protection", {"strict_execution": False})[0] == 200
            status, body = call("POST", "/api/agents", {"name": "Synthetic MCP", "project": project})
            assert status == 200, f"Grant creation failed: HTTP {status}"
            access = state / "agents" / f"{json.loads(body)['id']}.json"
            messages = [
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {"protocolVersion": "2025-06-18"},
                },
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "adr_list_sessions", "arguments": {}},
                },
            ]
            result = subprocess.run(
                [str(core), "mcp", "--access-file", str(access)],
                input="".join(json.dumps(message) + "\n" for message in messages),
                capture_output=True,
                text=True,
                timeout=10,
            )
            assert result.returncode == 0, result.stderr
            replies = [json.loads(line) for line in result.stdout.splitlines()]
            assert replies[-1]["result"]["structuredContent"]["total"] == 1, (
                f"Scoped MCP did not find its seeded project: {replies[-1]['result']['structuredContent']}"
            )
            status, content = call(
                "POST",
                "/api/agents",
                {"name": "Synthetic ADR Context", "kind": "context", "confirm_device_history": True},
            )
            assert status == 200
            history_access = state / "agents" / f"{json.loads(content)['id']}.json"
            messages[-1]["params"] = {
                "name": "adr_search_conversations",
                "arguments": {"query": "packaging"},
            }
            result = subprocess.run(
                [str(core), "mcp", "--access-file", str(history_access)],
                input="".join(json.dumps(message) + "\n" for message in messages),
                capture_output=True,
                text=True,
                timeout=10,
            )
            assert result.returncode == 0
            replies = [json.loads(line) for line in result.stdout.splitlines()]
            assert replies[-1]["result"]["structuredContent"]["total"] == 1
            decision = subprocess.run(
                [str(guard), "claude", str(state)],
                input=json.dumps(
                    {
                        "tool_name": "Read",
                        "tool_input": {"file_path": str(state / "policy.json")},
                        "cwd": project,
                    }
                ),
                text=True,
                capture_output=True,
                timeout=6,
            )
            assert decision.returncode == 0
            assert json.loads(decision.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
            print(
                "Packaged core, artifact threat feed/guardian, browser auth, capture intervals, "
                "starter rules, private UI resources, "
                "scoped MCP, and guardian smoke checks passed"
            )
        finally:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=3)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
