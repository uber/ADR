"""The same executable serves the app, isolated collectors, hooks, and scoped MCP."""

import argparse
import json
import os
import socket
import sys
import webbrowser
from pathlib import Path

from . import __version__
from .config import InstanceLock, atomic_json, default_state_dir, prepare_state_dir, read_private_json


def serve(args):
    import uvicorn

    from .api import create_app
    from .native import NativeBridge
    from .runtime import Runtime

    state_dir = prepare_state_dir(args.state_dir)
    lock = InstanceLock(state_dir)
    native = NativeBridge(enabled=args.native_bridge)
    runtime = Runtime(state_dir, native)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", args.port))
    listener.listen(64)
    runtime.port = listener.getsockname()[1]
    atomic_json(
        state_dir / "runtime.json",
        {"version": 1, "port": runtime.port, "pid": os.getpid(), "instance": runtime.instance},
    )
    if not args.native_bridge:
        atomic_json(state_dir / "owner-access.json", {"token": runtime.owner_token})
    server = uvicorn.Server(
        uvicorn.Config(
            create_app(runtime),
            host="127.0.0.1",
            port=runtime.port,
            log_level="warning",
            access_log=False,
            proxy_headers=False,
            limit_concurrency=64,
            timeout_keep_alive=3,
            timeout_graceful_shutdown=5,
        )
    )
    def native_disconnected():
        runtime.hook_approvals.close()
        server.should_exit = True

    native.on_disconnect = native_disconnected
    if args.native_bridge:
        native.emit(
            {
                "type": "ready",
                "port": runtime.port,
                "owner_token": runtime.owner_token,
                "version": __version__,
            }
        )
    else:
        print(f"ADR Desktop is running on 127.0.0.1:{runtime.port}", flush=True)
        print("Run `adr-desktop open` to open an authenticated local window.", flush=True)
    try:
        server.run(sockets=[listener])
    finally:
        runtime.close()
        listener.close()
        lock.close()
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="adr-desktop", description="ADR Desktop — local-first agent security"
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    server = sub.add_parser("serve", help="Run the local app backend")
    server.add_argument("--state-dir", type=Path, default=default_state_dir())
    server.add_argument("--port", type=int, default=0)
    server.add_argument("--native-bridge", action="store_true", help=argparse.SUPPRESS)
    adapter = sub.add_parser("hook", help="Agent pre-tool hook adapter")
    adapter.add_argument("--harness", choices=("claude", "codex", "opencode", "copilot"), required=True)
    adapter.add_argument("--state-dir", type=Path, default=default_state_dir())
    adapter.add_argument("--managed-by", default="", help=argparse.SUPPRESS)
    adapter.add_argument("--guard-protocol", action="store_true", help=argparse.SUPPRESS)
    adapter.add_argument("--phase", choices=("pre", "post", "prompt"), default="pre", help=argparse.SUPPRESS)
    disconnect = sub.add_parser("disconnect", help="Remove only ADR hooks, even if the app cannot start")
    disconnect.add_argument(
        "--harness", choices=("claude", "codex", "opencode", "copilot", "all"), default="all"
    )
    disconnect.add_argument("--state-dir", type=Path, default=default_state_dir())
    mcp = sub.add_parser("mcp", help="Serve an explicitly authorized ADR MCP connection over stdio")
    mcp.add_argument("--access-file", type=Path, required=True)
    execution = sub.add_parser("exec", help="Run a command with an explicitly granted vault environment")
    execution.add_argument("--access-file", type=Path, required=True)
    execution.add_argument(
        "--command", dest="script", required=True, help="Bash command using $VARIABLE aliases"
    )
    execution.add_argument("--cwd", default="")
    execution.add_argument("--timeout-seconds", type=int, default=30)
    connect = sub.add_parser("connect", help="Connect the ADR plugin to installed agents")
    connect.add_argument(
        "harness", choices=("claude", "codex", "opencode", "copilot", "all"), nargs="?", default="all",
    )
    connect.add_argument(
        "--allow-agent-access", action="store_true",
        help="Connect history, protection, and automatic use of all saved credentials",
    )
    connect.add_argument(
        "--allow-device-context",
        action="store_true",
        help="Consent to read-only captured conversation access",
    )
    connect.add_argument("--state-dir", type=Path, default=default_state_dir())
    context = sub.add_parser("context", help="Run ADR Context MCP for an already connected agent")
    context.add_argument("--harness", choices=("claude", "codex", "opencode", "copilot"), required=True)
    context.add_argument("--state-dir", type=Path, default=default_state_dir())
    migration = sub.add_parser("migrate-vault", help="Request a one-time native-approved Keychain copy")
    migration.add_argument("--confirm", action="store_true", help="Request the native owner's approval")
    migration.add_argument("--state-dir", type=Path, default=default_state_dir())
    review_usage = sub.add_parser("review-usage", help="Receive Claude status-line quota metadata on stdin")
    review_usage.add_argument("--state-dir", type=Path, default=default_state_dir())
    review_line = sub.add_parser("review-statusline", help="Preserve Claude's status line and report usage")
    review_line.add_argument("--state-dir", type=Path, default=default_state_dir())
    supervisor = sub.add_parser("review-supervise", help=argparse.SUPPRESS)
    supervisor.add_argument("--lifetime-fd", type=int, required=True)
    supervisor.add_argument("--timeout", type=float, required=True)
    supervisor.add_argument("arguments", nargs=argparse.REMAINDER)
    for name in ("open", "status"):
        command = sub.add_parser(name)
        command.add_argument("--state-dir", type=Path, default=default_state_dir())
    capture = sub.add_parser("capture", help=argparse.SUPPRESS)
    capture.add_argument("--destination", type=Path, required=True)
    capture.add_argument("--history-days", type=int, default=14)
    inventory = sub.add_parser("capture-inventory", help=argparse.SUPPRESS)
    inventory.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        if args.command == "review-supervise":
            from .review_supervisor import supervise

            command = args.arguments[1:] if args.arguments[:1] == ["--"] else args.arguments
            return supervise(command, args.lifetime_fd, args.timeout)
        if args.command == "serve":
            if args.port != 0 and not 1024 <= args.port <= 65535:
                parser.error("Choose port 0 or an unprivileged local port")
            return serve(args)
        if args.command == "hook":
            if args.phase == "prompt":
                from .prompt_guard import run_prompt_hook

                return run_prompt_hook(args.state_dir, args.harness, guard_protocol=args.guard_protocol)
            from .hooks import run_hook

            return run_hook(
                args.state_dir, args.harness, guard_protocol=args.guard_protocol, phase=args.phase
            )
        if args.command == "disconnect":
            from .agent_plugins import disconnect_offline

            for harness in (
                ("claude", "codex", "opencode", "copilot") if args.harness == "all" else (args.harness,)
            ):
                disconnect_offline(args.state_dir, harness)
            print(
                "ADR integrations disconnected and their context access revoked. Restart the affected agents."
            )
            return 0
        if args.command == "mcp":
            from .mcp_server import serve as mcp_serve

            return mcp_serve(args.access_file)
        if args.command == "exec":
            from .mcp_server import call_tool

            access = read_private_json(args.access_file, maximum=16384)
            result = call_tool(access, "adr_run_command", {
                "command": args.script, "cwd": args.cwd, "timeout_seconds": args.timeout_seconds,
            })
            print(result.get("stdout", ""), end="")
            print(result.get("stderr", ""), end="", file=sys.stderr)
            if result.get("message"):
                print(result["message"], file=sys.stderr)
            return result.get("exit_code") if isinstance(result.get("exit_code"), int) else 1
        if args.command == "context":
            from .agent_plugins import read_receipt
            from .mcp_server import serve as mcp_serve

            receipt = read_receipt(args.state_dir, args.harness)
            if not receipt or receipt.get("status") != "configured":
                raise ValueError("Connect ADR to this agent before starting ADR Context")
            return mcp_serve(args.state_dir / "agents" / f"{receipt['grant_id']}.json")
        if args.command == "capture":
            from .collector import capture_worker

            return capture_worker(args.destination, args.history_days)
        if args.command == "capture-inventory":
            from .collector import inventory_worker

            return inventory_worker(args.destination)
        from .local_client import request
        if args.command == "review-usage":
            # Add this as a side command to an existing status-line script.
            # Never log or forward the rest of its payload, which can contain
            # private session/workspace information.
            from .review_usage import report_usage

            try:
                report_usage(args.state_dir, sys.stdin.buffer.read(256 * 1024 + 1))
            except Exception:
                pass  # A reporting failure must not disrupt the person's status line.
            return 0
        if args.command == "review-statusline":
            from .review_usage import status_line

            return status_line(args.state_dir)

        if args.command == "migrate-vault":
            if not args.confirm:
                parser.error("Use --confirm to request the native owner's migration approval")
            print("Approve the one-time credential move in the ADR app.", file=sys.stderr)
            result = request(
                args.state_dir, "POST", "/api/vault/enroll-migration",
                payload={"confirm": True}, timeout=240,
            )
            results = result.get("results", [])
            print(json.dumps({
                "ready": sum(item.get("status") in ("migrated", "already_local") for item in results),
                "failed": sum(item.get("status") == "failed" for item in results),
                "keychain_originals_retained": result.get("keychain_originals_retained") is True,
            }))
            return 1 if any(item.get("status") == "failed" for item in results) else 0

        if args.command == "connect":
            if not args.allow_device_context and not args.allow_agent_access:
                parser.error(
                    "Add --allow-agent-access to connect the ADR plugin, or --allow-device-context "
                    "for a legacy history-only connection to one agent"
                )
            if args.harness == "all" and not args.allow_agent_access:
                parser.error("Use --allow-agent-access when connecting all installed agents")
            consent = (
                {"allow_agents": True} if args.harness == "all"
                else {"allow_context": True, "allow_credentials": args.allow_agent_access}
            )
            owner_file = args.state_dir / "owner-access.json"
            health = request(args.state_dir, "GET", "/api/health")
            if not health.get("interactive_setup") and owner_file.exists():
                owner = read_private_json(owner_file)["token"]
                result = request(
                    args.state_dir,
                    "POST",
                    "/api/integrations/connect-all" if args.harness == "all"
                    else f"/api/integrations/{args.harness}/connect",
                    token=owner,
                    payload=consent,
                    timeout=600,
                )
            else:
                print("Approve ADR integration setup in the menu-bar app.", file=sys.stderr)
                result = request(
                    args.state_dir,
                    "POST",
                    "/api/integrations/enroll",
                    payload={"harness": args.harness, **consent},
                    timeout=600,
                )
            if args.harness == "all":
                for item in result["items"]:
                    print(f"{item['harness']}: {item['status']}")
            else:
                print(f"ADR configured for {args.harness}.")
            print("Restart the agent and complete any native plugin trust prompts.")
            return 1 if any(item["status"] == "needs_repair" for item in result.get("items", [])) else 0

        if args.command == "status":
            print(json.dumps(request(args.state_dir, "GET", "/api/health"), indent=2))
            return 0
        auth = read_private_json(args.state_dir / "owner-access.json")
        result = request(args.state_dir, "POST", "/api/control/open", token=auth["token"])
        webbrowser.open(result["url"])
        return 0
    except Exception as error:
        if args.command == "hook":
            from .policy import Decision, hook_output

            print(
                "deny"
                if args.guard_protocol
                else json.dumps(
                    hook_output(
                        Decision("deny", "ADR file protection is unavailable", phase=args.phase), args.harness
                    )
                )
            )
            return 0
        print(f"ADR: {error}", file=sys.stderr)
        return 1
