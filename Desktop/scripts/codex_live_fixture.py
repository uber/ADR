#!/usr/bin/env python3
"""Opt-in, synthetic-only fixture for manually checking a real Codex session.

Does not launch a model, scan the device, read history, or use the native vault.
Native installation is explicit and removes only this fixture's unique plugin
and marketplace on shutdown. Review/trust its hooks in Codex, never trust all.
"""

import argparse
import json
import os
import shlex
import shutil
import socket
import subprocess
import tempfile
import tomllib
from pathlib import Path
from unittest.mock import patch

import uvicorn

from adr_desktop import agent_plugins
from adr_desktop.api import create_app
from adr_desktop.config import atomic_json, prepare_state_dir, utcnow
from adr_desktop.runtime import Runtime


class TestPluginDriver(agent_plugins.NativePluginDriver):
    def __init__(self, launcher):
        self.launcher = launcher

    def executable(self, harness):
        return self.launcher[0]

    def run(self, executable, *arguments):
        result = subprocess.run(
            [*self.launcher, *arguments],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode:
            raise RuntimeError("Codex rejected the fixture plugin command; inspect its local plugin state")


def launch_arguments(launcher, fixture, real_home):
    """Preserve authentication and security hooks; isolate only other ADR profiles."""
    market, project, catalog = (fixture[key] for key in ("market", "project", "catalog"))
    arguments = [
        *launcher,
        "--no-daemon",
        "-C", project,
        "-c", "projects={" + json.dumps(project) + '={trust_level="trusted"}}',
        "-c", f'marketplaces.{market}.source_type="local"',
        "-c", f"marketplaces.{market}.source={json.dumps(catalog)}",
        "-c", f"plugins.adr-agent@{market}.enabled=true",
    ]
    config = real_home / ".codex/config.toml"
    if config.is_file():
        # Read identifiers only into the command; do not copy provider settings,
        # credentials, or unrelated MCP/plugin definitions into the fixture.
        settings = tomllib.loads(config.read_text())
        for identifier in settings.get("plugins", {}):
            if identifier.startswith("adr-agent@") and identifier != "adr-agent@" + market:
                arguments.extend(["-c", f"plugins.{identifier}.enabled=false"])
    return arguments


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--codex-command",
        default="codex",
        help="Codex launcher command; defaults to the installed codex executable",
    )
    parser.add_argument(
        "--install",
        action="store_true",
        help="Use the native plugin manager to install/remove this unique synthetic test bundle",
    )
    args = parser.parse_args()
    launcher = shlex.split(args.codex_command)
    if not launcher or not shutil.which(launcher[0]):
        parser.error("The Codex launcher was not found")
    os.umask(0o077)
    real_home = Path.home()
    root = Path(tempfile.mkdtemp(prefix="adr-codex-test-")).resolve()
    state = prepare_state_dir(root / "state")
    project, fake_home = root / "project", root / "home"
    project.mkdir()
    fake_home.mkdir()
    driver = TestPluginDriver(launcher)
    runtime = None
    record = None
    listener = None
    try:
        with patch.object(Path, "home", return_value=fake_home):
            runtime = Runtime(state, start_collectors=False)
            if args.install:
                agent_plugins.connect(runtime, "codex", allow_context=True, driver=driver)
                record = agent_plugins.read_receipt(state, "codex")
            else:
                grant = runtime.create_grant(
                    "Synthetic Codex test", kind="context", confirm_device_history=True
                )
                market = "adr-local-codex-" + grant["id"][:12]
                _, files = agent_plugins.build_bundle(runtime, "codex", grant["id"], market)
                record = {
                    "schema": 1, "harness": "codex", "market": market, "grant_id": grant["id"],
                    "status": "configured", "updated_at": utcnow(), "files": files,
                    "market_registered": False,
                }
                atomic_json(agent_plugins.directory(state, "codex") / "installation.json", record)
        (project / "public.txt").write_text("ADR_PUBLIC_FIXTURE\n")
        (project / "protected.txt").write_text("ADR_BLOCKED_FIXTURE\n")
        (project / "approval.txt").write_text("ADR_APPROVAL_FIXTURE\n")
        (project / "synthetic-token.txt").write_text("ghp_" + "a" * 36 + "\n")
        for filename, action in (("protected.txt", "block"), ("approval.txt", "ask")):
            runtime.change_policy(
                add={"path": str(project / filename), "kind": "file", "action": action, "label": filename}
            )
        for source, answer in (("claude", "violet lighthouse"), ("opencode", "amber orchard")):
            runtime.store.ingest({
                "source": source, "session_id": "synthetic-" + source, "username": "synthetic",
                "timestamp": utcnow(), "project_path": str(project), "model": "synthetic",
                "chat_history": [
                    {"role": "user", "content": "ADR_SYNTHETIC_CONTEXT_NEEDLE", "tools": []},
                    {"role": "assistant", "content": answer, "tools": []},
                ],
            })
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(64)
        runtime.port = listener.getsockname()[1]
        atomic_json(state / "runtime.json", {
            "version": 1, "port": runtime.port, "pid": os.getpid(), "instance": runtime.instance,
        })
        fixture = {
            "project": str(project),
            "catalog": str(agent_plugins.directory(state, "codex") / "catalog"),
            "market": record["market"],
        }
        print(f"Synthetic fixture: {root}", flush=True)
        print("Launch in another terminal:\n" + shlex.join(launch_arguments(launcher, fixture, real_home)))
        print("Review only this test plugin's PreToolUse/PostToolUse entries in /hooks.")
        print("Search ADR_SYNTHETIC_CONTEXT_NEEDLE, then read both matching conversations.")
        print("Run separate cat calls on public.txt, protected.txt, and synthetic-token.txt.")
        print("Do not retry denials or access any other files. Stop this fixture with Ctrl-C.")
        print(
            "The project/state remain local for inspection; issued test access is revoked on exit.",
            flush=True,
        )
        uvicorn.Server(uvicorn.Config(
            create_app(runtime), host="127.0.0.1", port=runtime.port,
            log_level="warning", access_log=False, proxy_headers=False,
        )).run(sockets=[listener])
    finally:
        if runtime is not None:
            # Revoke every synthetic grant, including a partially failed install.
            for grant in runtime.store.rows("SELECT id FROM grants WHERE revoked=0"):
                runtime.revoke_grant(grant["id"])
            record = record or agent_plugins.read_receipt(state, "codex")
            if args.install and record:
                try:
                    agent_plugins.disconnect(runtime, "codex", driver=driver)
                    driver.run(launcher[0], "plugin", "marketplace", "remove", record["market"])
                except Exception:
                    print(
                        "Test access is revoked. Finish cleanup in Codex for only "
                        f"adr-agent@{record['market']} and marketplace {record['market']}."
                    )
            runtime.close()
        if listener is not None:
            listener.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        # main's finally block revokes the fixture before returning.
        pass
