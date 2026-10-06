"""Run the real ADR UI/API with disposable sample data for interactive browser QA.

No real agent configuration, captured history, credential values, or OS access
settings are read or changed. The printed URL authenticates only this lab.
"""

import argparse
import json
import socket
import tempfile
from pathlib import Path

import uvicorn
from qa_support import isolated_agent_profile
from ui_qa import SyntheticNative, SyntheticPluginDriver, seed

from adr_desktop.api import create_app
from adr_desktop.config import atomic_json, prepare_state_dir
from adr_desktop.runtime import Runtime


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=0, help="Loopback port; 0 selects an available port")
    parser.add_argument("--first-run", action="store_true", help="Show the first-run introduction")
    parser.add_argument(
        "--vault-recovery", action="store_true", help="Include synthetic vault recovery cases",
    )
    parser.add_argument(
        "--read-error", action="store_true", help="Include a synthetic filesystem I/O failure",
    )
    parser.add_argument(
        "--credential-activity", action="store_true", help="Include vault-to-session navigation cases",
    )
    parser.add_argument(
        "--threats", action="store_true",
        help="Include inert threat-list matches and a real synthetic denial",
    )
    parser.add_argument(
        "--connection-file", type=Path,
        help="Optional private JSON containing the lab URL; never point this at an ADR profile",
    )
    args = parser.parse_args()
    if args.port and not 1024 <= args.port <= 65535:
        parser.error("Use port 0 or a port between 1024 and 65535")
    if args.connection_file and args.connection_file.exists():
        parser.error("Choose a new connection-file path; existing files are never overwritten")

    with tempfile.TemporaryDirectory(prefix="adr-community-lab-") as temporary:
        directory = Path(temporary)
        home = directory / "home"
        home.mkdir(mode=0o700)

        with isolated_agent_profile(home):
            runtime = Runtime(
                prepare_state_dir(directory / "state"), SyntheticNative(), start_collectors=False,
            )
            runtime.integration_driver = SyntheticPluginDriver()
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                seed(runtime)
                if args.credential_activity:
                    from credential_activity_ui_qa import seed_credential_activity

                    seed_credential_activity(runtime)
                if args.threats:
                    from threats_ui_qa import seed_threats

                    seed_threats(runtime)
                snapshot = runtime.store.settings()["inventory_snapshot"]
                snapshot["coverage"] = {
                    "denied": [
                        *[
                            {"path": f"/var/folders/other-user/cache-{index}", "reason": "Permission denied"}
                            for index in range(85)
                        ],
                        *[
                            {"path": "/Users/sample/Library/Containers/"
                                     f"example.agent-{index % 2}/item-{index}",
                             "reason": "Operation not permitted"}
                            for index in range(21)
                        ],
                        {"path": "/Users/sample/.ssh", "reason": "personal_path"},
                    ],
                    "boundaries_hit": [
                        {"path": "/Users/sample/project/node_modules", "boundary": "scope_excluded",
                         "detail": "Dependency files are not part of the broad scan"},
                        {"path": "/Users/sample/project", "boundary": "budget_exhausted",
                         "detail": "Synthetic scan time limit"},
                    ],
                }
                runtime.store.setting("inventory_snapshot", snapshot)
                if args.read_error:
                    snapshot["coverage"]["denied"].append({
                        "path": "/Users/sample/Library/Application Support/Example Agent/config.json",
                        "reason": "Input/output error", "errno": 5,
                    })
                    runtime.store.setting("inventory_snapshot", snapshot)
                if args.first_run:
                    runtime.store.setting("onboarding_complete", False)
                if args.vault_recovery:
                    interrupted = runtime.environment_vault.create("Interrupted save", "RECOVER_ME")
                    runtime.store.execute(
                        "UPDATE environment_credentials SET state='unconfirmed' WHERE id=?",
                        (interrupted["id"],),
                    )
                    damaged = runtime.environment_vault.create("Backup needs its key", "BACKUP_TOKEN")
                    runtime.native.storage_errors[damaged["id"]] = "local_vault_key_missing"
                    old = runtime.environment_vault.create("Earlier credential", "LEGACY_TOKEN")
                    runtime.native.local_ids.discard(old["id"])
                    runtime.environment_vault.publish_aliases()
                listener.bind(("127.0.0.1", args.port))
                listener.listen(64)
                runtime.port = listener.getsockname()[1]
                connection = {
                    "url": f"http://127.0.0.1:{runtime.port}/#ticket={runtime.new_ticket()}",
                    "port": runtime.port,
                    "data": "synthetic only",
                    "expires": "when the lab stops",
                }
                if args.connection_file:
                    atomic_json(args.connection_file.resolve(), connection)
                print(json.dumps(connection), flush=True)
                print("Open the URL with your browser MCP. Ctrl+C stops this disposable lab.", flush=True)
                uvicorn.Server(uvicorn.Config(
                    create_app(runtime), log_level="warning", access_log=False, proxy_headers=False,
                )).run(sockets=[listener])
            finally:
                runtime.close()
                listener.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
