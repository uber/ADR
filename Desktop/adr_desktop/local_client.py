"""Bounded loopback-only client. It never follows redirects or reads proxy settings."""

import http.client
import json
import re
from pathlib import Path

from .config import read_private_json


class LocalUnavailable(RuntimeError):
    def __init__(self, message, *, run_id=""):
        super().__init__(message)
        self.run_id = run_id if isinstance(run_id, str) and re.fullmatch(r"[a-f0-9]{32}", run_id) else ""


SAFE_ERRORS = {
    "known_malicious_artifact": (
        "ADR blocked a known malicious artifact. Open Malicious artifacts in ADR to review the match."
    ),
    "keychain_unavailable": (
        "ADR could not access the saved credential in macOS Keychain. "
        "Unlock Keychain and allow the ADR app to use the item, then try again."
    ),
    "credential_check_timeout": (
        "ADR's credential check timed out. Open Credential vault in ADR to check its storage status."
    ),
    "credential_check_unavailable": (
        "ADR could not check the saved credentials. Open the ADR menu-bar app and try again."
    ),
    "invalid_environment_credential": "ADR could not load a saved credential. Review its entry in the vault.",
    "invalid_credential_id": "ADR could not find the saved credential. Review its entry in the vault.",
    "local_vault_missing": (
        "This credential is not in ADR's local vault yet. Open Credential vault and move the old "
        "Keychain entry, or save the value again. No extra agent configuration is needed."
    ),
    "local_vault_corrupt": (
        "A saved local credential could not be verified. Review that entry in ADR; it was not replaced."
    ),
    "local_vault_key_missing": (
        "ADR's local vault key is missing. Restore the complete vault backup or re-enter the credentials."
    ),
    "local_vault_key_invalid": (
        "ADR's local vault key is invalid. Review the vault in ADR; no key was replaced."
    ),
    "local_vault_unsafe_path": "ADR could not safely open its vault files. Review the local profile in ADR.",
    "local_vault_permissions": "ADR's vault files need owner-only access. Review the local profile in ADR.",
    "local_vault_too_large": "A local vault record exceeded its supported size. Review that entry in ADR.",
    "local_vault_unavailable": "ADR's local credential store is unavailable. Open the ADR menu-bar app.",
    "local_vault_busy": "ADR's credential store is busy with another operation. Wait for it to finish.",
    "local_vault_exists": "This credential already has a local copy. Refresh the vault before trying again.",
    "local_vault_write_uncertain": (
        "ADR could not confirm the credential save. "
        "Refresh vault storage before retrying or deleting anything."
    ),
    "credential_removed_during_save": (
        "This credential was removed while its save was pending. It was not reactivated."
    ),
    "vault_migration_busy": (
        "A previous credential move is still finishing. Close any pending Keychain dialog before retrying."
    ),
    "vault_migration_expired": "The credential move expired. Refresh storage before explicitly trying again.",
    "vault_migration_cancelled": (
        "The credential move was cancelled. Refresh storage to see which copies completed."
    ),
    "vault_migration_invalidated": "This entry was removed while the credential move was pending.",
}


def request(state_dir: Path, method: str, path: str, *, token="", payload=None, timeout=3.0):
    runtime = read_private_json(state_dir / "runtime.json", maximum=16384)
    port = runtime.get("port")
    if not isinstance(port, int) or isinstance(port, bool) or not 1024 <= port <= 65535:
        raise LocalUnavailable("ADR has no valid local listener")
    if not path.startswith("/api/") or "\r" in path or "\n" in path:
        raise ValueError("Invalid local API path")
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    encoded = json.dumps(payload, allow_nan=False).encode() if payload is not None else None
    try:
        connection.request(method, path, body=encoded, headers=headers)
        response = connection.getresponse()
        body = response.read(8 * 1024 * 1024 + 1)
        if len(body) > 8 * 1024 * 1024:
            raise LocalUnavailable("ADR response exceeded its local limit")
        if response.status >= 300:
            # Never reflect arbitrary server/validation text into a model result.
            # Only known credential-availability codes have actionable messages.
            try:
                error = json.loads(body)
                code = error.get("detail")
                message = SAFE_ERRORS.get(code) if isinstance(code, str) else None
                run_id = error.get("run_id", "") if path == "/api/agent/environment/run" else ""
            except (ValueError, AttributeError):
                message, run_id = None, ""
            raise LocalUnavailable(
                message or f"ADR rejected the request (HTTP {response.status})", run_id=run_id,
            )
        return json.loads(body) if body else {}
    except (OSError, ValueError, http.client.HTTPException) as exc:
        raise LocalUnavailable("ADR Desktop is unavailable; open the menu-bar app") from exc
    finally:
        connection.close()
