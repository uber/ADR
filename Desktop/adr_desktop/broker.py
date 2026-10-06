"""Approval-bound, read-only credential operations. SQLite never stores service secrets."""

import ipaddress
import json
import re
import threading
import time
from urllib.parse import urlsplit

from .config import canonical, utcnow
from .local_client import SAFE_ERRORS
from .native import NativeUnavailable
from .store import new_id

PATH_RE = re.compile(r"/[A-Za-z0-9/_@.:\-~]*")
HEADER_RE = re.compile(r"[A-Za-z][A-Za-z0-9-]{0,63}")
FORBIDDEN_HEADERS = {
    "host",
    "cookie",
    "content-length",
    "transfer-encoding",
    "connection",
    "proxy-authorization",
    "proxy-connection",
    "upgrade",
    "te",
    "trailer",
    "accept",
    "accept-encoding",
    "user-agent",
    "expect",
}


def validate_origin(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Use an HTTPS origin without a path, query, or embedded credentials")
    host = parsed.hostname.lower().encode("idna").decode("ascii")
    if host in ("localhost",) or host.endswith((".localhost", ".local")):
        raise ValueError("Local-network credential destinations are not supported in this preview")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if "." not in host:
            raise ValueError("Use a fully qualified public service hostname") from None
    else:
        raise ValueError("Use a public service hostname, not a literal IP address")
    port = parsed.port
    if port not in (None, 443):
        raise ValueError("This preview only supports HTTPS on port 443")
    return f"https://{host}"


def validate_path(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise ValueError("The service path is invalid")
    if any(ord(char) < 32 or ord(char) == 127 for char in value) or "\\" in value:
        raise ValueError("Control characters and backslashes are not allowed")
    parsed = urlsplit(value)
    if (
        parsed.scheme
        or parsed.netloc
        or parsed.fragment
        or value.startswith("//")
        or not PATH_RE.fullmatch(parsed.path)
        or any(part in (".", "..") for part in parsed.path.split("/"))
    ):
        raise ValueError("Use an origin-relative ASCII path without encoded segments or traversal")
    return value


def path_allowed(path: str, allowed: list[str]) -> bool:
    route = urlsplit(validate_path(path)).path
    return any(
        base == "/" or route == base.rstrip("/") or route.startswith(base.rstrip("/") + "/")
        for base in allowed
    )


def validate_profile(value: dict) -> dict:
    name = value.get("name", "").strip()
    if not name or len(name) > 80 or any(ord(char) < 32 for char in name):
        raise ValueError("Give the credential a short, readable name")
    origin = validate_origin(value["origin"])
    auth_type = value.get("auth_type", "bearer")
    if auth_type not in ("bearer", "api_key", "basic"):
        raise ValueError("Unsupported credential type")
    header = value.get("header_name") or "Authorization"
    if not HEADER_RE.fullmatch(header) or header.lower() in FORBIDDEN_HEADERS:
        raise ValueError("This header cannot carry a brokered credential")
    if auth_type in ("bearer", "basic"):
        header = "Authorization"
    username = value.get("username", "")
    if any(ord(char) < 32 for char in username) or (auth_type == "basic" and ":" in username):
        raise ValueError("The basic-auth username is invalid")
    if auth_type == "basic" and not username:
        raise ValueError("Basic authentication needs a username")
    paths = value.get("allowed_paths", ["/"])
    if not isinstance(paths, list) or not 1 <= len(paths) <= 32:
        raise ValueError("Choose between one and 32 allowed path prefixes")
    normalized = []
    for path in paths:
        validate_path(path)
        if "?" in path:
            raise ValueError("Allowed path prefixes must not contain a query")
        normalized.append(path.rstrip("/") or "/")
    return {
        "name": name,
        "origin": origin,
        "auth_type": auth_type,
        "header_name": header,
        "username": username,
        "allowed_paths": list(dict.fromkeys(normalized)),
    }


class Broker:
    def __init__(self, store, native):
        self.store = store
        self.native = native

    def credentials(self):
        rows = self.store.rows("SELECT * FROM credentials ORDER BY created_at DESC")
        for row in rows:
            row["allowed_paths"] = json.loads(row["allowed_paths"])
        return rows

    def create(self, value: dict):
        if not self.native.connected:
            raise NativeUnavailable("Open the macOS menu-bar app to use its Keychain broker")
        profile = validate_profile(value)
        identifier = new_id()
        self.store.execute(
            "INSERT INTO credentials VALUES (?,?,?,?,?,?,?,?,?)",
            (
                identifier,
                profile["name"],
                profile["origin"],
                profile["auth_type"],
                profile["header_name"],
                profile["username"],
                canonical(profile["allowed_paths"]),
                "preparing",
                utcnow(),
            ),
        )
        try:
            # Enter the secret in a native secure text field. Neither the browser
            # nor this Python process receives it. There is no vault_get RPC.
            receipt = self.native.call("vault_prompt_store", {"id": identifier, **profile}, timeout=120)
            if receipt.get("stored") is not True:
                raise NativeUnavailable("save_unconfirmed")
        except NativeUnavailable as error:
            if str(error) == "cancelled":
                self.store.execute("DELETE FROM credentials WHERE id=?", (identifier,))
                raise ValueError("Canceled; no credential was stored") from None
            self.store.execute("UPDATE credentials SET state='unconfirmed' WHERE id=?", (identifier,))
            self.store.audit("credential_save_unconfirmed", "Credential save needs verification", {
                "id": identifier,
                "reason_code": str(error) if str(error) in SAFE_ERRORS else "save_unconfirmed",
            })
            raise NativeUnavailable(
                "The save was not confirmed. Refresh Credential vault and recover the same entry if "
                "its local copy is available. Do not delete it or save a replacement yet."
            ) from None
        except Exception:
            self.store.execute("UPDATE credentials SET state='unconfirmed' WHERE id=?", (identifier,))
            self.store.audit("credential_save_unconfirmed", "Credential save needs verification",
                             {"id": identifier, "reason_code": "save_unconfirmed"})
            raise NativeUnavailable(
                "The save was not confirmed. "
                "Refresh Credential vault and verify the same entry before retrying."
            ) from None
        self.store.execute(
            "UPDATE credentials SET state='active' WHERE id=? AND state != 'revoked'", (identifier,),
        )
        current = next((item for item in self.credentials() if item["id"] == identifier), None)
        if not current or current["state"] != "active":
            raise NativeUnavailable("credential_removed_during_save")
        self.store.audit("credential_added", f"Added credential: {profile['name']}", {"id": identifier})
        return current

    def remove(self, identifier: str):
        credential = self.store.one("SELECT * FROM credentials WHERE id=?", (identifier,))
        if not credential:
            raise ValueError("Credential not found")
        # Revoke before touching local storage. A deletion failure must not leave
        # the credential usable through ADR.
        self.store.execute("UPDATE credentials SET state='revoked' WHERE id=?", (identifier,))
        self.store.execute(
            "UPDATE broker_requests SET state='revoked',result=NULL WHERE credential_id=?",
            (identifier,),
        )
        self.native.call("vault_delete", {"id": identifier})
        self.store.execute("DELETE FROM credentials WHERE id=?", (identifier,))
        self.store.audit("credential_removed", f"Removed credential: {credential['name']}")

    def expire(self):
        self.store.execute(
            """UPDATE broker_requests SET state='expired',result=NULL
               WHERE expires_at<? AND state IN ('pending','succeeded','failed')""",
            (time.time(),),
        )

    def enqueue(self, grant: dict, credential_id: str, path: str):
        if not self.native.connected:
            raise NativeUnavailable("Open the menu-bar app before requesting a Keychain-backed operation")
        self.expire()
        if credential_id not in json.loads(grant["credentials"]):
            raise PermissionError("This agent does not have access to that credential")
        credential = self.store.one(
            "SELECT * FROM credentials WHERE id=? AND state='active'", (credential_id,)
        )
        if not credential:
            raise ValueError("Credential is unavailable")
        validate_path(path)
        if not path_allowed(path, json.loads(credential["allowed_paths"])):
            raise PermissionError("This path is outside the credential's permitted scope")
        pending = self.store.one(
            "SELECT count(*) AS n FROM broker_requests WHERE grant_id=? AND state IN ('pending','running')",
            (grant["id"],),
        )["n"]
        if pending >= 10:
            raise ValueError("This agent already has ten outstanding requests")
        automatic = grant.get("kind") == "vault" and grant.get("approval_mode") == "automatic"
        state = "running" if automatic else "pending"
        identifier = new_id()
        self.store.execute(
            """INSERT INTO broker_requests(
               id,grant_id,credential_id,credential_name,origin,path,state,created_at,expires_at
               ) VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                identifier,
                grant["id"],
                credential_id,
                credential["name"],
                credential["origin"],
                path,
                state,
                utcnow(),
                time.time() + 300,
            ),
        )
        self.store.audit(
            "credential_requested",
            f"{grant['name']} requested {credential['name']}",
            {
                "request_id": identifier,
                "grant_id": grant["id"],
                "authorization": "automatic" if automatic else "ask",
            },
        )
        if automatic:
            threading.Thread(target=self._perform, args=(identifier,), daemon=True).start()
        return {
            "request_id": identifier,
            "state": state,
            "message": "Using the permission you configured in ADR"
            if automatic
            else "Approve this request in ADR",
        }

    def approve(self, identifier: str, allow: bool):
        self.expire()
        state = "running" if allow else "denied"
        changed = self.store.execute(
            "UPDATE broker_requests SET state=? WHERE id=? AND state='pending' AND expires_at>?",
            (state, identifier, time.time()),
        )
        if not changed:
            raise ValueError("This request is no longer pending")
        self.store.audit(
            "credential_approved" if allow else "credential_denied",
            "Credential request approved once" if allow else "Credential request denied",
            {"request_id": identifier},
        )
        if allow:
            threading.Thread(target=self._perform, args=(identifier,), daemon=True).start()
        return {"state": state}

    def _perform(self, identifier: str):
        request = self.store.one("SELECT * FROM broker_requests WHERE id=?", (identifier,))
        credential = self.store.one(
            "SELECT id FROM credentials WHERE id=? AND state='active'", (request["credential_id"],)
        )
        grant = self.store.one("SELECT id FROM grants WHERE id=? AND revoked=0", (request["grant_id"],))
        try:
            if not credential or not grant:
                raise PermissionError("Access was revoked")
            response = self.native.call(
                "vault_perform", {
                    "id": request["credential_id"], "path": request["path"],
                    "protection_environment_ids": [
                        row["id"] for row in self.store.rows(
                            "SELECT id FROM environment_credentials WHERE state='active'"
                        )
                    ],
                    "protection_service_ids": [
                        row["id"] for row in self.store.rows(
                            "SELECT id FROM credentials WHERE state='active'"
                        )
                    ],
                }, timeout=25,
            )
            self.store.execute(
                """UPDATE broker_requests SET state='succeeded',result=?,expires_at=?
                   WHERE id=? AND state='running'""",
                (canonical(response), time.time() + 300, identifier),
            )
        except Exception:
            self.store.execute(
                """UPDATE broker_requests SET state='failed',error=?,expires_at=?
                   WHERE id=? AND state='running'""",
                ("The approved request failed or its response was withheld", time.time() + 300, identifier),
            )

    def result(self, grant: dict, identifier: str):
        self.expire()
        row = self.store.one(
            "SELECT * FROM broker_requests WHERE id=? AND grant_id=?", (identifier, grant["id"])
        )
        if not row:
            raise ValueError("Request not found")
        return {
            "request_id": row["id"],
            "state": row["state"],
            "result": json.loads(row["result"]) if row["result"] else None,
            "error": row["error"],
        }
