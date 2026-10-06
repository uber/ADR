import time

import pytest
from conftest import add_credential

from adr_desktop.broker import path_allowed, validate_origin, validate_path, validate_profile


@pytest.mark.parametrize(
    "origin",
    [
        "http://api.github.com",
        "https://localhost",
        "https://127.0.0.1",
        "https://10.0.0.1",
        "https://api.github.com/path",
        "https://api.github.com?x=1",
        "https://user:secret@api.github.com",
        "https://api.github.com:8443",
    ],
)
def test_invalid_destinations_are_rejected(origin):
    with pytest.raises(ValueError):
        validate_origin(origin)


@pytest.mark.parametrize(
    "path",
    [
        "//evil.example",
        "https://evil.example",
        "/repos/../secret",
        "/repos/%2e%2e/secret",
        "/repos%2fsecret",
        "/repos\\secret",
        "/repos\r\nInjected: bad",
        "/repos#fragment",
    ],
)
def test_request_path_cannot_override_destination_or_scope(path):
    with pytest.raises(ValueError):
        validate_path(path)


def test_allowed_prefix_is_a_path_segment_boundary():
    assert path_allowed("/repos/a/b?per_page=10", ["/repos"])
    assert not path_allowed("/repositories", ["/repos"])
    assert not path_allowed("/user", ["/repos"])


@pytest.mark.parametrize(
    "header", ["Host", "Cookie", "Content-Length", "Proxy-Authorization", "Bad\r\nHeader"]
)
def test_credential_cannot_control_http_routing_headers(header):
    with pytest.raises(ValueError):
        validate_profile(
            {
                "name": "Test",
                "origin": "https://api.github.com",
                "auth_type": "api_key",
                "header_name": header,
                "allowed_paths": ["/user"],
            }
        )


def test_expired_requests_cannot_be_approved(runtime):
    credential = add_credential(runtime)
    grant = runtime.create_grant("Agent", "/workspace", [credential["id"]])
    stored = runtime.store.one("SELECT * FROM grants WHERE id=?", (grant["id"],))
    pending = runtime.broker.enqueue(stored, credential["id"], "/user")
    runtime.store.execute(
        "UPDATE broker_requests SET expires_at=? WHERE id=?", (time.time() - 1, pending["request_id"])
    )
    with pytest.raises(ValueError):
        runtime.broker.approve(pending["request_id"], True)
    assert not any(operation == "vault_perform" for operation, _ in runtime.native.calls)


def test_credential_revocation_blocks_pending_requests(runtime):
    credential = add_credential(runtime)
    grant = runtime.create_grant("Agent", "/workspace", [credential["id"]])
    stored = runtime.store.one("SELECT * FROM grants WHERE id=?", (grant["id"],))
    pending = runtime.broker.enqueue(stored, credential["id"], "/user")
    runtime.broker.remove(credential["id"])
    assert runtime.broker.result(stored, pending["request_id"])["state"] == "revoked"
    with pytest.raises(ValueError):
        runtime.broker.approve(pending["request_id"], True)


def test_approval_result_belongs_only_to_requesting_connection(runtime):
    credential = add_credential(runtime)
    first = runtime.create_grant("First", "/workspace", [credential["id"]])
    second = runtime.create_grant("Second", "/workspace", [credential["id"]])
    a = runtime.store.one("SELECT * FROM grants WHERE id=?", (first["id"],))
    b = runtime.store.one("SELECT * FROM grants WHERE id=?", (second["id"],))
    pending = runtime.broker.enqueue(a, credential["id"], "/user")
    with pytest.raises(ValueError):
        runtime.broker.result(b, pending["request_id"])


def test_no_plaintext_fallback_without_native_host(runtime):
    runtime.native.connected = False
    with pytest.raises(RuntimeError):
        add_credential(runtime)
    assert runtime.broker.credentials() == []
