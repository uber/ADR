import pytest
from conftest import grant_token

from adr_desktop.config import read_private_json
from adr_desktop.native import NativeTimedOut, NativeUnavailable


def saved(runtime):
    return runtime.environment_vault.create("Synthetic", "SYNTHETIC_TOKEN")


def test_storage_status_is_owner_only_and_metadata_only(client, owner, runtime):
    entry = saved(runtime)
    assert client.get("/api/vault/storage").status_code == 401
    response = client.get("/api/vault/storage", headers=owner)
    assert response.status_code == 200
    assert response.json()["backend"] == "local_encrypted"
    assert response.json()["entries"] == [
        {
            "id": entry["id"],
            "storage": "local_encrypted",
            "state": "available",
            "kind": "environment",
        }
    ]
    assert runtime.native.environment_values[entry["id"]] not in response.text
    assert not any(operation == "vault_migrate_legacy" for operation, _ in runtime.native.calls)


def test_migration_needs_owner_confirmation_and_only_registered_ids(client, owner, runtime):
    entry = saved(runtime)
    runtime.native.local_ids.clear()
    principal = runtime.create_grant("Agent", kind="agent", confirm_agent=True)
    agent = {"Authorization": "Bearer " + grant_token(runtime, principal)}
    body = {"ids": [entry["id"]], "confirm": True}
    assert client.post("/api/vault/migrate", json=body).status_code == 401
    assert client.post("/api/vault/migrate", headers=agent, json=body).status_code == 401
    assert client.post("/api/vault/migrate", headers=owner, json={"ids": body["ids"]}).status_code == 400
    assert (
        client.post(
            "/api/vault/migrate",
            headers=owner,
            json={"ids": ["0" * 32], "confirm": True},
        ).status_code
        == 400
    )
    assert not any(operation == "vault_migrate_legacy" for operation, _ in runtime.native.calls)
    response = client.post("/api/vault/migrate", headers=owner, json=body)
    assert response.status_code == 200
    assert response.json()["results"] == [{"id": entry["id"], "status": "migrated"}]
    assert response.json()["keychain_originals_retained"] is True
    assert runtime.native.environment_values[entry["id"]] not in response.text
    assert (
        client.post("/api/vault/migrate", headers=owner, json=body).json()["results"][0]["status"]
        == "already_local"
    )
    assert client.get("/api/vault/storage", headers=owner).json()["entries"][0]["state"] == "available"


@pytest.mark.parametrize("ids", [["invalid"], ["a" * 32, "a" * 32], []])
def test_invalid_migration_is_rejected_without_native_work(client, owner, runtime, ids):
    assert (
        client.post(
            "/api/vault/migrate",
            headers=owner,
            json={"ids": ids, "confirm": True},
        ).status_code
        == 422
    )
    assert not runtime.native.calls


def test_unavailable_storage_and_uncertain_migration_are_not_reported_as_success(
    client, owner, runtime, monkeypatch
):
    entry = saved(runtime)
    runtime.native.connected = False
    assert client.get("/api/vault/storage", headers=owner).json()["available"] is False
    runtime.native.connected = True
    original = runtime.native.call

    def slow(operation, *args, **kwargs):
        if operation == "vault_migrate_legacy":
            raise NativeTimedOut("synthetic")
        return original(operation, *args, **kwargs)

    monkeypatch.setattr(runtime.native, "call", slow)
    result = client.post(
        "/api/vault/migrate",
        headers=owner,
        json={"ids": [entry["id"]], "confirm": True},
    )
    assert result.status_code == 503
    assert "Refresh vault storage" in result.json()["detail"]
    assert not runtime.store.rows("SELECT * FROM audit WHERE kind='vault_storage_migrated'")
    assert runtime.environment_vault.entries()[0]["state"] == "active"


def test_vault_activity_contains_outcomes_not_commands_or_output(client, owner, runtime, tmp_path):
    saved(runtime)
    grant = runtime.create_grant("Agent", kind="agent", confirm_agent=True)
    principal = runtime.store.one("SELECT * FROM grants WHERE id=?", (grant["id"],))
    runtime.environment_vault.execute(principal, "printf unique-private-command", str(tmp_path))
    response = client.get("/api/environment-credentials", headers=owner)
    assert response.json()["recent_runs"][0]["agent"] == "Agent"
    assert response.json()["recent_runs"][0]["state"] == "finished"
    assert "unique-private-command" not in response.text
    assert "synthetic result" not in response.text


def test_uncertain_save_is_recovered_with_same_id_without_reentry_or_delete(
    client, owner, runtime, monkeypatch
):
    original = runtime.native.call

    def uncertain(operation, arguments=None, timeout=30):
        result = original(operation, arguments, timeout)
        if operation == "environment_prompt_store":
            raise NativeUnavailable("local_vault_write_uncertain")
        return result

    monkeypatch.setattr(runtime.native, "call", uncertain)
    with pytest.raises(NativeUnavailable, match="not confirmed"):
        runtime.environment_vault.create("Uncertain", "UNCERTAIN_TOKEN")
    entry = runtime.environment_vault.entries()[0]
    assert entry["state"] == "unconfirmed"
    assert entry["id"] in runtime.native.local_ids
    monkeypatch.setattr(runtime.native, "call", original)
    assert (
        client.post(
            "/api/vault/recover",
            headers=owner,
            json={"ids": [entry["id"]]},
        ).status_code
        == 400
    )
    response = client.post(
        "/api/vault/recover",
        headers=owner,
        json={"ids": [entry["id"]], "confirm": True},
    )
    assert response.json()["items"] == [{"id": entry["id"], "recovered": True}]
    assert runtime.environment_vault.entries()[0]["id"] == entry["id"]
    assert runtime.environment_vault.entries()[0]["state"] == "active"
    assert read_private_json(runtime.state_dir / "vault-aliases.json")["names"] == ["UNCERTAIN_TOKEN"]
    assert sum(op == "environment_prompt_store" for op, _ in runtime.native.calls) == 1
    assert not any(op == "vault_delete" for op, _ in runtime.native.calls)


def test_missing_value_can_be_reentered_without_replacing_its_metadata_id(client, owner, runtime):
    entry = saved(runtime)
    runtime.native.local_ids.clear()
    response = client.post(
        "/api/vault/finish-save",
        headers=owner,
        json={"ids": [entry["id"]], "confirm": True},
    )
    assert response.status_code == 200
    assert response.json()["items"] == [{"id": entry["id"], "recovered": True}]
    assert len(runtime.environment_vault.entries()) == 1
    assert runtime.environment_vault.entries()[0]["id"] == entry["id"]
    # An available copy can only be recovered, never overwritten by this action.
    assert (
        client.post(
            "/api/vault/finish-save",
            headers=owner,
            json={"ids": [entry["id"]], "confirm": True},
        ).status_code
        == 409
    )


def test_output_protection_ids_do_not_expand_scoped_environment_injection(runtime, tmp_path):
    first = runtime.environment_vault.create("First", "FIRST_TOKEN")
    second = runtime.environment_vault.create("Second", "SECOND_TOKEN")
    service = runtime.broker.create(
        {
            "name": "Service",
            "origin": "https://example.com",
            "auth_type": "basic",
            "username": "synthetic",
            "allowed_paths": ["/"],
        }
    )
    grant = runtime.create_grant(
        "Selected",
        str(tmp_path),
        [first["id"]],
        kind="execution",
        confirm_execution=True,
        approval_mode="automatic",
        confirm_automatic=True,
    )
    principal = runtime.store.one("SELECT * FROM grants WHERE id=?", (grant["id"],))
    runtime.environment_vault.execute(principal, "printf safe", str(tmp_path))
    arguments = next(args for op, args in runtime.native.calls if op == "environment_execute")
    assert arguments["ids"] == [first["id"]]
    assert set(arguments["protection_environment_ids"]) == {first["id"], second["id"]}
    assert arguments["protection_service_ids"] == [service["id"]]


def test_cli_migration_requires_native_owner_approval_and_rejects_web_requests(client, runtime, monkeypatch):
    entry = saved(runtime)
    runtime.native.local_ids.clear()
    body = {"confirm": True}
    assert (
        client.post(
            "/api/vault/enroll-migration",
            json=body,
            headers={"Origin": "http://127.0.0.1:48321"},
        ).status_code
        == 403
    )
    assert client.post("/api/vault/enroll-migration", json={}).status_code == 400
    assert client.post("/api/vault/enroll-migration", json=body).status_code == 403
    assert not any(op == "vault_migrate_legacy" for op, _ in runtime.native.calls)
    runtime.last_enrollment = 0
    original = runtime.native.call

    def approve(operation, *args, **kwargs):
        return (
            {"allowed": True}
            if operation == "approve_vault_migration"
            else original(operation, *args, **kwargs)
        )

    monkeypatch.setattr(runtime.native, "call", approve)
    response = client.post("/api/vault/enroll-migration", json=body)
    assert response.status_code == 200
    assert response.json()["results"] == [{"id": entry["id"], "status": "migrated"}]
    assert runtime.native.environment_values[entry["id"]] not in response.text
