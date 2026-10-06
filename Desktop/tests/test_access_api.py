from types import SimpleNamespace

import pytest
from conftest import grant_token


def test_access_view_groups_old_scan_failures_without_rescanning_or_granting_access(client, owner, runtime):
    snapshot = {
        "coverage": {
            "denied": [
                {"path": "/var/folders/other-user/a", "reason": "Permission denied"},
                {"path": "/var/folders/other-user/b", "reason": "Permission denied"},
                {"path": "/home/sample/.ssh", "reason": "personal_path"},
            ],
            "boundaries_hit": [
                {"path": "/home/sample/cache", "boundary": "scope_excluded", "detail": "cache"}
            ],
        },
        "assets": [],
    }
    runtime.store.setting("inventory_snapshot", snapshot)
    assert client.get("/api/access").status_code == 401
    response = client.get("/api/access", headers=owner).json()
    assert response["full_disk_access"] == "not_determined"
    assert response["coverage"]["access"]["path_count"] == 2
    assert response["coverage"]["access"]["group_count"] == 1
    assert response["coverage"]["skipped"]["path_count"] == 2
    assert runtime.store.settings()["inventory_snapshot"] == snapshot
    assert [operation for operation, _ in runtime.native.calls] == ["file_access_identity"]
    inventory = client.get("/api/inventory", headers=owner).json()
    assert inventory["access"]["coverage"]["access"]["path_count"] == 2


@pytest.mark.parametrize("platform_name", ["darwin", "linux", "win32"])
def test_opening_settings_is_owner_only_and_never_reports_a_grant(
    client, owner, runtime, monkeypatch, platform_name,
):
    # Model the API's platform, not the Python process or the host's permissions.
    monkeypatch.setattr("adr_desktop.api.sys", SimpleNamespace(platform=platform_name))
    grant = runtime.create_grant("Agent", kind="agent", confirm_agent=True)
    agent = {"Authorization": "Bearer " + grant_token(runtime, grant)}
    body = {"target": "full_disk_access"}
    assert client.post("/api/access/settings", json=body).status_code == 401
    assert client.post("/api/access/settings", headers=agent, json=body).status_code == 401
    assert (
        client.post(
            "/api/access/settings",
            headers=owner,
            json={"target": "https://not-a-settings-pane.example"},
        ).status_code
        == 422
    )
    assert not runtime.native.calls
    response = client.post("/api/access/settings", headers=owner, json=body)
    if platform_name != "darwin":
        assert response.status_code == 503
        assert not runtime.native.calls
        return
    assert response.status_code == 200
    assert response.json()["grants_access"] is False
    assert response.json()["full_disk_access"] == "not_determined"
    assert runtime.native.calls[-1] == ("open_access_settings", body)


def test_access_setup_can_continue_without_native_ui_or_saved_scan(client, owner, runtime):
    runtime.native.connected = False
    response = client.get("/api/access", headers=owner).json()
    assert response["state"] == "not_scanned"
    assert response["can_continue"] is True
    assert response["setup"]["settings_available"] is False
    assert client.post("/api/access/settings", headers=owner, json={}).status_code == 503
    assert not runtime.native.calls


def test_all_coverage_details_can_be_paged_and_changed_snapshots_are_rejected(client, owner, runtime):
    snapshot = {"coverage": {"denied": [
        {"path": f"/var/folders/cache-{index}/Copied.app/private", "reason": "Permission denied"}
        for index in range(106)
    ]}}
    runtime.store.setting("inventory_snapshot", snapshot)
    runtime.store.setting("inventory_updated_at", "first-scan")
    assert client.get("/api/inventory/coverage").status_code == 401
    summary = client.get("/api/inventory", headers=owner).json()["access"]["coverage"]["access"]
    assert summary["group_count"] == 1 and summary["path_count"] == 106
    assert summary["groups"][0]["root"] == "/var/folders"
    seen = []
    offset = 0
    while offset is not None:
        response = client.get("/api/inventory/coverage", headers=owner, params={
            "section": "access", "root": "/var/folders", "offset": offset, "limit": 20,
            "revision": "first-scan",
        })
        assert response.status_code == 200
        page = response.json()
        seen.extend(item["path"] for item in page["items"])
        offset = page["next_offset"]
    assert len(seen) == len(set(seen)) == 106
    runtime.store.setting("inventory_updated_at", "second-scan")
    assert client.get("/api/inventory/coverage", headers=owner, params={
        "root": "/var/folders", "revision": "first-scan",
    }).status_code == 409
    assert runtime.store.settings()["inventory_snapshot"] == snapshot
