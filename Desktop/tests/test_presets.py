import copy
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import pytest
from conftest import grant_token

from adr_desktop.config import atomic_json
from adr_desktop.policy import evaluate, hook_output
from adr_desktop.presets import STARTER_ID, starter_catalog


@pytest.fixture
def mac_runtime(runtime, monkeypatch):
    monkeypatch.setattr("adr_desktop.presets.platform.system", lambda: "Darwin")
    monkeypatch.setattr("adr_desktop.runtime.installed", lambda harness, **kwargs: harness == "claude")
    return runtime


def by_key(preview, key):
    return next(item for item in preview["items"] if item["key"] == key)


def tool_event(path, harness="claude"):
    if harness == "claude":
        return {"tool_name": "Read", "tool_input": {"file_path": str(path)}, "cwd": str(Path.home())}
    return {"toolName": "view", "toolArgs": {"path": str(path)}, "cwd": str(Path.home())}


@pytest.mark.parametrize("system,count", [("Darwin", 13), ("Linux", 12), ("Windows", 0)])
def test_catalog_is_platform_specific_and_uses_the_current_home(runtime, monkeypatch, system, count):
    monkeypatch.setattr("adr_desktop.presets.platform.system", lambda: system)
    catalog = starter_catalog()
    assert len(catalog) == count
    assert all(Path(item["path"]).is_relative_to(Path.home()) for item in catalog)
    assert all(item["action"] == "block" for item in catalog)
    assert ("keychains" in {item["key"] for item in catalog}) == (system == "Darwin")


def test_preview_is_opt_in_read_only_and_does_not_open_credentials(mac_runtime):
    runtime = mac_runtime
    original = copy.deepcopy(runtime.policy)
    cache = (runtime.state_dir / "policy.json").read_bytes()
    with patch.object(Path, "open", side_effect=AssertionError("Do not open credential files")):
        preview = runtime.starter_protection()
    assert preview["available"] == 13
    assert preview["enabled"] is True
    assert runtime.policy == original
    assert runtime.policy["rules"] == []
    assert (runtime.state_dir / "policy.json").read_bytes() == cache
    assert not runtime.store.rows("SELECT * FROM audit")
    assert not runtime.native.calls


def test_adding_starter_is_atomic_idempotent_and_does_not_install_hooks(mac_runtime):
    runtime = mac_runtime
    result = runtime.add_starter_protection()
    assert result["added"] == result["covered"] == 13
    assert result["available"] == 0
    assert len(runtime.policy["rules"]) == 13
    assert all(rule["preset"] == STARTER_ID for rule in runtime.policy["rules"])
    original = copy.deepcopy(runtime.policy)
    cache = (runtime.state_dir / "policy.json").read_bytes()
    assert json.loads(cache) == original
    assert runtime.add_starter_protection()["added"] == 0
    assert runtime.policy == original
    assert (runtime.state_dir / "policy.json").read_bytes() == cache
    assert len(runtime.store.rows("SELECT * FROM audit")) == 1
    assert not runtime.native.calls
    assert not (Path.home() / ".claude/settings.json").exists()
    assert not (Path.home() / ".copilot/hooks").exists()


def test_concurrent_adds_do_not_duplicate_rules(mac_runtime):
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: mac_runtime.add_starter_protection(), range(2)))
    assert sorted(result["added"] for result in results) == [0, 13]
    assert len(mac_runtime.policy["rules"]) == 13
    assert len(mac_runtime.store.rows("SELECT * FROM audit")) == 1


def test_existing_ask_rule_is_kept_not_shadowed_by_a_default_block(mac_runtime):
    runtime = mac_runtime
    runtime.change_policy(
        add={
            "path": str(Path.home() / ".ssh"),
            "kind": "directory",
            "action": "ask",
            "label": "My SSH choice",
        }
    )
    original = copy.deepcopy(runtime.policy["rules"][0])
    assert by_key(runtime.starter_protection(), "ssh")["existing_action"] == "ask"
    assert runtime.add_starter_protection()["added"] == 12
    assert runtime.policy["rules"][0] == original
    assert evaluate(tool_event(Path.home() / ".ssh/id_work"), "claude", runtime.policy).decision == "ask"


def test_default_parent_folder_does_not_override_a_custom_child_rule(mac_runtime):
    runtime = mac_runtime
    key = Path.home() / ".ssh/id_work"
    runtime.change_policy(add={"path": str(key), "kind": "file", "action": "ask", "label": "Work key"})
    assert by_key(runtime.starter_protection(), "ssh")["state"] == "custom"
    assert runtime.add_starter_protection()["added"] == 12
    assert evaluate(tool_event(key), "claude", runtime.policy).decision == "ask"
    assert by_key(runtime.starter_protection(), "ssh")["state"] == "custom"


def test_directory_rule_is_not_claimed_covered_by_a_same_path_file_rule(mac_runtime):
    runtime = mac_runtime
    runtime.change_policy(add={"path": str(Path.home() / ".ssh"), "kind": "file", "action": "ask"})
    assert by_key(runtime.starter_protection(), "ssh")["state"] == "custom"
    assert runtime.add_starter_protection()["added"] == 12


def test_existing_alias_of_a_protected_folder_is_not_duplicated(mac_runtime):
    runtime = mac_runtime
    protected = Path.home() / ".ssh"
    protected.mkdir()
    alias = Path.home() / "keys-alias"
    alias.symlink_to(protected, target_is_directory=True)
    runtime.change_policy(add={"path": str(alias), "kind": "directory", "action": "block"})
    assert by_key(runtime.starter_protection(), "ssh")["state"] == "covered"
    assert runtime.add_starter_protection()["added"] == 12


def test_paused_rules_and_other_preferences_remain_unchanged(mac_runtime):
    runtime = mac_runtime
    runtime.change_policy(enabled=False, opaque_tools="block")
    settings = runtime.store.settings()
    result = runtime.add_starter_protection()
    assert result["enabled"] is False
    assert runtime.policy["enabled"] is False
    assert runtime.policy["opaque_tools"] == "block"
    assert runtime.store.settings() == settings
    assert evaluate(tool_event(Path.home() / ".ssh/id_work"), "claude", runtime.policy).decision == "pass"


@pytest.mark.parametrize("target", ["home", "root"])
def test_broad_symlink_is_skipped_instead_of_protecting_the_whole_home(mac_runtime, target):
    runtime = mac_runtime
    destination = Path.home() if target == "home" else Path(Path.home().anchor)
    (Path.home() / ".ssh").symlink_to(destination, target_is_directory=True)
    assert by_key(runtime.starter_protection(), "ssh")["state"] == "unavailable"
    assert runtime.add_starter_protection()["added"] == 12
    assert not any(rule.get("preset_key") == "ssh" for rule in runtime.policy["rules"])


def test_symlink_loop_and_unexpected_file_type_can_be_reviewed_without_breaking_preview(mac_runtime):
    runtime = mac_runtime
    (Path.home() / ".ssh").symlink_to(Path.home() / ".ssh")
    (Path.home() / ".aws").write_text("synthetic")
    preview = runtime.starter_protection()
    assert by_key(preview, "ssh")["state"] == "unavailable"
    assert by_key(preview, "aws")["state"] == "unavailable"
    assert runtime.add_starter_protection()["added"] == 11


def test_unresolvable_existing_rule_prevents_changes_but_preview_still_loads(mac_runtime):
    runtime = mac_runtime
    link = Path.home() / "custom-key"
    runtime.change_policy(add={"path": str(link), "kind": "file", "action": "ask"})
    link.symlink_to(link)
    before = copy.deepcopy(runtime.policy)
    preview = runtime.starter_protection()
    assert preview["review_required"] == 1
    assert preview["available"] == 0
    with pytest.raises(ValueError, match="unreadable path"):
        runtime.add_starter_protection()
    assert runtime.policy == before


def test_failed_cache_write_does_not_activate_or_partially_add_defaults(mac_runtime, monkeypatch):
    runtime = mac_runtime
    before = copy.deepcopy(runtime.policy)
    cache = (runtime.state_dir / "policy.json").read_bytes()

    def fail(*_args, **_kwargs):
        raise OSError("synthetic write failure")

    monkeypatch.setattr("adr_desktop.runtime.atomic_json", fail)
    with pytest.raises(OSError):
        runtime.add_starter_protection()
    assert runtime.policy == before
    assert (runtime.state_dir / "policy.json").read_bytes() == cache
    assert not runtime.store.rows("SELECT * FROM audit")


def test_capacity_limit_does_not_partially_apply_a_starter_set(mac_runtime):
    runtime = mac_runtime
    runtime.policy["rules"] = [
        {"id": str(i), "path": str(Path.home() / f"custom-{i}"), "kind": "file", "action": "ask"}
        for i in range(99)
    ]
    atomic_json(runtime.state_dir / "policy.json", runtime.policy)
    before = copy.deepcopy(runtime.policy)
    cache = (runtime.state_dir / "policy.json").read_bytes()
    with pytest.raises(ValueError, match="100-rule limit"):
        runtime.add_starter_protection()
    assert runtime.policy == before
    assert (runtime.state_dir / "policy.json").read_bytes() == cache


@pytest.mark.parametrize("harness", ["claude", "copilot"])
@pytest.mark.parametrize(
    "relative",
    [
        "Library/Keychains/login.keychain-db",
        ".ssh/id_work",
        ".gnupg/private-keys-v1.d/work.key",
        ".aws/sso/cache/example.json",
        ".config/gcloud/application_default_credentials.json",
        ".azure/msal_token_cache.json",
        ".kube/config",
        ".docker/config.json",
        ".git-credentials",
        ".config/git/credentials",
        ".npmrc",
        ".pypirc",
        ".netrc",
    ],
)
def test_starter_blocks_sensitive_paths_even_before_they_exist(mac_runtime, harness, relative):
    runtime = mac_runtime
    runtime.add_starter_protection()
    target = Path.home() / relative
    assert not target.exists()
    decision = evaluate(tool_event(target, harness), harness, runtime.policy)
    assert decision.decision == "deny"
    output = hook_output(decision, harness)
    assert output.get("hookSpecificOutput", output)["permissionDecision"] == "deny"
    assert (
        evaluate(tool_event(Path.home() / "project/src/main.py", harness), harness, runtime.policy).decision
        == "pass"
    )


@pytest.mark.parametrize("harness", ["claude", "copilot"])
def test_starter_is_enforced_by_the_offline_hook(mac_runtime, harness):
    runtime = mac_runtime
    runtime.add_starter_protection()
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "adr_desktop",
            "hook",
            "--harness",
            harness,
            "--state-dir",
            str(runtime.state_dir),
        ],
        input=json.dumps(tool_event(Path.home() / ".ssh/id_work", harness)),
        text=True,
        capture_output=True,
        timeout=6,
    )
    assert result.returncode == 0
    output = json.loads(result.stdout)
    assert output.get("hookSpecificOutput", output)["permissionDecision"] == "deny"


def test_starter_api_requires_owner_and_csrf(client, mac_runtime):
    runtime = mac_runtime
    assert client.get("/api/protection/starter").status_code == 401
    assert client.post("/api/protection/starter", json={}).status_code == 401
    csrf = client.post("/api/auth/bootstrap", json={"ticket": runtime.new_ticket()}).json()["csrf"]
    assert client.get("/api/protection/starter").json()["available"] == 13
    assert runtime.policy["rules"] == []
    assert client.post("/api/protection/starter", json={}).status_code == 403
    response = client.post("/api/protection/starter", json={}, headers={"X-ADR-CSRF": csrf})
    assert response.status_code == 200
    assert response.json()["added"] == 13


def test_starter_api_does_not_accept_client_supplied_paths(client, owner, mac_runtime):
    response = client.post("/api/protection/starter", headers=owner, json={"path": "/"})
    assert response.status_code == 422
    assert mac_runtime.policy["rules"] == []


def test_agent_grant_cannot_inspect_or_install_starter_rules(client, mac_runtime):
    runtime = mac_runtime
    grant = runtime.create_grant("Synthetic", str(Path.home() / "project"), [])
    headers = {"Authorization": "Bearer " + grant_token(runtime, grant)}
    assert client.get("/api/protection/starter", headers=headers).status_code == 401
    assert client.post("/api/protection/starter", headers=headers, json={}).status_code == 401
    assert runtime.policy["rules"] == []


def test_cross_origin_cannot_install_starter_rules(client, owner, mac_runtime):
    response = client.post(
        "/api/protection/starter",
        json={},
        headers={**owner, "Origin": "https://untrusted.example"},
    )
    assert response.status_code == 403
    assert mac_runtime.policy["rules"] == []
