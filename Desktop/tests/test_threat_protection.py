"""Owner control, offline publication, local findings, and audited denials."""

import copy
import hashlib
import threading
from pathlib import Path

import pytest
from conftest import grant_token

from adr_desktop.config import canonical, read_private_json
from adr_desktop.policy import Decision
from adr_desktop.protection import evaluate_operation
from adr_desktop.threat_feed import BUNDLED_FEED_ID, compile_generation
from adr_desktop.threat_protection import ThreatStateConflict, initialize_threats

BODY = b"---\nname: harmless-fixture\n---\nInert local test; never execute.\n"
HASH = hashlib.sha256(BODY).hexdigest()
REFERENCE = "https://example.invalid/fixture-disclosure"


def feed(revision=1, *, revoked=False, endpoint=False):
    indicator = {
        "id": "fixture-skill", "status": "revoked" if revoked else "active", "kind": "skill_sha256",
        "target": {"sha256": HASH}, "summary": "Harmless fixture, not a real malicious artifact.",
        "references": [REFERENCE],
    }
    if revoked:
        indicator["revoked_reason"] = "Synthetic revocation test."
    if endpoint:
        indicator.update(
            id="fixture-endpoint", kind="mcp_endpoint",
            target={"url": "https://fixture-server.invalid/mcp"},
        )
    return {
        "schema_version": 1, "feed_id": "fixture-custom", "revision": revision,
        "published_at": "2026-10-05T00:00:00Z", "indicators": [indicator],
    }


def import_feed(runtime, document=None):
    return runtime.threats.import_feed(
        canonical(document or feed()), expected_revision=runtime.policy["revision"], confirm=True,
    )


def skill_fixture(tmp_path):
    path = tmp_path / "skill" / "SKILL.md"
    path.parent.mkdir()
    path.write_bytes(BODY)
    return path


def skill_event(path):
    return {
        "tool_name": "Read", "tool_input": {"file_path": str(path)},
        "cwd": str(path.parent), "session_id": "fixture-session",
    }


def owner_fields(runtime, document=None):
    return {"document": canonical(document or feed()), "expected_revision": runtime.policy["revision"]}


@pytest.mark.parametrize("enabled", [True, False])
def test_toggle_is_independent_and_embedded_policy_remains_valid(runtime, client, owner, enabled):
    original = copy.deepcopy(runtime.policy)
    response = client.patch(
        "/api/threats", headers=owner,
        json={"enabled": enabled, "expected_revision": original["revision"]},
    )
    assert response.status_code == 200 and response.json()["enabled"] is enabled
    saved = read_private_json(runtime.state_dir / "policy.json")
    assert saved["threats"]["enabled"] is enabled
    assert saved["revision"] != original["revision"]
    for key in ("enabled", "rules", "strict_execution", "opaque_tools"):
        assert saved[key] == original[key]
    assert compile_generation(saved["threats"]["generation"]).digest == response.json()["feed"]["generation"]


def test_baseline_reports_actual_not_fabricated_skill_coverage(client, owner):
    response = client.get("/api/threats", headers=owner)
    assert response.status_code == 200
    status = response.json()
    assert status["enabled"] is True
    assert status["feed"]["counts"] == {
        "file_sha256": 1, "skill_sha256": 0, "npm": 2, "pypi": 1,
        "mcp_endpoint": 0, "package_versions": 8, "total": 4,
    }
    assert status["scan"]["state"] == "not_run" and not status["blocks"]
    assert status["feed"]["has_custom"] is False


@pytest.mark.parametrize("authority", ["anonymous", "agent", "hook"])
def test_only_owner_can_read_or_change_threat_intelligence(client, runtime, authority):
    grant = runtime.create_grant("Fixture agent", kind="agent", confirm_agent=True)
    token = {"anonymous": "", "agent": grant_token(runtime, grant), "hook": runtime.hook_token}[authority]
    headers = {"Authorization": "Bearer " + token} if token else {}
    before = (runtime.state_dir / "policy.json").read_bytes()
    requests = [
        ("GET", "/api/threats", None),
        ("PATCH", "/api/threats", {"enabled": False, "expected_revision": runtime.policy["revision"]}),
        ("POST", "/api/threats/check", {}),
        ("POST", "/api/threats/import/preview", owner_fields(runtime)),
        ("POST", "/api/threats/import", {**owner_fields(runtime), "confirm": True}),
    ]
    for method, route, body in requests:
        assert client.request(method, route, headers=headers, json=body).status_code == 401
    assert (runtime.state_dir / "policy.json").read_bytes() == before


def test_browser_toggle_requires_csrf(client, runtime):
    response = client.post("/api/auth/bootstrap", json={"ticket": runtime.new_ticket()})
    assert response.status_code == 200
    body = {"enabled": False, "expected_revision": runtime.policy["revision"]}
    assert client.patch("/api/threats", json=body).status_code == 403
    assert runtime.policy["threats"]["enabled"] is True
    assert client.patch("/api/threats", json=body, headers={
        "X-ADR-CSRF": response.json()["csrf"],
    }).status_code == 200


def test_preview_is_read_only_and_import_adds_to_baseline(client, owner, runtime):
    before = (runtime.state_dir / "policy.json").read_bytes()
    fields = owner_fields(runtime)
    preview = client.post("/api/threats/import/preview", headers=owner, json=fields)
    assert preview.status_code == 200
    assert preview.json()["active_indicators"] == 1
    assert preview.json()["counts"]["total"] == 5
    assert (runtime.state_dir / "policy.json").read_bytes() == before
    assert client.post("/api/threats/import", headers=owner, json=fields).status_code == 400
    response = client.post("/api/threats/import", headers=owner, json={**fields, "confirm": True})
    assert response.status_code == 200
    assert response.json()["feed"]["counts"]["skill_sha256"] == 1
    assert response.json()["feed"]["feeds"][0]["feed_id"] == BUNDLED_FEED_ID
    assert response.json()["feed"]["has_custom"] is True


@pytest.mark.parametrize("malformation", ["syntax", "duplicate-key", "taxonomy", "namespace", "oversize"])
def test_rejected_feed_preserves_accepted_policy(client, owner, runtime, malformation):
    import_feed(runtime)
    before = (runtime.state_dir / "policy.json").read_bytes()
    invalid = {
        "syntax": "{bad json}",
        "duplicate-key": canonical(feed()).replace('"revision":1', '"revision":1,"revision":2'),
        "taxonomy": canonical({"threat_framework": {"tactics": {}}}),
        "namespace": canonical({**feed(), "feed_id": BUNDLED_FEED_ID}),
        "oversize": "x" * (512 * 1024 + 1),
    }[malformation]
    response = client.post("/api/threats/import", headers=owner, json={
        "document": invalid, "expected_revision": runtime.policy["revision"], "confirm": True,
    })
    assert response.status_code in (400, 422)
    assert (runtime.state_dir / "policy.json").read_bytes() == before


def test_stale_import_cannot_overwrite_another_owner_change(client, owner, runtime):
    fields = owner_fields(runtime)
    runtime.change_policy(enabled=False)
    before = (runtime.state_dir / "policy.json").read_bytes()
    response = client.post("/api/threats/import", headers=owner, json={**fields, "confirm": True})
    assert response.status_code == 409
    assert (runtime.state_dir / "policy.json").read_bytes() == before
    assert runtime.policy["enabled"] is False


def test_atomic_publication_failure_keeps_memory_and_disk(runtime, monkeypatch):
    before = (runtime.state_dir / "policy.json").read_bytes()
    original = copy.deepcopy(runtime.policy)

    def unavailable(*_args, **_kwargs):
        raise OSError("synthetic publication failure")

    monkeypatch.setattr("adr_desktop.runtime.atomic_json", unavailable)
    with pytest.raises(OSError):
        import_feed(runtime)
    assert runtime.policy == original
    assert (runtime.state_dir / "policy.json").read_bytes() == before


@pytest.mark.parametrize("broken_bundle", [False, True])
def test_restart_preserves_custom_feed_disabled_choice_and_last_good(runtime, monkeypatch, broken_bundle):
    import_feed(runtime)
    runtime.threats.change_settings(enabled=False, expected_revision=runtime.policy["revision"])
    previous = copy.deepcopy(runtime.policy["threats"])
    if broken_bundle:
        def invalid():
            raise ValueError("synthetic malformed bundle")
        monkeypatch.setattr("adr_desktop.threat_protection.load_bundled_feed", invalid)
    restored, warning = initialize_threats(previous)
    assert restored == previous
    assert bool(warning) is broken_bundle


def test_custom_revocation_does_not_remove_bundled_intelligence(runtime, tmp_path):
    path = skill_fixture(tmp_path)
    import_feed(runtime)
    assert evaluate_operation(
        skill_event(path), "claude", runtime.policy, state_dir=runtime.state_dir,
    ).artifact
    status = import_feed(runtime, feed(revision=2, revoked=True))
    assert status["feed"]["counts"]["total"] == 4
    assert status["feed"]["counts"]["package_versions"] == 8
    assert evaluate_operation(
        skill_event(path), "claude", runtime.policy, state_dir=runtime.state_dir,
    ).decision == "pass"


@pytest.mark.parametrize("mutation", ["none", "pass", "wrong-generation", "wrong-label", "wrong-kind"])
def test_only_valid_feature_denials_are_recorded(client, runtime, tmp_path, mutation):
    path = skill_fixture(tmp_path)
    import_feed(runtime)
    decision = evaluate_operation(skill_event(path), "claude", runtime.policy, state_dir=runtime.state_dir)
    body = {"harness": "claude", **decision.as_dict()}
    if mutation == "pass":
        body["decision"] = "pass"
    elif mutation == "wrong-generation":
        body["artifact"]["generation"] = "0" * 64
    elif mutation == "wrong-label":
        body["artifact"]["target_display"] = "Untrusted raw command text must not be saved"
    elif mutation == "wrong-kind":
        body["artifact"]["kind"] = "file_sha256"
    response = client.post("/api/hooks/events", headers={
        "Authorization": "Bearer " + runtime.hook_token,
    }, json=body)
    assert response.status_code == 200
    records = runtime.threats.status()["blocks"]
    assert len(records) == (1 if mutation == "none" else 0)
    assert BODY.decode() not in canonical(records)
    assert "Untrusted raw command" not in canonical(records)


def test_previous_accepted_generation_can_report_late_hook_without_changing_enforcement(runtime, tmp_path):
    path = skill_fixture(tmp_path)
    import_feed(runtime)
    old = evaluate_operation(skill_event(path), "claude", runtime.policy, state_dir=runtime.state_dir)
    import_feed(runtime, feed(revision=2, revoked=True))
    assert runtime.threats.record_block(old, harness="claude", source="hook")
    assert runtime.threats.status()["blocks"][0]["generation"] == old.artifact["generation"]
    assert evaluate_operation(
        skill_event(path), "claude", runtime.policy, state_dir=runtime.state_dir,
    ).decision == "pass"


@pytest.mark.parametrize("duplicate_asset", [False, True])
def test_installed_check_uses_bytes_preserves_unique_inventory_link_and_never_claims_block(
    client, owner, runtime, duplicate_asset,
):
    root = Path.home() / ".claude/skills/harmless-fixture"
    root.mkdir(parents=True)
    manifest = root / "SKILL.md"
    manifest.write_bytes(BODY)
    asset = {"asset_id": "fixture-asset", "kind": "skill", "name": "Fixture", "install_path": str(root)}
    runtime.store.setting("inventory_snapshot", {
        "assets": [asset, *([{**asset, "asset_id": "other-asset"}] if duplicate_asset else [])],
    })
    import_feed(runtime)
    response = client.post("/api/threats/check", headers=owner, json={})
    assert response.status_code == 200
    status = response.json()
    assert status["scan"]["checked_items"] >= 1
    assert len(status["scan"]["findings"]) == 1
    finding = status["scan"]["findings"][0]
    assert finding["inventory_asset_id"] == (None if duplicate_asset else "fixture-asset")
    assert finding["location"] == str(manifest.resolve())
    assert status["blocks"] == []
    assert manifest.read_bytes() == BODY
    assert BODY.decode() not in canonical(status)
    import_feed(runtime, feed(revision=2))
    assert runtime.threats.status()["scan"]["stale"] is True


def test_check_does_not_accept_arbitrary_paths_or_run_twice(client, owner, runtime):
    assert client.post(
        "/api/threats/check", headers=owner, json={"path": "/"},
    ).status_code == 422
    runtime.threats.check_lock.acquire()
    try:
        response = client.post("/api/threats/check", headers=owner, json={})
        assert response.status_code == 409
        assert runtime.threats.status()["scan"]["state"] == "not_run"
    finally:
        runtime.threats.check_lock.release()


@pytest.mark.parametrize("source", ["hook", "approval", "vault"])
def test_normal_pass_or_unrelated_file_deny_is_not_threat_activity(runtime, source):
    for decision in (Decision(), Decision(decision="deny", reason_code="protected_path")):
        assert not runtime.threats.record_block(decision, harness="codex", source=source)
    assert runtime.threats.status()["blocks"] == []


def test_approval_recheck_cannot_override_a_new_malicious_hash(client, runtime, tmp_path, monkeypatch):
    path = skill_fixture(tmp_path)
    runtime.change_policy(add={"path": str(path), "action": "ask", "kind": "file"})
    original = runtime.native.call

    def approve(operation, arguments=None, timeout=30):
        if operation == "approve_tool":
            import_feed(runtime)
            return {"allowed": True}
        return original(operation, arguments, timeout=timeout)

    monkeypatch.setattr(runtime.native, "call", approve)
    response = client.post("/api/hooks/approve", headers={
        "Authorization": "Bearer " + runtime.hook_token,
    }, json={"harness": "codex", "event": skill_event(path)})
    assert response.status_code == 200
    assert response.json() == {"allowed": False, "reason_code": "known_malicious_artifact"}
    assert runtime.threats.status()["blocks"][0]["source"] == "approval"


def test_invalid_saved_generation_is_not_replaced_with_empty_intelligence(runtime):
    previous = copy.deepcopy(runtime.policy["threats"])
    previous["generation"]["digest"] = "0" * 64
    with pytest.raises(ValueError):
        initialize_threats(previous)
    with pytest.raises(ThreatStateConflict):
        runtime.threats.change_settings(enabled=False, expected_revision="f" * 32)


def test_baseline_growth_retains_last_good_generation_when_combined_limit_is_exceeded(runtime, monkeypatch):
    import_feed(runtime)
    previous = copy.deepcopy(runtime.policy["threats"])
    baseline = previous["generation"]["feeds"][0]
    monkeypatch.setattr("adr_desktop.threat_protection.load_bundled_feed", lambda: baseline)

    def too_large(*_args, **_kwargs):
        raise ValueError("Too many combined artifact intelligence indicators")

    # Composition failure after validating the saved generation, not corrupted
    # trusted policy: the owner must still be able to open the app and trim it.
    monkeypatch.setattr("adr_desktop.threat_protection.compose_generation", too_large)
    restored, warning = initialize_threats(previous)
    assert restored == previous and warning


def test_baseline_refresh_changes_policy_revision_without_changing_other_preferences(runtime, monkeypatch):
    original = copy.deepcopy(runtime.policy)
    baseline = copy.deepcopy(original["threats"]["generation"]["feeds"][0])
    baseline["revision"] += 1
    monkeypatch.setattr("adr_desktop.threat_protection.load_bundled_feed", lambda: baseline)
    restored = runtime._load_policy()
    assert restored["revision"] != original["revision"]
    assert restored["threats"]["generation"]["digest"] != original["threats"]["generation"]["digest"]
    for key in ("enabled", "rules", "strict_execution", "opaque_tools"):
        assert restored[key] == original[key]


def test_baseline_growth_cannot_publish_a_policy_too_large_for_the_offline_reader(runtime, monkeypatch):
    original = copy.deepcopy(runtime.policy)
    baseline = copy.deepcopy(original["threats"]["generation"]["feeds"][0])
    baseline["revision"] += 1
    baseline["indicators"].append({
        **baseline["indicators"][0], "id": "additional-fixture-record",
        "summary": "Additional inert metadata used to exercise the total policy size budget.",
    })
    monkeypatch.setattr("adr_desktop.threat_protection.load_bundled_feed", lambda: baseline)
    monkeypatch.setattr("adr_desktop.runtime.MAX_POLICY_BYTES", len(canonical(original).encode()) + 192)
    restored = runtime._load_policy()
    assert restored["threats"]["generation"] == original["threats"]["generation"]
    assert "last accepted" in runtime.threat_feed_warning


def test_new_generation_receipt_waits_for_atomic_publication(runtime, tmp_path, monkeypatch):
    from adr_desktop.threat_feed import compose_generation

    path = skill_fixture(tmp_path)
    candidate = copy.deepcopy(runtime.policy)
    candidate["threats"]["generation"] = compose_generation(
        candidate["threats"]["generation"]["feeds"][0], feed(),
    )
    decision = evaluate_operation(skill_event(path), "claude", candidate, state_dir=runtime.state_dir)
    assert decision.artifact
    original = __import__("adr_desktop.runtime", fromlist=["atomic_json"]).atomic_json
    submitted, finished, receipts, workers = threading.Event(), threading.Event(), [], []

    def publish_then_report(destination, value):
        original(destination, value)

        def report():
            submitted.set()
            receipts.append(runtime.threats.record_block(decision, harness="claude", source="hook"))
            finished.set()

        worker = threading.Thread(target=report)
        workers.append(worker)
        worker.start()
        assert submitted.wait(1)
        assert not finished.wait(0.05), "A receipt must wait for the publication lock"

    monkeypatch.setattr("adr_desktop.runtime.atomic_json", publish_then_report)
    import_feed(runtime)
    assert finished.wait(2)
    for worker in workers:
        worker.join(timeout=2)
    assert receipts == [True]
    assert runtime.threats.status()["blocks"][0]["indicator_id"] == "fixture-custom/fixture-skill"


def test_approval_cannot_expire_during_final_artifact_check_and_still_pass(
    client, runtime, tmp_path, monkeypatch,
):
    import time
    from types import SimpleNamespace

    from adr_desktop import api

    path = skill_fixture(tmp_path)
    runtime.change_policy(add={"path": str(path), "action": "ask", "kind": "file"})
    clock, calls = [time.monotonic()], []
    original = api.evaluate_operation

    def check(*args, **kwargs):
        decision = original(*args, **kwargs)
        calls.append(decision)
        if len(calls) == 3:
            clock[0] += api.APPROVAL_TIMEOUT_SECONDS + 1
        return decision

    monkeypatch.setattr(api, "time", SimpleNamespace(monotonic=lambda: clock[0], time=time.time))
    monkeypatch.setattr(api, "evaluate_operation", check)
    monkeypatch.setattr(runtime.native, "call", lambda *_args, **_kwargs: {"allowed": True})
    response = client.post("/api/hooks/approve", headers={
        "Authorization": "Bearer " + runtime.hook_token,
    }, json={"harness": "codex", "event": skill_event(path)})
    assert response.json() == {"allowed": False, "reason_code": "approval_expired"}
    assert len(calls) == 3
