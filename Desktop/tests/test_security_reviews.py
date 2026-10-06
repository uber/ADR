import json
import threading
import time
import uuid

import pytest
from conftest import sample_session

from adr_desktop.review_process import ReviewError
from adr_desktop.security_reviews import DEFAULTS, SecurityReviews, evidence_for, validate_report


class Driver:
    def __init__(self, *, paid=False, fail=False, tokens=200, wait=False):
        self.paid, self.fail, self.tokens, self.wait = paid, fail, tokens, wait
        self.calls = []
        self.entered = threading.Event()

    def available(self):
        return {"claude": True, "codex": True}

    def probe(self, provider, cancel):
        self.calls.append("probe")
        return {"account": "synthetic-account", "subscription": not self.paid, "quota": None}

    def run(self, provider, prompt, schema, settings, cancel, progress):
        self.calls.append("run")
        self.entered.set()
        if self.wait:
            cancel.wait(5)
            raise ReviewError("cancelled")
        progress({"tokens": self.tokens, "cost_usd": 0.01})
        if self.fail:
            raise ReviewError("cli_failed")
        return {"summary": "No supported finding in this synthetic evidence.", "findings": []}


def configure(runtime, **updates):
    return runtime.reviews.change_settings(
        updates, expected_revision=runtime.reviews.preferences()["revision"], confirm_data_share=True
    )


def session(runtime, content=None):
    runtime.store.ingest(sample_session(content=content))
    return runtime.store.one("SELECT id FROM sessions")["id"]


def finished(runtime):
    runtime.reviews.worker.join(timeout=5)
    assert not runtime.reviews.worker.is_alive()
    return runtime.reviews.status()["jobs"][0]


def test_disabled_default_and_owner_consent(client, runtime, owner):
    assert runtime.reviews.preferences()["background"] is False
    identifier = session(runtime)
    body = {"session_id": identifier, "request_id": str(uuid.uuid4())}
    assert client.post("/api/reviews/start", headers=owner, json=body).status_code == 400
    assert client.get("/api/reviews").status_code == 401
    assert (
        client.post(
            "/api/reviews/start", headers={"Authorization": "Bearer " + runtime.hook_token}, json=body
        ).status_code
        == 401
    )


def test_settings_revision_scope_and_validation(client, runtime, owner):
    settings = runtime.reviews.preferences()
    endpoint = "/api/reviews/settings"
    assert (
        client.patch(
            endpoint,
            headers=owner,
            json={
                "expected_revision": settings["revision"],
                "background": True,
            },
        ).status_code
        == 400
    )
    configure(runtime, projects=["/workspace/sample"])
    assert (
        client.patch(
            endpoint,
            headers=owner,
            json={
                "expected_revision": settings["revision"],
                "confirm_data_share": True,
            },
        ).status_code
        == 400
    )
    with pytest.raises(ValueError):
        configure(runtime, max_tokens=50000, daily_tokens=10000)
    with pytest.raises(ValueError):
        configure(runtime, max_tokens=True)


def test_success_reconciles_reservation_and_idempotency(client, runtime, owner):
    runtime.reviews.driver = Driver()
    configure(runtime)
    identifier = session(runtime)
    payload = {"session_id": identifier, "request_id": str(uuid.uuid4())}
    first = client.post("/api/reviews/start", headers=owner, json=payload)
    assert first.status_code == 200
    job = finished(runtime)
    assert job["state"] == "completed" and job["tokens"] == job["token_charge"] == 200
    assert job["coverage"]["total_messages"] == 2
    again = client.post("/api/reviews/start", headers=owner, json=payload)
    assert again.json()["id"] == first.json()["id"]
    assert runtime.reviews.driver.calls.count("run") == 1
    assert runtime.reviews.ledger()["tokens"] == 200


def test_failure_and_restart_keep_reservation(runtime):
    runtime.reviews.driver = Driver(fail=True)
    configure(runtime)
    runtime.reviews.start(session(runtime), str(uuid.uuid4()))
    job = finished(runtime)
    assert job["state"] == "failed" and job["token_charge"] == DEFAULTS["max_tokens"]
    runtime.store.execute("UPDATE security_review_jobs SET state='running'")
    restarted = SecurityReviews(runtime)
    try:
        assert restarted.status()["jobs"][0]["state"] == "interrupted"
        assert restarted.ledger()["tokens"] == DEFAULTS["max_tokens"]
    finally:
        restarted.close()


def test_explicit_paid_permission_and_no_silent_fallback(runtime):
    runtime.reviews.driver = Driver(paid=True)
    configure(runtime)
    identifier = session(runtime)
    runtime.reviews.start(identifier, str(uuid.uuid4()))
    job = finished(runtime)
    assert job["state"] == "failed" and job["token_charge"] == 0
    assert "run" not in runtime.reviews.driver.calls
    configure(runtime, allow_paid=True)
    runtime.reviews.start(identifier, str(uuid.uuid4()))
    assert finished(runtime)["state"] == "completed"


def test_cancel_and_budget_reservations_prevent_concurrent_or_unbounded_jobs(runtime):
    runtime.reviews.driver = Driver(wait=True)
    configure(runtime, daily_tokens=DEFAULTS["max_tokens"])
    identifier = session(runtime)
    request = runtime.reviews.start(identifier, str(uuid.uuid4()))
    assert runtime.reviews.driver.entered.wait(2)
    with pytest.raises(ValueError, match="already"):
        runtime.reviews.start(identifier, str(uuid.uuid4()))
    runtime.reviews.cancel_job(request["id"])
    assert finished(runtime)["state"] == "cancelled"
    with pytest.raises(ValueError, match="tokens"):
        runtime.reviews.start(identifier, str(uuid.uuid4()))


def test_reported_overshoot_counts_actual_usage_and_stops(runtime):
    runtime.reviews.driver = Driver(tokens=20000)
    configure(runtime)
    runtime.reviews.start(session(runtime), str(uuid.uuid4()))
    job = finished(runtime)
    assert job["state"] == "failed" and job["token_charge"] == 20000


def test_no_model_work_when_quota_is_unknown_in_spare_mode(runtime):
    runtime.reviews.driver = Driver()
    configure(runtime, mode="spare")
    runtime.reviews.start(session(runtime), str(uuid.uuid4()))
    assert finished(runtime)["state"] == "failed"
    assert "run" not in runtime.reviews.driver.calls


def test_idle_scheduler_requires_actual_idle_and_opted_in_project(runtime, monkeypatch):
    runtime.reviews.driver = Driver()
    configure(runtime, background=True, projects=["/workspace/sample"])
    identifier = session(runtime)
    monkeypatch.setattr(runtime.reviews, "idle", lambda _: False)
    runtime.reviews.tick()
    assert not runtime.reviews.active and not runtime.reviews.driver.calls
    monkeypatch.setattr(runtime.reviews, "idle", lambda _: True)
    runtime.reviews.tick()
    assert finished(runtime)["session_id"] == identifier
    runtime.reviews.tick()
    assert runtime.reviews.driver.calls.count("run") == 1


def test_saved_credential_evidence_never_enters_a_model_job(runtime):
    runtime.reviews.driver = Driver()
    configure(runtime)
    runtime.environment_vault.create("Synthetic", "SYNTHETIC")
    identifier = session(runtime, "The password is synthetic-private-password-789!")
    with pytest.raises(ValueError, match="credentials"):
        runtime.reviews.start(identifier, str(uuid.uuid4()))
    assert not runtime.reviews.driver.calls


def test_partial_evidence_and_unsupported_citations_are_not_clean_reports():
    payload = {
        "payload": {
            "chat_history": [
                {"role": "user", "content": "Large " * 30000},
                {"role": "assistant", "content": "Small synthetic evidence"},
            ]
        }
    }
    _, coverage, included = evidence_for(payload, 1000)
    assert coverage["partial"] and coverage["message_indexes"] == [1]
    finding = {
        "title": "Test",
        "category": "prompt_injection",
        "severity": "low",
        "confidence": "low",
        "message_index": 0,
        "evidence": "Large",
        "explanation": "Synthetic only",
        "suggestion": "Review the evidence",
    }
    with pytest.raises(ReviewError):
        validate_report({"summary": "Test", "findings": [finding]}, included)
    finding.update(message_index=1, evidence="Small synthetic evidence")
    assert validate_report({"summary": "Test", "findings": [finding]}, included)
    finding["evidence"] = "hallucinated"
    with pytest.raises(ReviewError):
        validate_report({"summary": "Test", "findings": [finding]}, included)


def test_hook_usage_is_metadata_only_and_cannot_change_preferences(client, runtime):
    headers = {"Authorization": "Bearer " + runtime.hook_token}
    response = client.post(
        "/api/hooks/review-usage",
        headers=headers,
        json={
            "rate_limits": {
                "five_hour": {"used_percentage": 25, "resets_at": time.time() + 3600},
                "seven_day": {"used_percentage": 40, "resets_at": time.time() + 86400},
            }
        },
    )
    assert response.status_code == 200
    assert runtime.reviews.quota("claude")["complete"]
    assert not runtime.reviews.preferences()["consented"]
    assert (
        client.patch(
            "/api/reviews/settings",
            headers=headers,
            json={
                "expected_revision": runtime.reviews.preferences()["revision"],
                "confirm_data_share": True,
            },
        ).status_code
        == 401
    )
    assert "review_preferences" in runtime.store.settings()
    assert "rate_limits" not in json.dumps(runtime.reviews.quota("claude"))


def test_history_deletion_removes_review_content_but_not_spent_budget(client, runtime, owner):
    runtime.reviews.driver = Driver()
    configure(runtime)
    runtime.reviews.start(session(runtime), str(uuid.uuid4()))
    assert finished(runtime)["report"] is not None
    spent = runtime.reviews.ledger()["tokens"]
    assert client.post("/api/history/delete", headers=owner).status_code == 200
    item = runtime.reviews.status()["jobs"][0]
    assert item["report"] is None and item["coverage"]["evidence_deleted"]
    assert runtime.reviews.ledger()["tokens"] == spent


def test_background_skips_unexportable_evidence_without_starving_other_sessions(runtime, monkeypatch):
    runtime.reviews.driver = Driver()
    runtime.environment_vault.create("Synthetic", "SYNTHETIC")
    configure(runtime, background=True, projects=["/workspace/sample"])
    bad = sample_session(session_id="bad", content="synthetic-private-password-789!")
    bad["timestamp"] = "2026-10-06T09:00:00Z"
    good = sample_session(session_id="good")
    runtime.store.ingest(bad)
    runtime.store.ingest(good)
    monkeypatch.setattr(runtime.reviews, "idle", lambda _: True)
    runtime.reviews.tick()
    assert runtime.reviews.status()["jobs"][0]["state"] == "skipped"
    assert runtime.reviews.ledger()["tokens"] == 0
    runtime.reviews.tick()
    assert finished(runtime)["state"] == "completed"
    assert runtime.reviews.driver.calls.count("run") == 1


def test_known_partial_capture_is_preserved_in_review_coverage():
    _, coverage, _ = evidence_for({"partial": True, "payload": sample_session()}, 12000)
    assert coverage["partial"] and coverage["capture_partial"]


def test_idempotency_key_cannot_switch_sessions(runtime):
    runtime.reviews.driver = Driver()
    configure(runtime)
    request_id = str(uuid.uuid4())
    runtime.reviews.start(session(runtime), request_id)
    finished(runtime)
    with pytest.raises(ValueError, match="another session"):
        runtime.reviews.start("different", request_id)
