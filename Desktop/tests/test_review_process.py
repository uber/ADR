import os
import sys
import threading
import time
from pathlib import Path

import pytest

from adr_desktop.review_process import (
    JsonProcess,
    LocalReviewDriver,
    ReviewError,
    child_environment,
    usage_tokens,
)
from adr_desktop.security_reviews import DEFAULTS, REPORT_SCHEMA

FIXTURE = Path(__file__).parent / "fixtures" / "review_cli.py"


def driver(scenario="success"):
    return LocalReviewDriver(
        {kind: [sys.executable, str(FIXTURE), kind, scenario] for kind in ("claude", "codex")}
    )


@pytest.mark.parametrize("provider,expected", [("claude", 160), ("codex", 120)])
def test_real_subprocess_protocols_complete_and_report_usage(provider, expected):
    runner = driver()
    probe = runner.probe(provider, threading.Event())
    assert probe["subscription"] is True
    assert "synthetic@example.invalid" not in str(probe)
    if provider == "codex":
        assert probe["quota"]["complete"]
        assert len(probe["quota"]["windows"]) == 2
    updates = []
    report = runner.run(
        provider, "UNTRUSTED EVIDENCE: synthetic", REPORT_SCHEMA, DEFAULTS, threading.Event(), updates.append
    )
    assert report["findings"] == []
    assert max(update["tokens"] for update in updates if update.get("tokens") is not None) == expected


@pytest.mark.parametrize(
    "provider,scenario",
    [
        ("claude", "tool"),
        ("codex", "tool"),
        ("codex", "approval"),
    ],
)
def test_tool_or_approval_request_stops_the_review(provider, scenario):
    with pytest.raises(ReviewError) as raised:
        driver(scenario).run(
            provider, "UNTRUSTED EVIDENCE", REPORT_SCHEMA, DEFAULTS, threading.Event(), lambda _: None
        )
    assert raised.value.code == "unsafe_tool"


def test_claude_terminal_error_is_not_a_completed_review():
    with pytest.raises(ReviewError) as raised:
        driver("failed").run(
            "claude", "UNTRUSTED EVIDENCE", REPORT_SCHEMA, DEFAULTS, threading.Event(), lambda _: None
        )
    assert raised.value.code == "cli_failed"


def test_codex_does_not_send_evidence_when_mcp_is_still_present():
    with pytest.raises(ReviewError) as raised:
        driver("mcp").run(
            "codex", "UNTRUSTED EVIDENCE", REPORT_SCHEMA, DEFAULTS, threading.Event(), lambda _: None
        )
    assert raised.value.code == "isolation_unavailable"


@pytest.mark.parametrize("scenario,code", [("hang", "timeout"), ("oversize", "output_limit")])
def test_process_time_and_output_limits(tmp_path, scenario, code):
    with JsonProcess(
        [sys.executable, str(FIXTURE), "claude", scenario], tmp_path, threading.Event(), seconds=0.5
    ) as process:
        with pytest.raises(ReviewError) as raised:
            process.read()
        assert raised.value.code == code
    assert process.process.poll() is not None


def test_cancel_interrupts_waiting_process_and_blocked_input(tmp_path):
    cancel = threading.Event()
    with JsonProcess([sys.executable, str(FIXTURE), "claude", "hang"], tmp_path, cancel) as process:
        timer = threading.Timer(0.1, cancel.set)
        timer.start()
        with pytest.raises(ReviewError) as raised:
            process.text("x" * (512 * 1024))
        timer.join()
        assert raised.value.code == "cancelled"
    assert process.process.poll() is not None


@pytest.mark.skipif(os.name == "nt", reason="POSIX lifetime pipe")
def test_lifetime_pipe_loss_stops_cli_even_without_parent_cleanup(tmp_path):
    with JsonProcess(
        [sys.executable, str(FIXTURE), "claude", "announce_hang"],
        tmp_path,
        threading.Event(),
    ) as process:
        child = process.read()["pid"]
        os.close(process.lifetime)
        process.lifetime = None
        process.process.wait(timeout=3)
        deadline = time.monotonic() + 3
        while True:
            try:
                os.kill(child, 0)
            except ProcessLookupError:
                break
            if time.monotonic() > deadline:
                pytest.fail("The review CLI survived loss of its parent lifetime pipe")
            time.sleep(0.02)


def test_child_does_not_inherit_unrelated_connector_secrets(monkeypatch):
    monkeypatch.setenv("ADR_OWNER_TOKEN", "synthetic-not-a-secret")
    monkeypatch.setenv("UNRELATED_CONNECTOR_KEY", "synthetic-not-a-secret")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "synthetic-auth")
    env = child_environment()
    assert "ADR_OWNER_TOKEN" not in env and "UNRELATED_CONNECTOR_KEY" not in env
    assert env["ANTHROPIC_API_KEY"] == "synthetic-auth"


def test_invalid_usage_cannot_release_budget():
    assert usage_tokens({"input_tokens": -100}, "claude") is None
    assert usage_tokens({"input_tokens": True}, "claude") is None
    assert usage_tokens({}, "codex") is None
    assert usage_tokens({"inputTokens": 100, "cachedInputTokens": 80, "outputTokens": 20}, "codex") == 120
    assert usage_tokens({"inputTokens": 100, "outputTokens": 20, "totalTokens": 150}, "codex") == 150
