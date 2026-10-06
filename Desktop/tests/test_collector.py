import json
from datetime import datetime, timezone
from unittest.mock import Mock

import pytest
from adr_sensor.observer import AgentObserver
from adr_sensor.parsers.claude_parser import ClaudeParser

from adr_desktop.collector import capture_worker


@pytest.mark.parametrize("seconds", [300, 900, 1800, 3600])
@pytest.mark.parametrize("recording", [True, False])
def test_loop_waits_selected_minutes_and_does_not_scan_when_paused(runtime, monkeypatch, seconds, recording):
    collector = runtime.collector
    runtime.store.setting("interval_seconds", seconds)
    runtime.store.setting("recording", recording)
    events = []

    def wait(interval):
        events.append(("wait", interval))
        collector.stop_event.set()

    monkeypatch.setattr(collector, "scan", lambda: events.append(("scan",)))
    monkeypatch.setattr(collector, "wake", Mock(wait=Mock(side_effect=wait)))
    collector._loop()
    assert events == ([("scan",)] if recording else []) + [("wait", seconds)]


def test_resume_wakes_collection_immediately_without_waiting_for_interval(runtime):
    assert not runtime.collector.wake.is_set()
    runtime.collector.resume()
    assert runtime.store.settings()["recording"] is True
    assert runtime.collector.wake.is_set()
    runtime.collector.pause()
    assert runtime.store.settings()["recording"] is False


def test_real_claude_parser_flows_through_worker_and_store(runtime, tmp_path, monkeypatch):
    logs = tmp_path / "synthetic-projects"
    logs.mkdir()
    timestamp = datetime.now(timezone.utc).isoformat()
    records = [
        {
            "type": role,
            "sessionId": "synthetic-session",
            "timestamp": timestamp,
            "cwd": "/workspace/synthetic",
            "message": {"content": text},
        }
        for role, text in [
            ("user", "Review this synthetic fixture"),
            ("assistant", "The synthetic fixture was checked."),
        ]
    ]
    (logs / "session.jsonl").write_text("\n".join(json.dumps(item) for item in records) + "\n")
    parser = ClaudeParser()
    parser.base_path = logs
    observer = AgentObserver(output_dir=tmp_path / "observer")
    observer.SOURCES = (("claude", "Claude Code"),)
    observer.claude_parser = parser
    monkeypatch.setattr("adr_sensor.observer.AgentObserver", lambda **kwargs: observer)
    destination = tmp_path / "captured"
    assert capture_worker(destination, 14) == 0
    captured = [json.loads(line) for line in (destination / "sessions.jsonl").read_text().splitlines()]
    assert len(captured) == 1
    runtime.store.ingest(captured[0])
    row = runtime.store.sessions()["items"][0]
    assert (
        runtime.store.session(row["id"])["payload"]["chat_history"][0]["content"]
        == records[0]["message"]["content"]
    )
    assert json.loads((destination / "result.json").read_text())["diagnostics"][0]["source"] == "claude"
