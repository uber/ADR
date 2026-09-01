"""Tests for the AgentObserver."""

import json
import os
import stat
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from adr_sensor.observer import AgentObserver
from adr_sensor.schemas.agent_event_schema import AgentEvent, ChatMessage, ToolUsage


class TestAgentObserver:
    def test_init_default(self, tmp_path):
        """Test default initialization."""
        observer = AgentObserver(output_dir=tmp_path)
        assert observer.output_dir == tmp_path
        assert hasattr(observer, "copilot_parser")
        assert ("copilot", "GitHub Copilot") in observer.SOURCES

    def test_display_summary_empty(self, tmp_path, capsys):
        """Test display summary with no data."""
        observer = AgentObserver(output_dir=tmp_path)
        observer.display_summary([], [])
        captured = capsys.readouterr()
        assert "No logs found!" in captured.out

    def test_display_summary_with_entries(self, tmp_path, capsys):
        """Test display summary with entries."""
        observer = AgentObserver(output_dir=tmp_path)
        entries = [
            AgentEvent(
                timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
                source="claude",
                session_id="test",
                hostname="host",
                username="user",
                chat_history=[
                    ChatMessage(role="user", content="hello"),
                    ChatMessage(role="assistant", content="hi"),
                ],
            )
        ]
        observer.display_summary(entries, [])
        captured = capsys.readouterr()
        assert "CLAUDE" in captured.out
        assert "INGESTION SUMMARY" in captured.out

    def test_save_to_file_json(self, tmp_path):
        """Test saving entries as JSON."""
        observer = AgentObserver(output_dir=tmp_path)
        entries = [
            AgentEvent(
                timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
                source="claude",
                session_id="test",
                hostname="host",
                username="user",
                chat_history=[
                    ChatMessage(role="user", content="hello"),
                    ChatMessage(role="assistant", content="hi"),
                ],
            )
        ]
        saved = observer.save_to_file(entries, [], output_format="json", output_dir=tmp_path)
        assert len(saved) == 1
        assert saved[0].exists()

        with open(saved[0]) as f:
            data = json.load(f)
        assert data["total_entries"] == 1

    def test_save_to_file_jsonl(self, tmp_path):
        """Test saving entries as JSONL."""
        observer = AgentObserver(output_dir=tmp_path)
        entries = [
            AgentEvent(
                timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
                source="claude",
                session_id="test1",
                hostname="host",
                username="user",
                chat_history=[ChatMessage(role="user", content="hello")],
            ),
            AgentEvent(
                timestamp=datetime(2025, 1, 2, tzinfo=timezone.utc),
                source="cursor",
                session_id="test2",
                hostname="host",
                username="user",
                chat_history=[ChatMessage(role="user", content="world")],
            ),
        ]
        saved = observer.save_to_file(entries, [], output_format="jsonl", output_dir=tmp_path)
        assert len(saved) == 1

        with open(saved[0]) as f:
            lines = f.readlines()
        assert len(lines) == 2

    def test_save_sessions_individual(self, tmp_path):
        """Test saving individual session files."""
        observer = AgentObserver(output_dir=tmp_path)
        entries = [
            AgentEvent(
                timestamp=datetime(2025, 6, 15, 10, 30, 0, tzinfo=timezone.utc),
                source="claude",
                session_id="claude_abc123",
                hostname="host",
                username="user",
                chat_history=[
                    ChatMessage(role="user", content="test"),
                    ChatMessage(role="assistant", content="response"),
                ],
            )
        ]
        saved = observer.save_sessions_to_individual_files(entries, output_dir=tmp_path)
        assert len(saved) == 1
        assert saved[0].name.startswith("adr.")
        assert saved[0].name.endswith(".json")

    def test_clean_filename(self, tmp_path):
        """Test filename cleaning."""
        observer = AgentObserver(output_dir=tmp_path)
        assert observer._clean_filename("simple_id") == "simple_id"
        assert observer._clean_filename("path/with:special*chars") == "path_with_special_chars"
        assert observer._clean_filename("  spaces  ") == "spaces"
        assert observer._session_filename_id("simple_id") == "simple_id"
        assert observer._session_filename_id("path/with") != observer._session_filename_id("path:with")

    def test_filter_entries_by_existing_files(self, tmp_path):
        """Test incremental filtering."""
        observer = AgentObserver(output_dir=tmp_path)

        # Create an existing session file
        existing_file = tmp_path / "adr.claude_session1.20250615_103000.json"
        existing_file.write_text("{}")

        entries = [
            AgentEvent(
                timestamp=datetime(2025, 6, 15, 10, 30, 0, tzinfo=timezone.utc),
                source="claude",
                session_id="claude_session1",
                hostname="host",
                username="user",
                chat_history=[ChatMessage(role="user", content="old")],
            ),
            AgentEvent(
                timestamp=datetime(2025, 6, 16, 10, 30, 0, tzinfo=timezone.utc),
                source="claude",
                session_id="claude_session2",
                hostname="host",
                username="user",
                chat_history=[ChatMessage(role="user", content="new")],
            ),
        ]

        filtered = observer.filter_entries_by_existing_files(entries, output_dir=tmp_path)
        # session1 has same timestamp, should be filtered; session2 is new
        assert len(filtered) == 1
        assert filtered[0].session_id == "claude_session2"

    def test_content_filter_ignores_timestamp_identity_migration(self, tmp_path):
        """Changing from activity time to start time must not re-export unchanged history."""
        observer = AgentObserver(output_dir=tmp_path)
        entry = AgentEvent(
            timestamp=datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc),
            source="codex",
            session_id="codex_session1",
            hostname="host",
            username="user",
            chat_history=[ChatMessage(role="user", content="unchanged")],
            session_context={"last_event_at": "2025-06-16T12:30:00+00:00"},
        )
        legacy_data = entry.get_non_null_fields()
        legacy_data["timestamp"] = "2025-06-16T12:30:00+00:00"
        legacy_data["uuid"] = "legacy-moving-timestamp-uuid"
        legacy_data.pop("session_context")
        legacy_file = tmp_path / "adr.codex_session1.20250616_123000.json"
        legacy_file.write_text(json.dumps(legacy_data), encoding="utf-8")

        assert observer.filter_entries_by_existing_files([entry], output_dir=tmp_path) == []
        assert legacy_file.exists()

    def test_content_filter_detects_same_second_tool_result(self, tmp_path):
        """A result appended in the filename's second must still replace the snapshot."""
        observer = AgentObserver(output_dir=tmp_path)
        timestamp = datetime(2025, 6, 15, 10, 0, 0, 100000, tzinfo=timezone.utc)
        pending = AgentEvent(
            timestamp=timestamp,
            source="codex",
            session_id="codex_session1",
            hostname="host",
            username="user",
            chat_history=[
                ChatMessage(
                    role="assistant",
                    content="",
                    tools=[ToolUsage(tool_name="shell", tool_type="function_call", status="pending")],
                )
            ],
        )
        completed = AgentEvent(
            timestamp=timestamp.replace(microsecond=900000),
            source="codex",
            session_id="codex_session1",
            hostname="host",
            username="user",
            chat_history=[
                ChatMessage(
                    role="assistant",
                    content="",
                    tools=[
                        ToolUsage(
                            tool_name="shell",
                            tool_type="function_call",
                            result="done",
                            status="success",
                        )
                    ],
                )
            ],
        )

        first_saved = observer.save_sessions_to_individual_files([pending], output_dir=tmp_path)
        assert observer.filter_entries_by_existing_files([completed], output_dir=tmp_path) == [completed]
        second_saved = observer.save_sessions_to_individual_files([completed], output_dir=tmp_path)

        assert first_saved == second_saved
        session_files = list(tmp_path.glob("adr.codex_session1.*.json"))
        assert session_files == second_saved
        saved_data = json.loads(session_files[0].read_text(encoding="utf-8"))
        assert saved_data["chat_history"][0]["tools"][0]["result"] == "done"

    def test_content_update_replaces_legacy_snapshot_with_stable_file(self, tmp_path):
        """A changed legacy snapshot should converge to one start-time file."""
        observer = AgentObserver(output_dir=tmp_path)
        legacy_file = tmp_path / "adr.copilot_session1.20250616_123000.json"
        backup_file = tmp_path / "adr.copilot_session1.backup.json"
        backup_file.write_text("keep", encoding="utf-8")
        legacy_file.write_text(
            json.dumps(
                {
                    "timestamp": "2025-06-16T12:30:00+00:00",
                    "source": "copilot",
                    "session_id": "copilot_session1",
                    "chat_history": [{"role": "user", "content": "old", "tools": []}],
                    "uuid": "legacy",
                }
            ),
            encoding="utf-8",
        )
        entry = AgentEvent(
            timestamp=datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc),
            source="copilot",
            session_id="copilot_session1",
            hostname="host",
            username="user",
            chat_history=[ChatMessage(role="user", content="updated")],
        )

        assert observer.filter_entries_by_existing_files([entry], output_dir=tmp_path) == [entry]
        saved = observer.save_sessions_to_individual_files([entry], output_dir=tmp_path)

        assert [path.name for path in saved] == ["adr.copilot_session1.20250615_100000.json"]
        assert saved[0].exists()
        assert not legacy_file.exists()
        assert backup_file.read_text(encoding="utf-8") == "keep"

    def test_cleanup_rechecks_session_ownership_before_deleting(self, tmp_path):
        """A stale in-memory index must not authorize deleting a replaced path."""
        observer = AgentObserver(output_dir=tmp_path)
        candidate = tmp_path / "adr.codex_session1.20250616_123000.json"
        candidate.write_text(json.dumps({"session_id": "other_session"}), encoding="utf-8")

        removed = observer._remove_stale_session_files(
            "codex_session1",
            tmp_path / "adr.codex_session1.20250615_100000.json",
            [{"file_path": candidate, "data": {"session_id": "codex_session1"}}],
        )

        assert not removed
        assert candidate.exists()

    def test_directory_sync_failure_preserves_legacy_snapshot(self, tmp_path):
        """Do not remove the only prior snapshot until the replacement entry is durable."""
        observer = AgentObserver(output_dir=tmp_path)
        legacy_file = tmp_path / "adr.codex_session1.20250616_123000.json"
        legacy_file.write_text(json.dumps({"session_id": "codex_session1"}), encoding="utf-8")
        entry = AgentEvent(
            timestamp=datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc),
            source="codex",
            session_id="codex_session1",
            hostname="host",
            username="user",
            chat_history=[ChatMessage(role="user", content="updated")],
        )

        with patch.object(observer, "_sync_session_directory", side_effect=OSError("sync failed")):
            assert observer.save_sessions_to_individual_files([entry], output_dir=tmp_path) == []

        assert legacy_file.exists()

    def test_atomic_save_failure_preserves_existing_snapshot(self, tmp_path):
        """A failed replacement must leave the previous complete JSON intact."""
        observer = AgentObserver(output_dir=tmp_path)
        old_entry = AgentEvent(
            timestamp=datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc),
            source="codex",
            session_id="codex_session1",
            hostname="host",
            username="user",
            chat_history=[ChatMessage(role="user", content="old")],
        )
        new_entry = AgentEvent(
            timestamp=old_entry.timestamp,
            source="codex",
            session_id="codex_session1",
            hostname="host",
            username="user",
            chat_history=[ChatMessage(role="user", content="new")],
        )
        existing_path = observer.save_sessions_to_individual_files([old_entry], output_dir=tmp_path)[0]
        original_data = existing_path.read_text(encoding="utf-8")

        with patch("adr_sensor.observer.os.replace", side_effect=OSError("replace failed")):
            saved = observer.save_sessions_to_individual_files([new_entry], output_dir=tmp_path)

        assert saved == []
        assert existing_path.read_text(encoding="utf-8") == original_data
        assert list(tmp_path.glob("*.tmp")) == []

    @pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits are not preserved on Windows")
    def test_atomic_replacement_preserves_existing_permissions(self, tmp_path):
        observer = AgentObserver(output_dir=tmp_path)
        entry = AgentEvent(
            timestamp=datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc),
            source="codex",
            session_id="codex_session1",
            hostname="host",
            username="user",
            chat_history=[ChatMessage(role="user", content="old")],
        )
        path = observer.save_sessions_to_individual_files([entry], output_dir=tmp_path)[0]
        path.chmod(0o640)
        updated = AgentEvent(
            timestamp=entry.timestamp,
            source=entry.source,
            session_id=entry.session_id,
            hostname=entry.hostname,
            username=entry.username,
            chat_history=[ChatMessage(role="user", content="updated")],
        )

        observer.save_sessions_to_individual_files([updated], output_dir=tmp_path)

        assert stat.S_IMODE(path.stat().st_mode) == 0o640

    def test_lossy_session_ids_do_not_overwrite_or_delete_each_other(self, tmp_path):
        """Sanitized filename collisions must retain both sessions."""
        observer = AgentObserver(output_dir=tmp_path)
        timestamp = datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
        slash_entry = AgentEvent(
            timestamp=timestamp,
            source="codex",
            session_id="codex_a/b",
            hostname="host",
            username="user",
            chat_history=[ChatMessage(role="user", content="slash")],
        )
        colon_entry = AgentEvent(
            timestamp=timestamp,
            source="codex",
            session_id="codex_a:b",
            hostname="host",
            username="user",
            chat_history=[ChatMessage(role="user", content="colon")],
        )

        saved = observer.save_sessions_to_individual_files([slash_entry, colon_entry], output_dir=tmp_path)

        assert len(saved) == 2
        assert saved[0] != saved[1]
        assert all(path.exists() for path in saved)
        assert observer.filter_entries_by_existing_files([slash_entry, colon_entry], output_dir=tmp_path) == []

        colliding_legacy = tmp_path / "adr.codex_a_b.20250616_100000.json"
        colliding_legacy.write_text(json.dumps(colon_entry.get_non_null_fields()), encoding="utf-8")
        updated_slash = AgentEvent(
            timestamp=timestamp,
            source="codex",
            session_id=slash_entry.session_id,
            hostname="host",
            username="user",
            chat_history=[ChatMessage(role="user", content="updated slash")],
        )
        observer.save_sessions_to_individual_files([updated_slash], output_dir=tmp_path)
        assert colliding_legacy.exists()
        assert json.loads(colliding_legacy.read_text(encoding="utf-8"))["session_id"] == colon_entry.session_id

    def test_generated_filename_does_not_overwrite_matching_literal_session_id(self, tmp_path):
        """A hash-suffixed generated name may also be another session's literal ID."""
        observer = AgentObserver(output_dir=tmp_path)
        timestamp = datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
        lossy_id = "codex_a/b"
        literal_id = observer._session_filename_id(lossy_id)
        lossy_entry = AgentEvent(
            timestamp=timestamp,
            source="codex",
            session_id=lossy_id,
            hostname="host",
            username="user",
            chat_history=[ChatMessage(role="user", content="lossy")],
        )
        literal_entry = AgentEvent(
            timestamp=timestamp,
            source="codex",
            session_id=literal_id,
            hostname="host",
            username="user",
            chat_history=[ChatMessage(role="user", content="literal")],
        )

        saved = observer.save_sessions_to_individual_files([lossy_entry, literal_entry], output_dir=tmp_path)

        assert len(saved) == 2
        assert saved[0] != saved[1]
        assert {json.loads(path.read_text(encoding="utf-8"))["session_id"] for path in saved} == {
            lossy_id,
            literal_id,
        }
        assert observer.filter_entries_by_existing_files([lossy_entry, literal_entry], output_dir=tmp_path) == []

    def test_older_revision_cannot_replace_newer_snapshot(self, tmp_path):
        """A delayed writer must not regress an already exported session."""
        observer = AgentObserver(output_dir=tmp_path)
        timestamp = datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
        newer = AgentEvent(
            timestamp=timestamp,
            source="copilot",
            session_id="copilot_session1",
            hostname="host",
            username="user",
            chat_history=[ChatMessage(role="user", content="newer")],
            session_context={"last_event_at": "2025-06-16T12:30:01.000Z"},
        )
        older = AgentEvent(
            timestamp=timestamp,
            source="copilot",
            session_id="copilot_session1",
            hostname="host",
            username="user",
            chat_history=[ChatMessage(role="user", content="older")],
            session_context={"last_event_at": "2025-06-16T12:30:00.000Z"},
        )

        saved_path = observer.save_sessions_to_individual_files([newer], output_dir=tmp_path)[0]
        assert observer.filter_entries_by_existing_files([older], output_dir=tmp_path) == []
        assert observer.save_sessions_to_individual_files([older], output_dir=tmp_path) == []
        assert json.loads(saved_path.read_text(encoding="utf-8"))["chat_history"][0]["content"] == "newer"

    def test_equal_event_timestamp_uses_event_count_to_prevent_stale_replacement(self, tmp_path):
        """An older parse cannot overwrite a same-timestamp append-only snapshot."""
        observer = AgentObserver(output_dir=tmp_path)
        timestamp = datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
        newer = AgentEvent(
            timestamp=timestamp,
            source="codex",
            session_id="codex_session1",
            hostname="host",
            username="user",
            chat_history=[ChatMessage(role="user", content="newer")],
            session_context={"last_event_at": "2025-06-16T12:30:00.000Z", "event_count": 3},
        )
        stale = AgentEvent(
            timestamp=timestamp,
            source="codex",
            session_id="codex_session1",
            hostname="host",
            username="user",
            chat_history=[ChatMessage(role="user", content="stale")],
            session_context={"last_event_at": "2025-06-16T12:30:00.000Z", "event_count": 2},
        )

        saved_path = observer.save_sessions_to_individual_files([newer], output_dir=tmp_path)[0]
        assert observer.save_sessions_to_individual_files([stale], output_dir=tmp_path) == []
        assert json.loads(saved_path.read_text(encoding="utf-8"))["chat_history"][0]["content"] == "newer"

    def test_leftover_legacy_file_cannot_hide_newer_stable_revision(self, tmp_path):
        """Regression checks must use stored revisions, not moving filenames."""
        observer = AgentObserver(output_dir=tmp_path)
        timestamp = datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
        newer = AgentEvent(
            timestamp=timestamp,
            source="copilot",
            session_id="copilot_session1",
            hostname="host",
            username="user",
            chat_history=[ChatMessage(role="user", content="newest")],
            session_context={"last_event_at": "2025-06-18T12:30:00.000Z"},
        )
        stale = AgentEvent(
            timestamp=timestamp,
            source="copilot",
            session_id="copilot_session1",
            hostname="host",
            username="user",
            chat_history=[ChatMessage(role="user", content="stale")],
            session_context={"last_event_at": "2025-06-17T12:30:00.000Z"},
        )
        stable_path = observer.save_sessions_to_individual_files([newer], output_dir=tmp_path)[0]
        legacy_data = stale.get_non_null_fields()
        legacy_data["timestamp"] = "2025-06-16T12:30:00+00:00"
        legacy_data["session_context"]["last_event_at"] = "2025-06-16T12:30:00.000Z"
        legacy_path = tmp_path / "adr.copilot_session1.20250620_123000.json"
        legacy_path.write_text(json.dumps(legacy_data), encoding="utf-8")

        assert observer.filter_entries_by_existing_files([stale], output_dir=tmp_path) == []
        assert observer.save_sessions_to_individual_files([stale], output_dir=tmp_path) == []
        assert json.loads(stable_path.read_text(encoding="utf-8"))["chat_history"][0]["content"] == "newest"
        assert legacy_path.exists()

    def test_session_lock_blocks_competing_writer_and_recovers(self, tmp_path):
        """The OS releases a session lock cleanly for the next writer."""
        lock_path = tmp_path / ".adr.codex_session1.lock"
        first_fd = AgentObserver._acquire_session_lock(lock_path)
        try:
            with pytest.raises(TimeoutError):
                AgentObserver._acquire_session_lock(lock_path, timeout_seconds=0)
        finally:
            AgentObserver._release_session_lock(first_fd)

        second_fd = AgentObserver._acquire_session_lock(lock_path, timeout_seconds=0)
        AgentObserver._release_session_lock(second_fd)

    def test_waiting_stale_writer_refreshes_target_after_lock(self, tmp_path):
        """A writer must re-read output created after its initial directory scan."""
        observer = AgentObserver(output_dir=tmp_path)
        competing_observer = AgentObserver(output_dir=tmp_path)
        timestamp = datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
        stale = AgentEvent(
            timestamp=timestamp,
            source="codex",
            session_id="codex_session1",
            hostname="host",
            username="user",
            chat_history=[ChatMessage(role="user", content="stale")],
            session_context={"last_event_at": "2025-06-16T12:30:00.000Z"},
        )
        newer = AgentEvent(
            timestamp=timestamp,
            source="codex",
            session_id="codex_session1",
            hostname="host",
            username="user",
            chat_history=[ChatMessage(role="user", content="newer")],
            session_context={"last_event_at": "2025-06-16T12:30:01.000Z"},
        )
        acquire_lock = AgentObserver._acquire_session_lock
        injected = False

        def inject_competing_write(lock_path):
            nonlocal injected
            if not injected:
                injected = True
                competing_observer.save_sessions_to_individual_files([newer], output_dir=tmp_path)
            return acquire_lock(lock_path)

        with patch.object(observer, "_acquire_session_lock", side_effect=inject_competing_write):
            assert observer.save_sessions_to_individual_files([stale], output_dir=tmp_path) == []

        saved_path = next(tmp_path.glob("adr.codex_session1.*.json"))
        assert json.loads(saved_path.read_text(encoding="utf-8"))["chat_history"][0]["content"] == "newer"

    @patch("adr_sensor.observer.ClaudeParser")
    def test_ingest_all_handles_parser_errors(self, mock_claude_cls, tmp_path):
        """Test that ingest_all handles parser errors gracefully."""
        mock_parser = MagicMock()
        mock_parser.parse_all.side_effect = Exception("Parser crashed")
        mock_claude_cls.return_value = mock_parser

        observer = AgentObserver(output_dir=tmp_path)
        observer.claude_parser = mock_parser

        # Should not raise
        entries, configs = observer.ingest_all(source_filter="claude")
        assert entries == []
