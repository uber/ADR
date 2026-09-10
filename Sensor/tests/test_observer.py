"""Tests for the AgentObserver."""

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from adr_sensor.observer import AgentObserver
from adr_sensor.schemas.agent_event_schema import AgentEvent, ChatMessage


class TestAgentObserver:
    def test_init_default(self, tmp_path):
        """Test default initialization."""
        observer = AgentObserver(output_dir=tmp_path)
        assert observer.output_dir == tmp_path

    def test_init_propagates_max_age_days_to_cline(self, tmp_path):
        observer = AgentObserver(output_dir=tmp_path, max_age_days=30)

        assert observer.cline_parser.max_age_days == 30

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
