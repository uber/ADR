"""Content-free parser diagnostics exercised only with synthetic inputs."""

import json
import os
import sqlite3
from pathlib import Path

import pytest

from adr_sensor.parsers.base_parser import BaseParser
from adr_sensor.parsers.claude_desktop_parser import ClaudeDesktopParser
from adr_sensor.parsers.cline_parser import ClineParser
from adr_sensor.parsers.codex_parser import CodexParser
from adr_sensor.parsers.copilot_parser import CopilotParser
from adr_sensor.parsers.cursor_parser import CursorParser
from adr_sensor.parsers.dsh_parser import DshParser
from adr_sensor.parsers.gemini_parser import GeminiParser
from adr_sensor.parsers.opencode_parser import OpencodeParser
from adr_sensor.parsers.warp_parser import WarpParser

PARSERS = (
    ClaudeDesktopParser,
    ClineParser,
    CodexParser,
    CopilotParser,
    CursorParser,
    DshParser,
    GeminiParser,
    OpencodeParser,
    WarpParser,
)
CANARY = "diagnostic-private-payload-credential"


def isolated_parser(parser_class, tmp_path):
    """Avoid constructors probing real installed-agent paths."""
    parser = parser_class.__new__(parser_class)
    parser.max_age_days = 0
    parser.base_path = tmp_path / "missing"
    parser.base_paths = [parser.base_path]
    parser.codex_home = parser.base_path
    parser.db_path = parser.base_path / "missing.db"
    parser.base_dir = parser.base_path
    parser.backend = None
    return parser


def test_diagnostics_are_lazy_isolated_bounded_and_resettable(tmp_path):
    first = isolated_parser(CodexParser, tmp_path)
    second = isolated_parser(CodexParser, tmp_path)
    assert first.get_diagnostics() == {}
    for _ in range(10_000):
        first.record_diagnostic("record_decode_error")
    assert first.get_diagnostics() == {"record_decode_error": 10_000}
    snapshot = first.get_diagnostics()
    snapshot["record_decode_error"] = 0
    assert first.get_diagnostics()["record_decode_error"] == 10_000
    assert second.get_diagnostics() == {}
    first.reset_diagnostics()
    assert first.get_diagnostics() == {}


@pytest.mark.parametrize(
    "code,count",
    [
        (CANARY, 1),
        (None, 1),
        ([], 1),
        ("parser_error", 0),
        ("parser_error", -1),
        ("parser_error", True),
        ("parser_error", 1.5),
    ],
)
def test_diagnostics_reject_unbounded_labels_and_invalid_counts(tmp_path, code, count):
    parser = isolated_parser(CodexParser, tmp_path)
    with pytest.raises(ValueError) as error:
        parser.record_diagnostic(code, count)
    assert CANARY not in str(error.value)
    assert parser.get_diagnostics() == {}


@pytest.mark.parametrize("parser_class", PARSERS)
def test_absent_source_is_an_expected_skip(tmp_path, parser_class):
    parser = isolated_parser(parser_class, tmp_path)
    assert parser.parse_all() == []
    assert parser.get_diagnostics() == {"input_missing": 1}
    assert set(parser.get_diagnostics()) <= BaseParser.EXPECTED_DIAGNOSTIC_CODES


@pytest.mark.parametrize("source", ["codex", "copilot", "dsh", "gemini", "claude_desktop"])
def test_jsonl_recovery_reports_decode_error_without_copying_content(tmp_path, source):
    classes = {
        "codex": CodexParser,
        "copilot": CopilotParser,
        "dsh": DshParser,
        "gemini": GeminiParser,
        "claude_desktop": ClaudeDesktopParser,
    }
    parser = isolated_parser(classes[source], tmp_path)
    directory = tmp_path / "private-source-path"
    directory.mkdir()
    path = directory / ("events.jsonl" if source == "copilot" else "audit.jsonl")
    records = {
        "codex": [
            {"type": "session_meta", "payload": {"id": "synthetic-session"}},
            {"type": "response_item", "payload": {"type": "message", "role": "user", "content": CANARY}},
        ],
        "copilot": [{"type": "user.message", "data": {"content": CANARY}}],
        "dsh": [
            {"type": "session", "version": 3, "id": "synthetic-session"},
            {
                "type": "user/message",
                "data": {"id": "user1", "role": "user", "content": [{"type": "text", "text": CANARY}]},
            },
        ],
        "gemini": [{"sessionId": "synthetic-session"}, {"id": "user1", "type": "user", "content": CANARY}],
        "claude_desktop": [{"type": "user", "uuid": "user1", "message": {"content": CANARY}}],
    }[source]
    path.write_text("invalid-json-" + CANARY + "\n" + "\n".join(map(json.dumps, records)) + "\n", encoding="utf-8")
    before = path.read_bytes()
    if source == "copilot":
        entry = parser.parse_session_dir(directory)
    elif source == "dsh":
        entry = parser.parse_session_file(path)
    elif source == "gemini":
        entry = parser.parse_file(path)
    elif source == "claude_desktop":
        entry = parser._parse_session(path, {})
    else:
        entry = parser.parse_jsonl_file(path)

    assert entry is not None
    assert entry.chat_history[0].content == CANARY
    assert path.read_bytes() == before
    assert parser.get_diagnostics() == {"record_decode_error": 1}
    encoded_diagnostics = json.dumps(parser.get_diagnostics())
    assert CANARY not in encoded_diagnostics
    assert str(path) not in encoded_diagnostics
    assert "private-source-path" not in encoded_diagnostics


@pytest.mark.parametrize("parser_class", [DshParser, GeminiParser])
def test_diagnostics_survive_when_every_record_is_rejected(tmp_path, parser_class):
    parser = isolated_parser(parser_class, tmp_path)
    path = tmp_path / "session.jsonl"
    path.write_text("not json\n[]\n", encoding="utf-8")
    entry = parser.parse_session_file(path) if parser_class is DshParser else parser.parse_file(path)
    assert entry is None
    assert parser.get_diagnostics()["record_decode_error"] == 1
    assert parser.get_diagnostics()["record_shape_error"] >= 1


@pytest.mark.parametrize("parser_class", [CursorParser, OpencodeParser, WarpParser])
def test_incompatible_database_reports_failure(tmp_path, parser_class):
    parser = isolated_parser(parser_class, tmp_path)
    parser.db_path = tmp_path / "synthetic.db"
    parser.backend = "sqlite"
    with sqlite3.connect(parser.db_path):
        pass
    assert parser.parse_all() == []
    assert parser.get_diagnostics()["database_error"] >= 1


def test_dsh_new_generation_reports_schema_drift_without_reading_payload(tmp_path):
    parser = isolated_parser(DshParser, tmp_path)
    parser.base_path = tmp_path
    (tmp_path / "session.v999.jsonl").write_text(CANARY, encoding="utf-8")
    assert parser.parse_all() == []
    assert parser.get_diagnostics() == {"unsupported_schema": 1}


def test_dsh_uncommitted_tail_is_not_reported_as_corrupt_json(tmp_path):
    parser = isolated_parser(DshParser, tmp_path)
    path = tmp_path / "session.v3.jsonl"
    path.write_text('{"unfinished":', encoding="utf-8")
    assert parser.parse_session_file(path) is None
    assert parser.get_diagnostics() == {"incomplete_record": 1}
    assert set(parser.get_diagnostics()) <= BaseParser.EXPECTED_DIAGNOSTIC_CODES


def test_codex_unsupported_catalog_and_missing_optional_catalog(tmp_path):
    parser = isolated_parser(CodexParser, tmp_path)
    parser._add_catalog_rollouts({}, tmp_path / "missing.sqlite")
    assert parser.get_diagnostics() == {}
    path = tmp_path / "catalog.sqlite"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE threads (id TEXT)")
    parser._add_catalog_rollouts({}, path)
    assert parser.get_diagnostics() == {"unsupported_schema": 1}


def test_stat_failure_is_not_reported_as_age_filtering(tmp_path, monkeypatch):
    parser = isolated_parser(CodexParser, tmp_path)
    path = tmp_path / "session.jsonl"
    path.write_text("{}", encoding="utf-8")
    original_stat = Path.stat

    def fail_selected_path(candidate, *args, **kwargs):
        if candidate == path:
            raise PermissionError(CANARY)
        return original_stat(candidate, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", fail_selected_path)
    parser._add_rollout_candidate({}, path)
    assert parser.get_diagnostics() == {"file_stat_error": 1}


def test_cline_malformed_file_and_expected_old_file_are_distinct(tmp_path):
    parser = isolated_parser(ClineParser, tmp_path)
    parser.base_path = tmp_path
    task = tmp_path / "synthetic-task"
    task.mkdir()
    path = task / "api_conversation_history.json"
    path.write_text("invalid-json-" + CANARY, encoding="utf-8")
    assert parser.parse_all() == []
    assert parser.get_diagnostics() == {"record_decode_error": 1}
    parser.reset_diagnostics()
    parser.max_age_days = 14
    os.utime(path, (1, 1))
    assert parser.parse_all() == []
    assert parser.get_diagnostics() == {"file_age_skipped": 1}


def test_opencode_skipped_json_rows_and_warp_plain_model_fallback(tmp_path):
    parser = isolated_parser(OpencodeParser, tmp_path)
    assert parser._safe_json("invalid-json-" + CANARY) is None
    assert parser.get_diagnostics() == {"record_decode_error": 1}
    warp = isolated_parser(WarpParser, tmp_path)
    assert warp._parse_json_safely("plain-model-name", report_failure=False) is None
    assert warp.get_diagnostics() == {}
    assert warp._parse_json_safely("invalid-json-" + CANARY) is None
    assert warp.get_diagnostics() == {"record_decode_error": 1}


def test_cline_malformed_tool_arguments_report_loss(tmp_path):
    parser = isolated_parser(ClineParser, tmp_path)
    assert (
        parser.extract_mcp_tools(
            "<use_mcp_tool><server_name>test</server_name><tool_name>read</tool_name>"
            '<arguments>{"invalid":}</arguments></use_mcp_tool>'
        )
        == []
    )
    assert parser.get_diagnostics() == {"record_decode_error": 1}


def test_gemini_optional_metadata_absence_is_not_a_read_failure(tmp_path):
    parser = isolated_parser(GeminiParser, tmp_path)
    project = tmp_path / "tmp" / "project"
    chats = project / "chats"
    chats.mkdir(parents=True)
    path = chats / "session.jsonl"
    assert parser._project_path(path) is None
    assert parser.get_diagnostics() == {}
    (project / ".project_root").write_bytes(b"\xff")
    (tmp_path / "projects.json").write_text("invalid-json-" + CANARY, encoding="utf-8")
    assert parser._project_path(path) is None
    assert parser.get_diagnostics() == {"file_read_error": 1, "record_decode_error": 1}
