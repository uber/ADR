"""Claude health counters use synthetic inputs and never copy payloads into labels."""

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from adr_sensor.parsers.base_parser import BaseParser
from adr_sensor.parsers.claude_parser import ClaudeParser

CANARY = "private-content-credential-canary"


def _record(content=CANARY, **fields):
    return {
        "type": "user",
        "sessionId": "synthetic-session",
        "timestamp": "2026-09-19T10:00:00Z",
        "message": {"content": content},
        **fields,
    }


def _parse(tmp_path, text):
    path = tmp_path / "private-source-path.jsonl"
    path.write_text(text, encoding="utf-8")
    parser = ClaudeParser()
    entries = parser.parse_jsonl_file(path)
    assert path.read_text(encoding="utf-8") == text
    return parser, entries


def test_absent_claude_source_is_an_expected_skip(tmp_path):
    parser = ClaudeParser()
    parser.base_path = tmp_path / "missing"

    assert parser.parse_all() == []
    assert parser.get_diagnostics() == {"input_missing": 1}


@pytest.mark.parametrize("operation,reason", [("exists", "file_stat_error"), ("glob", "file_read_error")])
def test_discovery_errors_remain_visible_to_caller_and_are_counted(tmp_path, operation, reason):
    parser = ClaudeParser()
    parser.base_path = tmp_path
    with patch.object(Path, operation, side_effect=PermissionError(CANARY)):
        with pytest.raises(PermissionError):
            parser.parse_all()

    assert parser.get_diagnostics() == {reason: 1}


def test_old_transcript_and_failed_stat_are_distinct(tmp_path, monkeypatch):
    path = tmp_path / "old.jsonl"
    path.write_text(json.dumps(_record()), encoding="utf-8")
    os.utime(path, (1, 1))
    parser = ClaudeParser()
    parser.base_path = tmp_path

    assert parser.parse_all() == []
    assert parser.get_diagnostics() == {"file_age_skipped": 1}
    parser.reset_diagnostics()
    original_stat = Path.stat

    def fail_selected_path(candidate, *args, **kwargs):
        if candidate == path:
            raise PermissionError(CANARY)
        return original_stat(candidate, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", fail_selected_path)
    assert parser.parse_all() == []
    assert parser.get_diagnostics() == {"file_stat_error": 1}


def test_read_failure_reports_no_payload(tmp_path):
    parser = ClaudeParser()
    with patch("builtins.open", side_effect=PermissionError(CANARY)):
        assert parser.parse_jsonl_file(tmp_path / CANARY) == []

    assert parser.get_diagnostics() == {"file_read_error": 1}
    assert CANARY not in json.dumps(parser.get_diagnostics())


def test_malformed_records_are_counted_and_valid_content_is_unchanged(tmp_path):
    parser, entries = _parse(
        tmp_path,
        "invalid-json-" + CANARY + "\nnull\n" + json.dumps(_record()) + "\n",
    )

    assert len(entries) == 1
    assert entries[0].chat_history[0].content == CANARY
    assert parser.get_diagnostics() == {"record_decode_error": 1, "record_shape_error": 1}
    diagnostics = json.dumps(parser.get_diagnostics())
    assert CANARY not in diagnostics
    assert "private-source-path" not in diagnostics


@pytest.mark.parametrize("suffix", ['{"unfinished":', '{"unfinished":"text', '{"unfinished":tru', '{"value":1e'])
def test_unfinished_final_write_is_expected_and_complete_prefix_survives(tmp_path, suffix):
    parser, entries = _parse(tmp_path, json.dumps(_record()) + suffix)

    assert entries[0].chat_history[0].content == CANARY
    assert parser.get_diagnostics() == {"incomplete_record": 1}
    assert set(parser.get_diagnostics()) <= BaseParser.EXPECTED_DIAGNOSTIC_CODES


@pytest.mark.parametrize("malformed", ['{"unfinished":\n', '{"invalid":}\n', '{"invalid":}', "not-json"])
def test_malformed_terminated_lines_and_invalid_final_tokens_are_corruption(tmp_path, malformed):
    parser, entries = _parse(tmp_path, json.dumps(_record()) + "\n" + malformed)

    assert len(entries) == 1
    assert parser.get_diagnostics() == {"record_decode_error": 1}


def test_valid_final_record_padding_and_concatenated_objects_have_no_diagnostic(tmp_path):
    parser, entries = _parse(tmp_path, "\0" + json.dumps(_record()) + "\0" + json.dumps(_record("Second message")))

    assert [message.content for message in entries[0].chat_history] == [CANARY, "Second message"]
    assert parser.get_diagnostics() == {}


@pytest.mark.parametrize(
    "record", [_record(message=None), _record(sessionId=[]), _record(type=[]), _record(content={})]
)
def test_invalid_envelope_and_message_shapes_are_counted_once(tmp_path, record):
    parser, entries = _parse(tmp_path, json.dumps(record) + "\n" + json.dumps(_record()) + "\n")

    assert entries[0].chat_history[0].content == CANARY
    assert parser.get_diagnostics() == {"record_shape_error": 1}


@pytest.mark.parametrize("timestamp", [None, True, "invalid-" + CANARY, [], 10**100])
def test_invalid_timestamp_keeps_content_and_reports_fixed_reason(tmp_path, timestamp):
    parser, entries = _parse(tmp_path, json.dumps(_record(timestamp=timestamp)) + "\n")

    assert entries[0].chat_history[0].content == CANARY
    assert parser.get_diagnostics() == {"invalid_timestamp": 1}


def test_known_metadata_without_session_ids_and_expected_nontext_blocks_are_quiet(tmp_path):
    metadata = [
        {"type": kind, "private_value": CANARY}
        for kind in (
            "summary",
            "file-history-snapshot",
            "queue-operation",
            "custom-title",
            "tag",
            "content-replacement",
        )
    ]
    content = [
        {"type": kind, "private_value": CANARY}
        for kind in ("image", "document", "thinking", "redacted_thinking", "tool_reference")
    ] + [{"type": "text", "text": CANARY}]
    records = metadata + [_record(content), {"type": "system", "sessionId": "synthetic-session", "subtype": CANARY}]
    parser, entries = _parse(tmp_path, "\n".join(map(json.dumps, records)) + "\n")

    assert entries[0].chat_history[0].content == CANARY
    assert parser.get_diagnostics() == {}


def test_unknown_kinds_use_fixed_labels_without_changing_known_content(tmp_path):
    records = [
        _record(type="future-envelope-" + CANARY),
        _record([{"type": "future-block-" + CANARY}, {"type": "text", "text": CANARY}]),
    ]
    parser, entries = _parse(tmp_path, "\n".join(map(json.dumps, records)) + "\n")

    assert [message.content for message in entries[0].chat_history] == [CANARY]
    assert parser.get_diagnostics() == {"unsupported_record_type": 1, "unsupported_content_block": 1}
    assert CANARY not in json.dumps(parser.get_diagnostics())


def test_invalid_blocks_and_tool_identifiers_keep_valid_call_and_result(tmp_path):
    records = [
        _record(
            [
                {"type": "text", "text": None},
                {"type": "tool_use", "id": "invalid", "name": "Read", "input": []},
                {"type": "tool_use", "id": "call", "name": "Read", "input": {}},
            ],
            type="assistant",
        ),
        _record(
            [
                {"type": "tool_result", "tool_use_id": [], "content": CANARY},
                {
                    "type": "tool_result",
                    "tool_use_id": "call",
                    "content": [None, {"type": "image"}, {"type": "text", "text": CANARY}],
                },
            ]
        ),
    ]
    parser, entries = _parse(tmp_path, "\n".join(map(json.dumps, records)) + "\n")

    assert len(entries[0].chat_history[0].tools) == 1
    assert entries[0].chat_history[0].tools[0].result == CANARY
    assert parser.get_diagnostics() == {"record_shape_error": 4}


def test_session_build_error_is_counted_without_exception_text(tmp_path):
    path = tmp_path / "session.jsonl"
    path.write_text(json.dumps(_record()), encoding="utf-8")
    parser = ClaudeParser()
    with patch("adr_sensor.parsers.claude_parser.AgentEvent", side_effect=ValueError(CANARY)):
        assert parser.parse_jsonl_file(path) == []

    assert parser.get_diagnostics() == {"session_build_error": 1}
    assert CANARY not in json.dumps(parser.get_diagnostics())
