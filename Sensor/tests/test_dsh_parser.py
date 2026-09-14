import json
import os
from datetime import datetime, timezone

import zstandard

from adr_sensor.observer import AgentObserver
from adr_sensor.parsers.dsh_parser import DshParser


def write_session(tmp_path, events, filename="session.v3.jsonl", session_dir_name="session-test"):
    session_dir = tmp_path / "sessions" / "workspace" / session_dir_name
    session_dir.mkdir(parents=True, exist_ok=True)
    content = "\n".join(json.dumps(event) for event in events) + "\n"
    path = session_dir / filename
    if filename.endswith(".zstd"):
        path.write_bytes(zstandard.ZstdCompressor(write_checksum=True).compress(content.encode("utf-8")))
    else:
        path.write_text(content, encoding="utf-8")
    return path


def test_parse_session_jsonl_normalizes_messages_and_tools(tmp_path):
    path = write_session(
        tmp_path,
        [
            {"type": "session", "version": 3, "id": "session-test", "createdAt": 1750000000000, "cwd": "/work"},
            {
                "type": "user/message",
                "seq": 1,
                "time": 1750000001000,
                "data": {"id": "u1", "role": "user", "content": [{"type": "text", "text": "inspect"}]},
            },
            {
                "type": "assistant/message",
                "seq": 2,
                "time": 1750000002000,
                "data": {
                    "message": {
                        "role": "assistant",
                        "id": "a1",
                        "source": {"kind": "model", "provider": "local", "model": "qwen38"},
                        "content": [
                            {"type": "text", "text": "I will inspect"},
                            {"type": "tool-call", "id": "call-1", "name": "bash", "arguments": '{"command": "pwd"}'},
                        ],
                    },
                    "usage": {
                        "inputTokens": 10,
                        "outputTokens": 5,
                        "totalTokens": 15,
                        "cacheReadTokens": 2,
                        "reasoningTokens": 3,
                    },
                },
            },
            {
                "type": "tool/result",
                "seq": 3,
                "time": 1750000003000,
                "data": {
                    "message": {
                        "source": {"callId": "call-1"},
                        "content": [{"type": "tool-result", "content": [{"type": "text", "text": "/work"}]}],
                    }
                },
            },
            {
                "type": "request/context",
                "seq": 4,
                "time": 1750000004000,
                "data": {"provider": "local", "model": "qwen38", "contextWindow": 32768},
            },
            {"type": "malformed", "seq": 5, "time": 1750000005000, "data": {}},
        ],
    )

    before = path.read_bytes(), path.stat().st_mtime_ns
    entry = DshParser(base_path=tmp_path / "sessions", max_age_days=0).parse_session_file(path)

    assert entry is not None
    assert entry.source == "dsh"
    assert entry.session_id == "dsh_session-test"
    assert entry.project_path == "/work"
    assert entry.model == "qwen38"
    assert entry.timestamp == datetime.fromtimestamp(1750000000, timezone.utc)
    assert [message.role for message in entry.chat_history] == ["user", "assistant"]
    assert [message.sequence_id for message in entry.chat_history] == ["u1", "a1"]
    tool = entry.chat_history[1].tools[0]
    assert tool.tool_name == "bash"
    assert tool.arguments == {"command": "pwd"}
    assert tool.result == "/work"
    assert tool.status == "success"
    assert entry.session_context["event_count"] == 5
    assert entry.session_context["last_event_at"] == "2025-06-15T15:06:45+00:00"
    assert entry.token_usage["cumulative"]["total_tokens"] == 15
    assert entry.token_usage["cumulative"]["cached_input_tokens"] == 2
    assert entry.token_usage["cumulative"]["reasoning_output_tokens"] == 3
    assert entry.session_context["message_metadata"]["u1"]["role"] == "user"
    assert entry.session_context["message_metadata"]["a1"]["source"]["provider"] == "local"
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before


def test_parse_session_marks_failed_tool_result(tmp_path):
    path = write_session(
        tmp_path,
        [
            {"type": "session", "version": 3, "id": "session-error", "createdAt": 1750000000000},
            {
                "type": "assistant/message",
                "data": {
                    "message": {
                        "role": "assistant",
                        "content": [{"type": "tool-call", "id": "call-1", "name": "read", "arguments": "{}"}],
                    }
                },
            },
            {
                "type": "tool/result",
                "data": {
                    "message": {
                        "source": {"callId": "call-1"},
                        "content": [
                            {"type": "tool-result", "isError": True, "content": [{"type": "text", "text": "denied"}]}
                        ],
                    },
                    "error": {"name": "FsError", "code": "FS_SANDBOX_DENIED"},
                },
            },
        ],
    )

    tool = DshParser(max_age_days=0).parse_session_file(path).chat_history[0].tools[0]
    assert tool.status == "error"
    assert tool.error == "FsError: FS_SANDBOX_DENIED"


def test_parse_session_preserves_tool_result_metadata_and_replacements(tmp_path):
    original_content = [
        {
            "type": "tool-result",
            "content": [
                {"type": "text", "text": "original result"},
                {"type": "image", "attachment": {"id": "attachment-1"}},
            ],
        }
    ]
    replacement_content = [{"type": "tool-result", "content": [{"type": "text", "text": "[result pruned]"}]}]
    path = write_session(
        tmp_path,
        [
            {"type": "session", "version": 3, "id": "tool-metadata", "createdAt": 1750000000000},
            {
                "type": "assistant/message",
                "seq": 1,
                "surfaceOp": "append",
                "data": {
                    "message": {
                        "role": "assistant",
                        "content": [{"type": "tool-call", "id": "call-1", "name": "read", "arguments": "{}"}],
                    }
                },
            },
            {
                "type": "tool/result",
                "seq": 2,
                "surfaceOp": "append",
                "data": {
                    "turn": 1,
                    "step": 1,
                    "message": {"source": {"kind": "tool", "callId": "call-1"}, "content": original_content},
                    "meta": {"diff": {"before": "old", "after": "new"}},
                },
            },
            {
                "type": "compaction/prune",
                "seq": 3,
                "ignorable": True,
                "data": {"shadowedRange": {"start": 2, "end": 2}, "shadowedSeqs": [2]},
            },
            {
                "type": "tool/result",
                "seq": 4,
                "surfaceOp": {"op": "replace", "startSeq": 2, "endSeq": 2},
                "sourceEventSeqs": [2],
                "data": {
                    "turn": 1,
                    "step": 1,
                    "message": {"source": {"kind": "tool", "callId": "call-1"}, "content": replacement_content},
                    "meta": {"diff": {"before": "old", "after": "new"}},
                },
            },
        ],
    )

    entry = DshParser().parse_session_file(path)
    tool = entry.chat_history[0].tools[0]
    assert tool.result == "original result"
    results = entry.session_context["tool_result_metadata"]
    assert len(results) == 2
    assert results[0]["content_parts"] == original_content
    assert results[0]["meta"] == {"diff": {"before": "old", "after": "new"}}
    assert results[0]["is_replacement"] is False
    assert results[1]["content_parts"] == replacement_content
    assert results[1]["is_replacement"] is True
    assert results[1]["surface_op"] == {"op": "replace", "startSeq": 2, "endSeq": 2}
    assert results[1]["source_event_seqs"] == [2]


def test_parse_session_captures_ptc_subdispatch(tmp_path):
    path = write_session(
        tmp_path,
        [
            {"type": "session", "version": 3, "id": "session-ptc", "createdAt": 1750000000000},
            {
                "type": "assistant/message",
                "data": {
                    "message": {
                        "role": "assistant",
                        "content": [{"type": "tool-call", "id": "root", "name": "run_code", "arguments": "{}"}],
                    }
                },
            },
            {
                "type": "tool/ptc-dispatch-start",
                "data": {
                    "rootCallId": "root",
                    "parentCallId": "root",
                    "subCallId": "root:ptc:0",
                    "name": "read",
                    "arguments": {"path": "README.md"},
                },
            },
            {
                "type": "tool/ptc-dispatch",
                "data": {
                    "rootCallId": "root",
                    "parentCallId": "root",
                    "subCallId": "root:ptc:0",
                    "name": "read",
                    "arguments": {"path": "README.md"},
                    "isError": False,
                    "content": [{"type": "text", "text": "contents"}],
                },
            },
        ],
    )

    entry = DshParser().parse_session_file(path)
    assert [tool.tool_name for tool in entry.chat_history[0].tools] == ["run_code", "read"]
    assert entry.chat_history[0].tools[1].result == "contents"
    assert entry.chat_history[0].tools[1].status == "success"


def test_parse_session_preserves_system_approval_and_mode_context(tmp_path):
    path = write_session(
        tmp_path,
        [
            {"type": "session", "version": 3, "id": "session-context", "createdAt": 1750000000000},
            {
                "type": "system/message",
                "data": {"message": {"role": "system", "content": [{"type": "text", "text": "policy"}]}},
            },
            {
                "type": "user/message",
                "data": {
                    "id": "u1",
                    "role": "user",
                    "source": {"kind": "user"},
                    "content": [{"type": "text", "text": "inspect project"}],
                },
            },
            {
                "type": "user/message",
                "data": {
                    "id": "image-1",
                    "role": "user",
                    "source": {"kind": "user"},
                    "content": [{"type": "image", "attachment": {"id": "attachment-1"}}],
                },
            },
            {"type": "approval/asked", "data": {"id": "approval-1", "toolName": "bash", "callId": "call-1"}},
            {"type": "approval/decided", "data": {"id": "approval-1", "outcome": "approved"}},
            {"type": "approval/policy", "data": {"policy": "on-request"}},
            {"type": "plan/mode", "data": {"active": True}},
        ],
    )

    context = DshParser().parse_session_file(path).session_context
    assert context["system_messages"] == ["policy"]
    assert [event["type"] for event in context["approvals"]] == ["approval/asked", "approval/decided"]
    assert context["approval_policy"] == "on-request"
    assert context["plan_mode"] is True
    assert context["message_metadata"]["image-1"]["content_parts"][0]["type"] == "image"


def test_parse_all_selects_highest_generation_once_and_reads_zstd(tmp_path):
    events = [
        {"type": "session", "version": 3, "id": "session-one", "createdAt": 1750000000000},
        {"type": "user/message", "data": {"role": "user", "content": [{"type": "text", "text": "hello world"}]}},
    ]
    write_session(tmp_path, events, "session.v2.jsonl")
    current = write_session(tmp_path, events, "session.v3.jsonl.zstd")

    entries = DshParser(base_path=tmp_path / "sessions", max_age_days=0).parse_all()

    assert len(entries) == 1
    assert entries[0].raw_log_path == str(current)


def test_zstd_reader_recovers_complete_records_from_torn_final_frame(tmp_path):
    events = [
        {"type": "session", "version": 3, "id": "session-torn", "createdAt": 1750000000000},
        {"type": "user/message", "data": {"role": "user", "content": [{"type": "text", "text": "inspect project"}]}},
    ]
    path = write_session(tmp_path, events, "session.v3.jsonl.zstd")
    appended = zstandard.ZstdCompressor(write_checksum=True).compress(
        (
            json.dumps(
                {
                    "type": "assistant/message",
                    "data": {
                        "message": {
                            "role": "assistant",
                            "content": [{"type": "text", "text": "uncommitted"}],
                        }
                    },
                }
            )
            + "\n"
        ).encode()
    )
    with path.open("ab") as handle:
        handle.write(appended[:-1])

    entry = DshParser().parse_session_file(path)
    assert [message.role for message in entry.chat_history] == ["user", "assistant"]
    assert entry.chat_history[1].content == "uncommitted"


def test_future_or_legacy_generation_is_not_parsed_as_v3(tmp_path):
    events = [
        {"type": "session", "version": 3, "id": "session-one", "createdAt": 1750000000000},
        {"type": "user/message", "data": {"role": "user", "content": [{"type": "text", "text": "hello world"}]}},
    ]
    write_session(tmp_path, events, "session.v3.jsonl")
    future = list(events)
    future[0] = dict(future[0], version=4)
    write_session(tmp_path, future, "session.v4.jsonl")

    assert DshParser(base_path=tmp_path / "sessions", max_age_days=0).parse_all() == []

    legacy_path = write_session(tmp_path, [dict(events[0], version=2), events[1]], "session.v2.jsonl")
    assert DshParser().parse_session_file(legacy_path) is None


def test_default_home_follows_dsh_home_or_user_home(monkeypatch, tmp_path):
    monkeypatch.delenv("DSH_HOME", raising=False)
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    assert DshParser().base_path == tmp_path / ".dsh" / "sessions"

    monkeypatch.setenv("DSH_HOME", "   ")
    assert DshParser().base_path == tmp_path / ".dsh" / "sessions"
    assert DshParser(base_path=tmp_path / "logs").base_path == tmp_path / "logs"


def test_age_filter_and_duplicate_session_ids(tmp_path):
    events = [
        {"type": "session", "version": 3, "id": "session-one", "createdAt": 1750000000000},
        {"type": "user/message", "data": {"role": "user", "content": [{"type": "text", "text": "inspect project"}]}},
    ]
    old = write_session(tmp_path, events, session_dir_name="old")
    os.utime(old, (1, 1))
    parser = DshParser(base_path=tmp_path / "sessions")
    assert parser.parse_all() == []

    write_session(tmp_path, events, session_dir_name="copy-one")
    write_session(tmp_path, events, session_dir_name="copy-two")
    assert len(DshParser(base_path=tmp_path / "sessions", max_age_days=0).parse_all()) == 1


def test_parse_all_preserves_distinct_source_session_ids(tmp_path):
    for session_id in ("session-review", "review"):
        write_session(
            tmp_path,
            [
                {"type": "session", "version": 3, "id": session_id, "createdAt": 1750000000000},
                {
                    "type": "user/message",
                    "data": {"role": "user", "content": [{"type": "text", "text": "inspect project"}]},
                },
            ],
            session_dir_name=session_id,
        )

    entries = DshParser(base_path=tmp_path / "sessions", max_age_days=0).parse_all()
    assert {entry.session_id for entry in entries} == {"dsh_session-review", "dsh_review"}


def test_resumed_export_updates_existing_snapshot(tmp_path):
    events = [
        {"type": "session", "version": 3, "id": "session-resume", "createdAt": 1750000000000},
        {
            "type": "user/message",
            "data": {
                "id": "u1",
                "role": "user",
                "content": [{"type": "text", "text": "inspect project"}],
            },
        },
    ]
    path = write_session(tmp_path, events)
    observer = AgentObserver(output_dir=tmp_path / "output", max_age_days=0)
    observer.dsh_parser = DshParser(base_path=tmp_path / "sessions", max_age_days=0)
    event = observer.ingest_all("dsh")[0][0]
    saved = observer.save_sessions_to_individual_files([event], tmp_path / "output")
    assert observer.filter_entries_by_existing_files([event], tmp_path / "output") == []

    resumed = {
        "type": "assistant/message",
        "time": 1750000001000,
        "data": {"message": {"id": "a1", "role": "assistant", "content": [{"type": "text", "text": "done"}]}},
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(resumed) + "\n")
    updated = observer.ingest_all("dsh")[0][0]
    selected = observer.filter_entries_by_existing_files([updated], tmp_path / "output")
    assert len(selected) == 1
    assert observer.save_sessions_to_individual_files(selected, tmp_path / "output") == saved


def test_parse_all_handles_missing_directory(tmp_path):
    assert DshParser(base_path=tmp_path / "missing").parse_all() == []


def test_parse_all_reads_workspace_dsh_home(monkeypatch, tmp_path):
    monkeypatch.setenv("DSH_HOME", str(tmp_path))
    write_session(
        tmp_path,
        [
            {"type": "session", "version": 3, "id": "session-one", "createdAt": 1750000000000, "cwd": "/work"},
            {
                "type": "user/message",
                "time": 1750000001000,
                "data": {"role": "user", "content": [{"type": "text", "text": "hello"}]},
            },
            {
                "type": "assistant/message",
                "time": 1750000002000,
                "data": {"message": {"role": "assistant", "content": [{"type": "text", "text": "hello back"}]}},
            },
        ],
    )
    entries = DshParser(max_age_days=0).parse_all()
    assert len(entries) == 1
