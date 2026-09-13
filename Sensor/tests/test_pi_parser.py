"""Contract fixtures for Pi v1-v3 session files; no account or local agent required."""

import json
import os
from pathlib import Path

import pytest

from adr_sensor.observer import AgentObserver
from adr_sensor.parsers.pi_parser import PiParser


def header(version=3, session_id="example"):
    return {
        "type": "session",
        "version": version,
        "id": session_id,
        "timestamp": "2026-01-01T00:00:00Z",
        "cwd": "C:\\work\\project",
    }


def message(entry_id, parent, role, content, **kwargs):
    return {
        "type": "message",
        "id": entry_id,
        "parentId": parent,
        "timestamp": "2026-01-01T00:00:01Z",
        "message": {"role": role, "content": content, **kwargs},
    }


def call(entry_id="a", parent="u", call_id="c"):
    return message(
        entry_id,
        parent,
        "assistant",
        [
            {"type": "text", "text": "Reading file"},
            {"type": "toolCall", "id": call_id, "name": "read", "arguments": {"path": "file.txt"}},
        ],
        model="model-test",
        provider="provider-test",
        usage={"input": 10, "output": 2, "totalTokens": 12},
    )


def result(entry_id="r", parent="a", text="result", call_id="c", **kwargs):
    return message(
        entry_id,
        parent,
        "toolResult",
        [{"type": "text", "text": text}],
        toolCallId=call_id,
        toolName="read",
        isError=False,
        **kwargs,
    )


def write(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
    return path


def test_home_and_override_precedence(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("PI_CODING_AGENT_DIR", "")
    monkeypatch.setenv("PI_CODING_AGENT_SESSION_DIR", "")
    assert PiParser().base_path == tmp_path / ".pi/agent/sessions"
    monkeypatch.setenv("PI_CODING_AGENT_DIR", str(tmp_path / "agent"))
    assert PiParser().base_path == tmp_path / "agent/sessions"
    monkeypatch.setenv("PI_CODING_AGENT_SESSION_DIR", str(tmp_path / "sessions"))
    assert PiParser().base_path == tmp_path / "sessions"
    assert PiParser(base_path=tmp_path / "explicit").base_path == tmp_path / "explicit"


@pytest.mark.parametrize("version", [1, 2, 3])
def test_versions_tools_usage_and_read_only(tmp_path, version):
    rows = [
        header(version),
        message("u", None, "user", "Inspect the project"),
        call(),
        result(text="secret:" + "x" * 4000),
    ]
    if version == 1:
        for row in rows[1:]:
            row.pop("id")
            row.pop("parentId")
    path = write(tmp_path / "--project--/session.jsonl", rows)
    before = path.read_bytes(), path.stat().st_mtime_ns
    entry = PiParser(base_path=tmp_path).parse_all()[0]
    assert entry.source == "pi" and entry.project_path == "C:\\work\\project"
    assert len(entry.chat_history) == 2
    tool = entry.chat_history[1].tools[0]
    assert tool.result == "secret:" + "x" * 4000
    assert tool.status == "success" and tool.arguments == {"path": "file.txt"}
    assert entry.model == "model-test"
    assert entry.token_usage["cumulative"]["total_tokens"] == 12
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before


def test_sibling_branch_call_ids_are_not_cross_correlated(tmp_path):
    rows = [
        header(),
        message("u", None, "user", "Inspect the project"),
        call("a", "u", "same-call"),
        call("b", "u", "same-call"),
        result("ra", "a", "branch A", "same-call"),
        result("rb", "b", "branch B", "same-call"),
    ]
    entry = PiParser().parse_file(write(tmp_path / "session.jsonl", rows))
    tools = [msg.tools[0] for msg in entry.chat_history if msg.tools]
    assert [tool.result for tool in tools] == ["branch A", "branch B"]
    assert entry.session_context["history_scope"] == "all_recorded_branches"
    assert entry.session_context["entries"][2]["parentId"] == "u"


def test_metadata_reasoning_images_and_custom_messages(tmp_path):
    rows = [header(), message("u", None, "user", "Inspect the project"), call()]
    rows[-1]["message"]["content"].extend(
        [{"type": "thinking", "thinking": "Recorded plan"}, {"type": "image", "data": "abc", "mimeType": "image/png"}]
    )
    rows += [
        {"type": "compaction", "id": "compact", "parentId": "a", "summary": "Summary", "usage": {"totalTokens": 5}},
        {"type": "branch_summary", "id": "branch", "parentId": "u", "fromId": "compact", "summary": "Old branch"},
        {"type": "custom_message", "id": "custom", "parentId": "branch", "content": "Extension instructions"},
        {"type": "model_change", "id": "model", "parentId": "custom", "modelId": "next-model"},
    ]
    entry = PiParser().parse_file(write(tmp_path / "session.jsonl", rows))
    assert entry.chat_history[-1].role == "system"
    assert entry.model == "next-model"
    assert entry.token_usage["cumulative"]["total_tokens"] == 17
    assert entry.session_context["entries"][1]["content_parts"][-2]["thinking"] == "Recorded plan"
    assert entry.session_context["entries"][2]["summary"] == "Summary"
    assert entry.session_context["entries"][3]["fromId"] == "compact"


def test_multiple_results_for_shared_ancestor_preserve_first_and_additional_results(tmp_path):
    rows = [
        header(),
        message("u", None, "user", "Inspect the project"),
        call(),
        result("first", "a", "original result"),
        result("second", "a", "alternate result"),
    ]
    entry = PiParser().parse_file(write(tmp_path / "session.jsonl", rows))
    tools = [tool for msg in entry.chat_history for tool in msg.tools]
    assert len(tools) == 1 and tools[0].result == "original result"
    assert entry.chat_history[-1].role == "tool"
    assert entry.chat_history[-1].content == "alternate result"
    metadata = entry.session_context["entries"][-1]
    assert metadata["additional_tool_result"] is True
    assert metadata["tool_call_entry_id"] == "a"
    assert metadata["parentId"] == "a"


def test_legacy_extension_messages_and_image_only_content_are_retained(tmp_path):
    rows = [
        header(2),
        message("u", None, "user", [{"type": "image", "data": "abc", "mimeType": "image/png"}]),
        message("hook", "u", "hookMessage", "Extension instructions", customType="extension"),
        message("a", "hook", "assistant", [{"type": "thinking", "thinking": "Recorded thought"}]),
    ]
    entry = PiParser(base_path=tmp_path).parse_file(write(tmp_path / "session.jsonl", rows))
    assert [msg.role for msg in entry.chat_history] == ["user", "system", "assistant"]
    assert entry.session_context["entries"][0]["content_parts"][0]["data"] == "abc"
    assert entry.session_context["entries"][1]["message_metadata"]["customType"] == "extension"
    assert entry.session_context["entries"][2]["content_parts"][0]["thinking"] == "Recorded thought"


def test_nested_usage_and_compaction_are_counted_once(tmp_path):
    rows = [
        header(),
        call(parent=None),
        result(usage={"input": 4, "output": 2, "cacheRead": 3, "totalTokens": 9, "cost": {"total": 0.1}}),
        {"type": "compaction", "id": "comp", "parentId": "r", "summary": "Compact", "usage": {"totalTokens": 5}},
        {"type": "branch_summary", "id": "b", "parentId": None, "summary": "Branch", "usage": {"totalTokens": 6}},
    ]
    entry = PiParser().parse_file(write(tmp_path / "session.jsonl", rows))
    assert entry.token_usage["cumulative"] == {
        "input_tokens": 14,
        "output_tokens": 4,
        "cached_input_tokens": 3,
        "total_tokens": 32,
    }
    assert entry.session_context["entries"][1]["message_metadata"]["usage"]["cost"]["total"] == 0.1


def test_errors_pending_orphan_and_user_shell_attribution(tmp_path):
    failed = result(text="Access denied")
    failed["message"]["isError"] = True
    rows = [
        header(),
        message("u", None, "user", "Inspect project"),
        call(),
        failed,
        call("pending", "r", "pending-call"),
        result("orphan", "u", "Detached result", "missing"),
        message("shell", "orphan", "bashExecution", None, command="pwd", output="/work", exitCode=0, cancelled=False),
    ]
    entry = PiParser().parse_file(write(tmp_path / "session.jsonl", rows))
    assert entry.chat_history[1].tools[0].error == "Access denied"
    assert entry.chat_history[2].tools[0].status == "pending"
    assert entry.chat_history[3].role == "tool" and not entry.chat_history[3].tools
    assert entry.chat_history[4].role == "user"
    assert entry.chat_history[4].tools[0].tool_type == "terminal_command"
    assert entry.chat_history[4].tools[0].result == "/work"


def test_bad_files_and_unrecognized_versions_do_not_block_other_sessions(tmp_path):
    write(tmp_path / "good.jsonl", [header(), message("u", None, "user", "Inspect project")])
    write(tmp_path / "future.jsonl", [header(99), message("u", None, "user", "Inspect project")])
    write(tmp_path / "wrong.jsonl", [{"type": "unrelated", "content": "Do not ingest"}])
    path = tmp_path / "good.jsonl"
    with path.open("a", encoding="utf-8") as handle:
        handle.write('[]\n{"partial":')
    entries = PiParser(base_path=tmp_path).parse_all()
    assert len(entries) == 1
    assert entries[0].session_context["malformed_records"] == 2
    assert PiParser(base_path=tmp_path / "missing").parse_all() == []


def test_age_filter_and_deduplicate_copies(tmp_path):
    rows = [header(), message("u", None, "user", "Inspect project")]
    path = write(tmp_path / "old/session.jsonl", rows)
    os.utime(path, (1, 1))
    assert PiParser(base_path=tmp_path).parse_all() == []
    assert len(PiParser(max_age_days=0, base_path=tmp_path).parse_all()) == 1
    write(tmp_path / "copy/session.jsonl", rows)
    assert len(PiParser(max_age_days=0, base_path=tmp_path).parse_all()) == 1


def test_resumed_export_updates_without_duplicate_files(tmp_path):
    path = write(tmp_path / "input/session.jsonl", [header(), message("u", None, "user", "Inspect project"), call()])
    observer = AgentObserver(output_dir=tmp_path / "output", max_age_days=0)
    assert observer.pi_parser.max_age_days == 0
    observer.pi_parser = PiParser(base_path=tmp_path / "input")
    event = observer.ingest_all("pi")[0][0]
    saved = observer.save_sessions_to_individual_files([event], tmp_path / "output")
    assert observer.filter_entries_by_existing_files([event], tmp_path / "output") == []
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(result()) + "\n")
    resumed = observer.ingest_all("pi")[0][0]
    assert resumed.timestamp == event.timestamp
    selected = observer.filter_entries_by_existing_files([resumed], tmp_path / "output")
    assert len(selected) == 1
    assert observer.save_sessions_to_individual_files(selected, tmp_path / "output") == saved
    assert json.loads(saved[0].read_text(encoding="utf-8"))["chat_history"][1]["tools"][0]["result"] == "result"
