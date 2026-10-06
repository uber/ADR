import json
import sqlite3

from adr_sensor.parsers.codex_parser import CodexParser
from adr_sensor.utils.codex_context import codex_session_context


def write_rollout(path, header):
    path.parent.mkdir(parents=True, exist_ok=True)
    records = [
        {"type": "session_meta", "payload": header},
        # Copied parent headers must never redefine the physical child/fork.
        {"type": "session_meta", "payload": {"id": "unrelated", "forked_from_id": "wrong"}},
        {"type": "response_item", "payload": {
            "type": "message", "role": "user",
            "content": [{"type": "input_text", "text": "Synthetic inherited request"}],
        }},
    ]
    path.write_text("".join(json.dumps(row) + "\n" for row in records))


def test_codex_preserves_child_and_fork_lineage_without_removing_messages(tmp_path):
    header = {
        "id": "child", "forked_from_id": "fork-origin",
        "source": {"subagent": {"thread_spawn": {
            "parent_thread_id": "parent", "agent_path": "/root/review_changes",
            "agent_nickname": "Synthetic reviewer",
        }}},
    }
    rollout = tmp_path / "child.jsonl"
    write_rollout(rollout, header)
    event = CodexParser().parse_jsonl_file(rollout)
    assert event.session_id == "codex_child"
    assert event.session_context["parent_session_id"] == "codex_parent"
    assert event.session_context["forked_from_session_id"] == "codex_fork-origin"
    assert event.session_context["session_kind"] == "subagent"
    assert event.session_context["agent_path"] == "/root/review_changes"
    assert event.chat_history[0].content == "Synthetic inherited request"


def test_codex_catalog_names_are_retained_and_catalog_is_read_only(tmp_path):
    root = tmp_path / "codex"
    rollout = root / "sessions" / "parent.jsonl"
    write_rollout(rollout, {"id": "parent"})
    catalog_path = root / "state_5.sqlite"
    connection = sqlite3.connect(catalog_path)
    connection.execute("CREATE TABLE threads(id TEXT,rollout_path TEXT,name TEXT,source TEXT)")
    connection.execute("INSERT INTO threads VALUES (?,?,?,?)", (
        "parent", str(rollout), "A meaningful native title", "cli",
    ))
    connection.commit()
    connection.close()
    before = catalog_path.read_bytes()
    parser = CodexParser(max_age_days=0)
    parser.codex_home = root
    parser.base_path = root / "sessions"
    event = parser.parse_all()[0]
    assert event.session_context["session_title"] == "A meaningful native title"
    assert event.session_context["session_kind"] == "conversation"
    assert catalog_path.read_bytes() == before


def test_malformed_metadata_is_not_interpreted_as_a_relationship():
    for value in (None, "cli", "invalid{", [], {"subagent": "invalid"}, {"subagent": {"thread_spawn": []}}):
        context = codex_session_context({"id": "session", "source": value})
        assert "parent_session_id" not in context
    context = codex_session_context({"id": "same", "forked_from_id": "same", "title": ["not text"]})
    assert context == {"session_kind": "conversation"}
