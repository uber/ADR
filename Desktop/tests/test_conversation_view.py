import copy
import importlib.util
import json
import shutil
import sqlite3
import subprocess
from pathlib import Path

import pytest
from conftest import sample_session

from adr_desktop.config import canonical, prepare_state_dir
from adr_desktop.conversation_view import is_setup_message, recover_codex_metadata, session_title
from adr_desktop.store import Store


def conversation(identifier, *, parent=None, fork=None, label=None, project="/work", username="synthetic"):
    payload = sample_session(source="codex", session_id="codex_" + identifier, project=project)
    payload["username"] = username
    payload["chat_history"].insert(0, {
        "role": "user", "content": "<environment_context>synthetic setup</environment_context>", "tools": [],
    })
    payload["session_context"] = {}
    if parent:
        payload["session_context"]["parent_session_id"] = "codex_" + parent
    if fork:
        payload["session_context"]["forked_from_session_id"] = "codex_" + fork
    if label:
        payload["session_context"]["agent_path"] = "/root/" + label
    return payload


def identifier(store, source_id):
    return store.one("SELECT id FROM sessions WHERE source_session_id=?", ("codex_" + source_id,))["id"]


@pytest.mark.parametrize("setup", [
    "<environment_context>cwd=/synthetic</environment_context>",
    "<recommended_plugins>synthetic</recommended_plugins>",
    "# AGENTS.md instructions for /synthetic\n<INSTRUCTIONS>synthetic</INSTRUCTIONS>",
    "<skills_instructions>synthetic</skills_instructions>\n<apps_instructions>synthetic</apps_instructions>",
])
def test_setup_does_not_become_title_or_get_removed(setup):
    payload = sample_session(content=setup)
    payload["chat_history"].append({"role": "user", "content": "Fix the actual bug", "tools": []})
    original = copy.deepcopy(payload)
    assert session_title(payload) == "Fix the actual bug"
    assert is_setup_message(payload["chat_history"][0])
    assert payload == original


def test_mixed_setup_and_real_request_stays_visible():
    message = {
        "role": "user",
        "content": "<environment_context>synthetic</environment_context>\nFix the actual bug",
    }
    payload = sample_session()
    payload["chat_history"] = [message]
    assert session_title(payload) == "Fix the actual bug"
    assert not is_setup_message(message)
    assert not is_setup_message({"role": "user", "content": "<example>real question</example>"})
    assert not is_setup_message({"role": "developer", "content": "setup", "tools": [{"tool_name": "Read"}]})
    assert session_title(payload, native_title="<environment_context>truncated setup") == "Fix the actual bug"


def test_children_are_grouped_but_forks_and_same_title_sessions_remain(runtime):
    store = runtime.store
    for payload in (
        conversation("parent"),
        conversation("child", parent="parent", label="inspect_backend"),
        conversation("grandchild", parent="child", label="check_tests"),
        conversation("fork", fork="parent"),
        conversation("unrelated"),
        conversation("orphan", parent="missing"),
    ):
        store.ingest(payload)
    grouped = store.sessions(grouped=True)
    assert grouped["total"] == 4
    assert {row["source_session_id"] for row in grouped["items"]} == {
        "codex_parent", "codex_fork", "codex_unrelated", "codex_orphan",
    }
    assert store.sessions()["total"] == 6
    parent_id = identifier(store, "parent")
    children = store.session_children(parent_id)
    assert children["total"] == 1
    child = children["items"][0]
    assert child["title"] == "inspect backend"
    assert child["kind"] == "subagent" and child["parent"]["id"] == parent_id
    assert child["child_count"] == 1
    assert store.session_children(child["id"])["items"][0]["title"] == "check tests"
    fork = store.session(identifier(store, "fork"))
    assert fork["kind"] == "fork" and fork["forked_from"]["id"] == parent_id
    assert not fork["parent"]
    assert store.session(identifier(store, "orphan"))["parent"] is None


@pytest.mark.parametrize("source", ["claude", "gemini"])
def test_existing_non_codex_parent_metadata_is_respected(runtime, source):
    parent = sample_session(source=source, session_id=source + "_parent")
    child = sample_session(source=source, session_id=source + "_child")
    child["session_context"] = {
        "parent_session_id": "parent" if source == "gemini" else parent["session_id"],
        "agent_id": "synthetic-worker",
    }
    runtime.store.ingest(parent)
    runtime.store.ingest(child)
    grouped = runtime.store.sessions(grouped=True)
    assert grouped["total"] == 1 and grouped["items"][0]["child_count"] == 1
    children = runtime.store.session_children(grouped["items"][0]["id"])["items"]
    assert children[0]["source_session_id"] == child["session_id"]
    assert children[0]["title"] == "synthetic-worker"


def test_grouping_pagination_never_drops_children_or_counts_them_as_roots(runtime):
    store = runtime.store
    store.ingest(conversation("parent"))
    for index in range(35):
        store.ingest(conversation(f"child-{index}", parent="parent", label=f"task_{index}"))
    parent_id = identifier(store, "parent")
    assert store.sessions(grouped=True, limit=1)["total"] == 1
    first = store.session_children(parent_id, limit=30)
    second = store.session_children(parent_id, limit=30, offset=first["next_offset"])
    assert len(first["items"]) == 30 and len(second["items"]) == 5
    assert second["next_offset"] is None
    assert len({row["id"] for row in first["items"] + second["items"]}) == 35


def test_scoped_metadata_does_not_leak_parent_titles_or_other_project_children(runtime):
    store = runtime.store
    for payload in (
        conversation("parent", project="/secret"),
        conversation("child", parent="parent", project="/allowed"),
        conversation("other", parent="parent", project="/elsewhere"),
        conversation("fork", fork="parent", project="/allowed"),
    ):
        store.ingest(payload)
    assert store.sessions(grouped=True, project="/allowed")["total"] == 2
    child_id = identifier(store, "child")
    assert store.session(child_id, project="/allowed")["parent"] is None
    fork = store.session(identifier(store, "fork"), project="/allowed")
    assert fork["forked_from"] is None
    assert store.session_children(identifier(store, "parent"), project="/allowed") is None
    matches = store.search_history("validation", project="/allowed")
    assert matches["total"] == 2
    assert all(row["parent"] is None and row["forked_from"] is None for row in matches["items"])


def test_lineage_does_not_merge_different_users_and_cannot_form_hidden_cycles(runtime):
    store = runtime.store
    store.ingest(conversation("parent", username="first"))
    store.ingest(conversation("child", parent="parent", username="second"))
    store.ingest(conversation("cycle-a", parent="cycle-b"))
    store.ingest(conversation("cycle-b", parent="cycle-a"))
    store.ingest(conversation("self", parent="self"))
    assert store.sessions(grouped=True)["total"] == 4
    assert store.session(identifier(store, "child"))["parent"] is None
    assert store.session(identifier(store, "self"))["parent"] is None
    assert sum(row["child_count"] for row in store.sessions(grouped=True)["items"]) == 1


def test_ui_projection_and_export_preserve_repeated_messages_and_all_snapshots(client, runtime, owner):
    payload = conversation("parent")
    repeated = {"role": "developer", "content": "Synthetic recurring setup", "tools": []}
    payload["chat_history"][1:1] = [copy.deepcopy(repeated) for _ in range(100)]
    real = {"role": "user", "content": "Please repeat the test", "tools": []}
    payload["chat_history"].extend([real, copy.deepcopy(real)])
    runtime.store.ingest(payload)
    parent_id = identifier(runtime.store, "parent")
    result = client.get(f"/api/sessions/{parent_id}", headers=owner).json()
    assert len(result["presentation"]["setup_message_indexes"]) == 101
    assert result["payload"] == payload
    exported = client.get(f"/api/sessions/{parent_id}/export", headers=owner)
    assert exported.json() == payload
    assert result["revisions"] == 1
    runtime.store.ingest(payload)
    assert runtime.store.session(parent_id)["revisions"] == 1


def test_children_endpoint_requires_owner_and_search_keeps_child_matches(client, runtime, owner):
    for payload in (conversation("parent"), conversation("child", parent="parent", label="test_worker")):
        runtime.store.ingest(payload)
    parent_id = identifier(runtime.store, "parent")
    route = f"/api/sessions/{parent_id}/children"
    assert client.get(route).status_code == 401
    assert client.get(route, headers=owner).json()["items"][0]["kind"] == "subagent"
    assert client.get("/api/sessions/missing/children", headers=owner).status_code == 404
    assert client.get("/api/sessions", headers=owner).json()["total"] == 1
    assert client.get("/api/sessions?grouped=false", headers=owner).json()["total"] == 2
    assert client.get("/api/history/search?q=validation", headers=owner).json()["total"] == 2


def test_old_history_migration_recovers_metadata_without_rewriting_payloads(tmp_path, monkeypatch):
    home = tmp_path / "home"
    codex_home = home / ".codex"
    codex_home.mkdir(parents=True)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.delenv("CODEX_HOME", raising=False)
    directory = prepare_state_dir(tmp_path / "state")
    store = Store(directory)
    payloads = [conversation(name) for name in ("parent", "child", "fork")]
    for payload in payloads:
        store.ingest(payload)
    store.setting("recording", False)
    store.setting("interval_seconds", 3600)
    before = store.rows("SELECT * FROM snapshots ORDER BY digest")
    original_ids = store.rows("SELECT id,digest FROM sessions ORDER BY id")
    store.execute("DROP TABLE session_metadata")
    store.execute("PRAGMA user_version=2")
    store.close()

    catalog = sqlite3.connect(codex_home / "state_5.sqlite")
    catalog.execute("CREATE TABLE threads(id TEXT,source TEXT,name TEXT,rollout_path TEXT)")
    for name in ("parent", "child", "fork"):
        source = {"subagent": {"thread_spawn": {
            "parent_thread_id": "parent", "agent_path": "/root/inspect_backend",
        }}} if name == "child" else "cli"
        header = {"id": name, "source": source}
        if name == "fork":
            header["forked_from_id"] = "parent"
        rollout = codex_home / "sessions" / f"{name}.jsonl"
        rollout.parent.mkdir(exist_ok=True)
        rollout.write_text(canonical({"type": "session_meta", "payload": header}) + "\n")
        catalog.execute("INSERT INTO threads VALUES (?,?,?,?)", (
            name, canonical(source), "Actual project title" if name == "parent" else "", str(rollout),
        ))
    catalog.commit()
    catalog.close()
    catalog_before = (codex_home / "state_5.sqlite").read_bytes()
    migrated = Store(directory)
    try:
        assert migrated.rows("SELECT * FROM snapshots ORDER BY digest") == before
        assert migrated.rows("SELECT id,digest FROM sessions ORDER BY id") == original_ids
        assert migrated.settings()["recording"] is False
        assert migrated.settings()["interval_seconds"] == 3600
        assert migrated.sessions(grouped=True)["total"] == 2
        parent = migrated.session(identifier(migrated, "parent"))
        assert parent["title"] == "Actual project title" and parent["child_count"] == 1
        assert migrated.session(identifier(migrated, "child"))["title"] == "inspect backend"
        assert migrated.session(identifier(migrated, "fork"))["forked_from"]["id"] == parent["id"]
        assert (codex_home / "state_5.sqlite").read_bytes() == catalog_before
        # An unchanged re-capture without new metadata must not undo the backfill.
        migrated.ingest(payloads[1])
        assert migrated.session(identifier(migrated, "child"))["parent"]["id"] == parent["id"]
    finally:
        migrated.close()
    reopened = Store(directory)
    try:
        assert reopened.rows("SELECT * FROM snapshots ORDER BY digest") == before
        assert reopened.sessions(grouped=True)["total"] == 2
    finally:
        reopened.close()


def test_legacy_recovery_is_bounded_and_does_not_follow_untrusted_paths(tmp_path, monkeypatch):
    home = tmp_path / "home"
    root = home / ".codex"
    root.mkdir(parents=True)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.delenv("CODEX_HOME", raising=False)
    payload = conversation("target")
    for content in ("[]", "x" * (512 * 1024 + 1), canonical({
        "type": "session_meta", "payload": {"id": "different", "forked_from_id": "parent"},
    })):
        path = root / "malformed.jsonl"
        path.write_text(content)
        payload["raw_log_path"] = str(path)
        assert recover_codex_metadata([payload]) == {}
    outside = tmp_path / "outside.jsonl"
    outside.write_text(canonical({
        "type": "session_meta", "payload": {"id": "target", "forked_from_id": "parent"},
    }))
    payload["raw_log_path"] = str(outside)
    assert recover_codex_metadata([payload]) == {}
    symlink = root / "escape.jsonl"
    symlink.symlink_to(outside)
    payload["raw_log_path"] = str(symlink)
    assert recover_codex_metadata([payload]) == {}


def test_browser_groups_setup_only_and_never_removes_real_repeated_requests():
    node = shutil.which("node")
    if not node:
        playwright = importlib.util.find_spec("playwright")
        if playwright and playwright.origin:
            candidate = Path(playwright.origin).parent / "driver" / "node"
            if candidate.is_file():
                node = str(candidate)
    if not node:
        pytest.skip("A JavaScript runtime is required for the UI projection test")
    source = Path(__file__).resolve().parents[1] / "adr_desktop" / "web" / "app.js"
    script = """
const fs = require("node:fs"), vm = require("node:vm"), assert = require("node:assert/strict");
const source = fs.readFileSync(process.argv[1], "utf8");
const start = source.indexOf("function conversationBlocks(");
const end = source.indexOf("\\nfunction setupBundle(", start);
const context = vm.createContext({});
vm.runInContext(source.slice(start, end), context);
const messages = [
  { role: "developer", content: "Repeated setup", tools: [] },
  { role: "developer", content: "Repeated setup", tools: [] },
  { role: "user", content: "<environment_context>setup</environment_context>", tools: [] },
  { role: "user", content: "Run the check again", tools: [] },
  { role: "user", content: "Run the check again", tools: [] },
  { role: "developer", content: "Tool-bearing setup", tools: [{tool_name: "Read"}] },
];
const before = JSON.stringify(messages);
const blocks = context.conversationBlocks(messages, [0,1,2,5]);
assert.equal(blocks[0].kind, "setup");
assert.equal(blocks[0].entries.length, 2);
assert.equal(blocks[0].entries[0].count, 2);
assert.equal(blocks.filter(x => x.kind === "message" && x.message.role === "user").length, 2);
assert.equal(blocks.filter(x => x.kind === "tools").length, 1);
assert.equal(JSON.stringify(messages), before);
console.log(JSON.stringify({ok:true}));
"""
    result = subprocess.run(
        [node, "-e", script, str(source)], capture_output=True, text=True, check=True, timeout=10,
    )
    assert json.loads(result.stdout) == {"ok": True}
