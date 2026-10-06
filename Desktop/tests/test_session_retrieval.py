"""Sessions retrieval projections use synthetic data and never change stored snapshots."""

import copy
import importlib.util
import json
import shutil
import subprocess
import zlib
from pathlib import Path

import pytest
from conftest import grant_token, sample_session

from adr_desktop.config import canonical
from adr_desktop.store import RETRIEVAL_INDEX_VERSION, Store


@pytest.fixture(autouse=True)
def synthetic_retrieval_home(tmp_path, monkeypatch):
    # Metadata backfills can consult Codex catalogs. Never inherit the user's
    # CODEX_HOME, including when this module is run outside the synthetic shell.
    home = tmp_path / "retrieval-home"
    codex = home / ".codex"
    codex.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("CODEX_HOME", str(codex))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))


def seed(runtime, identifier, *, source="claude", project="/work/garden", timestamp=None, parent=None):
    payload = sample_session(source=source, session_id=identifier, project=project)
    if timestamp:
        payload["timestamp"] = timestamp
    if parent:
        payload["session_context"] = {"parent_session_id": parent}
    runtime.store.ingest(payload)
    return runtime.store.one(
        "SELECT id FROM sessions WHERE source_session_id=?", (identifier,),
    )["id"]


def test_owner_facets_are_read_only_exact_projects_and_include_captured_sources(client, owner, runtime):
    seed(runtime, "garden", project="/work/garden", source="codex")
    seed(runtime, "other-garden", project="/other/garden", source="opencode")
    seed(runtime, "missing", project="")
    assert client.get("/api/sessions/filters").status_code == 401
    result = client.get("/api/sessions/filters", headers=owner)
    assert result.status_code == 200
    assert result.json()["projects"] == [
        {"project": "/other/garden", "sessions": 1},
        {"project": "/work/garden", "sessions": 1},
    ]
    assert result.json()["sources"] == ["claude", "codex", "opencode"]
    exact = client.get("/api/sessions", params={"project": "/work/garden"}, headers=owner).json()
    assert exact["total"] == 1
    assert exact["items"][0]["project"] == "/work/garden"


def test_local_date_bounds_are_utc_half_open_and_apply_to_search(client, owner, runtime):
    # A local UTC+02 calendar day, with both adjacent boundaries represented.
    seed(runtime, "before", timestamp="2026-10-03T21:59:59Z")
    inside = seed(runtime, "start", timestamp="2026-10-04T00:00:00+02:00")
    seed(runtime, "end", timestamp="2026-10-04T22:00:00Z")
    params = {"since": "2026-10-04T00:00:00+02:00", "before": "2026-10-05T00:00:00+02:00"}
    listing = client.get("/api/sessions", params=params, headers=owner).json()
    assert [row["id"] for row in listing["items"]] == [inside]
    results = client.get("/api/history/search", params={**params, "q": "validation"}, headers=owner).json()
    assert [row["id"] for row in results["items"]] == [inside]


@pytest.mark.parametrize(
    "params",
    [
        {"since": "not-a-date"},
        {"since": "2026-10-05"},  # Never silently assume the browser's timezone.
        {"since": "2026-10-06T00:00:00Z", "before": "2026-10-05T00:00:00Z"},
        {"since": "2026-10-05T00:00:00Z", "before": "2026-10-05T00:00:00Z"},
    ],
)
def test_bad_dates_fail_without_modifying_history(client, owner, runtime, params):
    seed(runtime, "kept")
    for route in ("/api/sessions", "/api/history/search"):
        response = client.get(route, params={**params, "q": "validation"}, headers=owner)
        assert response.status_code == 400
    assert runtime.store.sessions()["total"] == 1


def test_filters_combine_without_hiding_child_matches_or_crossing_projects(client, owner, runtime):
    seed(runtime, "parent", source="codex", timestamp="2026-09-01T10:00:00Z")
    child = seed(runtime, "child", source="codex", parent="parent", timestamp="2026-10-05T10:00:00Z")
    seed(runtime, "other-project", source="codex", project="/work/garden-copy")
    seed(runtime, "other-agent", source="claude")
    params = {
        "source": "codex", "project": "/work/garden", "since": "2026-10-05T00:00:00Z",
        "grouped": "false",
    }
    rows = client.get("/api/sessions", params=params, headers=owner).json()["items"]
    assert [row["id"] for row in rows] == [child]
    assert rows[0]["parent"]["title"] == "Add input validation"
    result = client.get(
        "/api/history/search", params={**params, "q": "validation"}, headers=owner,
    ).json()
    assert [row["id"] for row in result["items"]] == [child]


def test_preview_prefers_answer_over_setup_and_keeps_every_byte(client, owner, runtime):
    payload = sample_session()
    answer = "Use the validated path rather than the raw input. " * 80
    payload["chat_history"].insert(0, {"role": "developer", "content": "Synthetic setup", "tools": []})
    payload["chat_history"].append({"role": "assistant", "content": answer, "tools": []})
    payload["chat_history"].append({
        "role": "assistant", "content": "[Assistant decided to use a tool]",
        "tools": [{"tool_name": "Read", "arguments": {}, "result": "Synthetic result"}],
    })
    runtime.store.ingest(payload)
    result = client.get("/api/sessions", headers=owner).json()["items"][0]
    assert result["preview"]["label"] == "Answer"
    assert result["preview"]["text"].startswith("Use the validated path")
    assert len(result["preview"]["text"]) <= 281
    assert result["preview"]["message_index"] == 3
    full = client.get(f"/api/sessions/{result['id']}", headers=owner).json()
    exported = client.get(f"/api/sessions/{result['id']}/export", headers=owner).json()
    assert full["payload"] == payload == exported
    assert full["revisions"] == 1


def test_search_preview_centers_on_deep_tool_result_and_stays_plain_text(client, owner, runtime):
    payload = sample_session()
    tool_result = "Unrelated fixture output. " * 3000
    tool_result += " The cedarneedle retry works. <img src=x onerror=synthetic()> "
    tool_result += "More synthetic output. " * 3000
    payload["chat_history"][1]["tools"][0]["result"] = tool_result
    runtime.store.ingest(payload)
    result = client.get("/api/history/search?q=cedarneedle", headers=owner).json()["items"][0]
    assert result["preview"]["label"] == "Read result"
    assert "cedarneedle" in result["preview"]["text"]
    assert result["preview"]["message_index"] == 1
    assert result["preview"]["tool_index"] == 0
    assert len(result["preview"]["text"]) <= 282
    assert runtime.store.session(result["id"])["payload"] == payload


def test_preview_changes_with_current_revision_not_older_snapshot(client, owner, runtime):
    payload = sample_session()
    runtime.store.ingest(payload)
    newer = copy.deepcopy(payload)
    newer["timestamp"] = "2026-10-05T10:00:00Z"
    newer["chat_history"].append({"role": "assistant", "content": "The current answer.", "tools": []})
    runtime.store.ingest(newer)
    runtime.store.ingest(payload)
    result = client.get("/api/sessions", headers=owner).json()["items"][0]
    assert result["preview"]["text"] == "The current answer."
    assert runtime.store.session(result["id"])["revisions"] == 2


def test_newest_sort_and_pagination_keep_totals_stable(client, owner, runtime):
    oldest = seed(runtime, "one", timestamp="2026-10-01T00:00:00Z")
    newest = seed(runtime, "two", timestamp="2026-10-03T00:00:00Z")
    seed(runtime, "three", timestamp="2026-10-02T00:00:00Z")
    params = {"q": "validation", "sort": "newest", "limit": 1}
    first = client.get("/api/history/search", params=params, headers=owner).json()
    assert first["total"] == 3 and first["next_offset"] == 1
    assert first["items"][0]["id"] == newest
    last = client.get("/api/history/search", params={**params, "offset": 2}, headers=owner).json()
    assert last["items"][0]["id"] == oldest and last["next_offset"] is None
    assert client.get("/api/history/search?q=validation&sort=unknown", headers=owner).status_code == 422


def test_native_titles_and_subagent_names_are_searchable_without_duplicate_results(runtime):
    parent = sample_session(session_id="named")
    parent["session_context"] = {"session_title": "Lighthouse refactor"}
    child = sample_session(session_id="named-child")
    child["session_context"] = {"parent_session_id": "named", "agent_path": "/root/accessibility_review"}
    for payload in (parent, child):
        runtime.store.ingest(payload)
    titled = runtime.store.search_history("lighthouse refactor", previews=True)
    assert titled["total"] == 1
    assert titled["items"][0]["preview"]["label"] == "Session details"
    assert titled["items"][0]["title"] == "Lighthouse refactor"
    assert runtime.store.search_history("accessibility review")["total"] == 1
    assert runtime.store.search_history("validation")["total"] == 2
    assert runtime.store.search_history("lighthouse", project="/work/elsewhere")["total"] == 0
    assert runtime.store.session(titled["items"][0]["id"])["payload"] == parent


@pytest.mark.parametrize("source", ["claude", "codex", "gemini", "copilot", "dsh"])
def test_resumed_activity_drives_today_order_and_row_dates(client, owner, runtime, source):
    resumed = sample_session(source=source, session_id="resumed")
    resumed["timestamp"] = "2026-10-01T09:00:00Z"
    resumed["session_context"] = {"last_event_at": "2026-10-05T14:00:00+02:00"}
    runtime.store.ingest(resumed)
    seed(runtime, "started-today", source=source, timestamp="2026-10-05T11:00:00Z")
    seed(runtime, "yesterday", source=source, timestamp="2026-10-04T23:00:00Z")
    params = {
        "source": source, "since": "2026-10-05T00:00:00Z", "before": "2026-10-06T00:00:00Z",
        "grouped": "false", "sort": "newest", "q": "validation",
    }
    for route in ("/api/sessions", "/api/history/search"):
        result = client.get(route, params=params, headers=owner).json()
        assert result["total"] == 2
        row = result["items"][0]
        assert row["occurred_at"] == row["activity_at"] == "2026-10-05T12:00:00.000+00:00"
        assert row["started_at"] == "2026-10-01T09:00:00.000+00:00"
        detail = runtime.store.session(row["id"])
        assert detail["activity_at"] == row["activity_at"]
        assert detail["payload"] == resumed
        assert runtime.store.one(
            "SELECT occurred_at FROM sessions WHERE id=?", (row["id"],),
        )["occurred_at"] == "2026-10-01T09:00:00.000+00:00"


def test_unchanged_recapture_moves_last_seen_but_not_activity(runtime, monkeypatch):
    payload = sample_session()
    payload["session_context"] = {"last_event_at": "2026-10-04T10:00:00Z"}
    monkeypatch.setattr("adr_desktop.store.utcnow", lambda: "2026-10-04T12:00:00.000+00:00")
    assert runtime.store.ingest(payload)
    first = runtime.store.sessions()["items"][0]
    monkeypatch.setattr("adr_desktop.store.utcnow", lambda: "2026-10-05T12:00:00.000+00:00")
    assert not runtime.store.ingest(payload)
    again = runtime.store.sessions()["items"][0]
    assert again["last_seen"] > first["last_seen"]
    assert again["occurred_at"] == first["occurred_at"] == "2026-10-04T10:00:00.000+00:00"
    assert runtime.store.sessions(since="2026-10-05T00:00:00Z")["total"] == 0
    assert runtime.store.search_history("validation", since="2026-10-05T00:00:00Z")["total"] == 0
    assert runtime.store.session(again["id"])["revisions"] == 1


@pytest.mark.parametrize("named_field, name", [
    ("session_title", "Lighthouse investigation"),
    ("agent_path", "/root/lighthouse_investigation"),
])
def test_each_word_can_match_metadata_or_tool_result_in_the_same_session(runtime, named_field, name):
    payload = sample_session(session_id="mixed", project="/work/allowed")
    payload["session_context"] = {named_field: name}
    if named_field == "agent_path":
        payload["session_context"]["parent_session_id"] = "parent"
    payload["chat_history"][1]["tools"][0]["result"] = "Diagnosed ECONNRESET in the retry handler."
    runtime.store.ingest(payload)
    result = runtime.store.search_history("Lighthouse ECONNRESET", previews=True)
    assert result["total"] == 1
    row = result["items"][0]
    assert row["preview"]["label"] == "Read result"
    assert "ECONNRESET" in row["snippet"] and "ECONNRESET" in row["preview"]["text"]
    assert runtime.store.search_history("ECONNRESET Lighthouse", project="/work/allowed")["total"] == 1
    assert runtime.store.search_history("Lighthouse ECONNRESET", project="/work/allow")["total"] == 0
    assert runtime.store.session(row["id"])["payload"] == payload


def test_late_unseen_older_revision_with_same_start_cannot_replace_current(runtime):
    current = sample_session(content="currentanswer")
    current["session_context"] = {
        "last_event_at": "2026-10-05T12:00:00Z", "session_title": "Current lighthouse",
    }
    runtime.store.ingest(current)
    before = runtime.store.sessions()["items"][0]
    older = copy.deepcopy(current)
    older["session_context"] = {
        "last_event_at": "2026-10-03T12:00:00Z", "session_title": "Obsolete beacon",
    }
    older["chat_history"][0]["content"] = "obsoleteanswer"
    assert runtime.store.ingest(older)
    after = runtime.store.session(before["id"])
    assert after["payload"] == current
    assert after["digest"] == before["digest"]
    assert after["revisions"] == 2
    assert runtime.store.search_history("lighthouse currentanswer")["total"] == 1
    assert runtime.store.search_history("beacon")["total"] == 0
    assert runtime.store.search_history("obsoleteanswer")["total"] == 0


@pytest.mark.parametrize("started, event, expected", [
    ("2026-10-01T09:00:00Z", "2026-10-05T01:30:00+02:00", "2026-10-04T23:30:00.000+00:00"),
    ("2026-10-01T09:00:00Z", "2026-10-04T20:30:00-03:00", "2026-10-04T23:30:00.000+00:00"),
    ("2026-10-01T09:00:00Z", "2026-10-04T23:30:00", "2026-10-04T23:30:00.000+00:00"),
    ("2026-10-01T09:00:00Z", "2026-10-04T23:30:00.123456Z", "2026-10-04T23:30:00.123+00:00"),
    ("2026-10-01T11:00:00+02:00", "invalid", "2026-10-01T09:00:00.000+00:00"),
    ("2026-10-01T09:00:00Z", None, "2026-10-01T09:00:00.000+00:00"),
    ("2026-10-01T09:00:00Z", True, "2026-10-01T09:00:00.000+00:00"),
    ("2026-10-01T09:00:00Z", {"bad": "timestamp"}, "2026-10-01T09:00:00.000+00:00"),
    ("2026-10-01T09:00:00Z", "0001-01-01T00:00:00+14:00", "2026-10-01T09:00:00.000+00:00"),
    ("2026-10-01T09:00:00Z", "2026-09-29T23:00:00Z", "2026-10-01T09:00:00.000+00:00"),
    ("invalid", "2026-10-04T23:30:00Z", "2026-10-04T23:30:00.000+00:00"),
    ("invalid", "invalid", ""),
    (None, None, ""),
    (True, 12345, ""),
    ("9999-12-31T23:59:59-14:00", None, ""),
])
def test_activity_normalization_and_invalid_fallback_never_use_wall_clock(
    runtime, monkeypatch, started, event, expected,
):
    payload = sample_session(session_id="timestamp-case")
    payload["timestamp"] = started
    payload["session_context"] = {"last_event_at": event}
    monkeypatch.setattr("adr_desktop.store.utcnow", lambda: "2026-10-05T20:00:00.000+00:00")
    runtime.store.ingest(payload)
    row = runtime.store.sessions()["items"][0]
    assert row["occurred_at"] == row["activity_at"] == expected
    assert runtime.store.session(row["id"])["payload"] == payload
    assert runtime.store.search_history("validation")["items"][0]["occurred_at"] == expected
    assert runtime.store.sessions(since="2026-10-05T00:00:00Z")["total"] == 0
    assert runtime.store.search_history("validation", since="2026-10-05T00:00:00Z")["total"] == 0
    # Even an upper-bound-only filter must exclude unknown dates.
    count = int(bool(expected))
    assert runtime.store.sessions(before="2026-10-05T00:00:00Z")["total"] == count
    assert runtime.store.search_history("validation", before="2026-10-05T00:00:00Z")["total"] == count
    newer = sample_session(session_id="dated")
    newer["timestamp"] = "2026-10-05T00:00:00Z"
    runtime.store.ingest(newer)
    assert runtime.store.sessions()["items"][-1]["id"] == row["id"]


@pytest.mark.parametrize("context", [None, [], "invalid", {"last_seen": "2099-01-01T00:00:00Z"}])
def test_unsupported_activity_metadata_falls_back_to_captured_timestamp(runtime, context):
    payload = sample_session()
    payload["session_context"] = context
    runtime.store.ingest(payload)
    assert runtime.store.sessions()["items"][0]["activity_at"] == "2026-09-30T10:00:00.000+00:00"


def test_activity_uses_half_open_normalized_date_bounds_and_rejects_overflow(runtime):
    for name, event in (
        ("before", "2026-10-24T21:59:59.999Z"),
        ("start", "2026-10-25T00:00:00+02:00"),
        ("last", "2026-10-25T23:59:59.999+01:00"),
        ("end", "2026-10-26T00:00:00+01:00"),
    ):
        payload = sample_session(session_id=name)
        payload["session_context"] = {"last_event_at": event}
        runtime.store.ingest(payload)
    bounds = {"since": "2026-10-25T00:00:00+02:00", "before": "2026-10-26T00:00:00+01:00"}
    browse = runtime.store.sessions(**bounds)
    assert [row["source_session_id"] for row in browse["items"]] == ["last", "start"]
    assert [row["id"] for row in runtime.store.search_history("validation", **bounds)["items"]] == [
        row["id"] for row in browse["items"]
    ]
    for value in ("0001-01-01T00:00:00+14:00", "9999-12-31T23:59:59-14:00"):
        with pytest.raises(ValueError, match="valid date range"):
            runtime.store.sessions(before=value)
        with pytest.raises(ValueError, match="valid date range"):
            runtime.store.search_history("validation", since=value)


def test_grouped_parents_do_not_borrow_child_activity_and_scoped_relations_do_not_leak(runtime):
    payloads = []
    for name, project, activity, context in (
        ("parent", "/allowed", "2026-10-01T00:00:00Z", {"session_title": "Root lighthouse"}),
        ("child", "/allowed", "2026-10-05T09:00:00Z", {
            "parent_session_id": "parent", "agent_path": "/root/visible_worker",
        }),
        ("grandchild", "/allowed", "2026-10-05T10:00:00Z", {"parent_session_id": "child"}),
        ("hidden-child", "/allowed-copy", "2026-10-06T00:00:00Z", {
            "parent_session_id": "parent", "session_title": "Secret child",
        }),
        ("secret-parent", "/secret", "2026-10-07T00:00:00Z", {"session_title": "Secret root"}),
        ("orphan", "/allowed", "2026-10-02T00:00:00Z", {"parent_session_id": "secret-parent"}),
        ("fork", "/allowed", "2026-10-03T00:00:00Z", {"forked_from_session_id": "secret-parent"}),
    ):
        payload = sample_session(session_id=name, project=project)
        payload["session_context"] = {**context, "last_event_at": activity}
        payloads.append(payload)
        runtime.store.ingest(payload)
    rows = runtime.store.sessions(grouped=True, project="/allowed")["items"]
    assert [row["source_session_id"] for row in rows] == ["fork", "orphan", "parent"]
    parent = rows[-1]
    assert parent["child_count"] == 1
    assert parent["activity_at"] == parent["occurred_at"] == "2026-10-01T00:00:00.000+00:00"
    assert rows[0]["forked_from"] is None and rows[1]["parent"] is None
    children = runtime.store.session_children(parent["id"], project="/allowed")["items"]
    assert len(children) == 1 and children[0]["child_count"] == 1
    assert children[0]["activity_at"] == "2026-10-05T09:00:00.000+00:00"
    assert set(children[0]["parent"]) == {"id", "title"}  # No related-session activity.
    filters = {"project": "/allowed", "since": "2026-10-05T00:00:00Z"}
    visible = runtime.store.sessions(**filters)["items"]
    assert [row["source_session_id"] for row in visible] == ["grandchild", "child"]
    assert runtime.store.sessions(grouped=True, **filters)["total"] == 0
    search = runtime.store.search_history("validation", sort="newest", **filters)
    assert [row["id"] for row in search["items"]] == [row["id"] for row in visible]
    assert runtime.store.search_history("secret", project="/allowed")["total"] == 0
    assert runtime.store.sessions(project="/allowed", since="2026-10-06T00:00:00Z")["total"] == 0
    assert len(payloads) == runtime.store.sessions()["total"]


def test_words_cannot_mix_across_sessions_parents_siblings_forks_or_projects(runtime):
    for name, title, word, context, project in (
        ("parent", "Lighthouse", "parentword", {}, "/allowed"),
        ("child", "Child title", "ECONNRESET", {"parent_session_id": "parent"}, "/allowed"),
        ("sibling", "Orchid", "siblingword", {"parent_session_id": "parent"}, "/allowed"),
        ("fork", "Fork title", "ECONNRESET", {"forked_from_session_id": "parent"}, "/allowed"),
        ("unrelated", "Lighthouse", "unrelatedword", {}, "/allowed"),
        ("outside", "Lighthouse", "ECONNRESET", {}, "/allowed-copy"),
    ):
        payload = sample_session(session_id=name, project=project, content=word)
        payload["session_context"] = {"session_title": title, **context}
        runtime.store.ingest(payload)
    for query in ("Lighthouse ECONNRESET", "Orchid ECONNRESET", "Lighthouse siblingword"):
        assert runtime.store.search_history(query, project="/allowed")["total"] == 0
    assert runtime.store.search_history("Lighthouse ECONNRESET")["total"] == 1
    assert runtime.store.search_history("Child ECONNRESET", project="/allowed")["total"] == 1


def test_mixed_search_keeps_literal_operators_unicode_and_deduplicates(runtime):
    payload = sample_session(content="ECONNRESET Lighthouse")
    payload["session_context"] = {"session_title": "Éclair Lighthouse OR NEAR"}
    runtime.store.ingest(payload)
    for query in (
        "Lighthouse ECONNRESET", '"Lighthouse" + (ECONNRESET*)', "éclair ECONNRESET",
        "Lighthouse Lighthouse ECONNRESET", "OR NEAR ECONNRESET",
    ):
        assert runtime.store.search_history(query)["total"] == 1
    assert runtime.store.search_history("Lighthouse OR missing")["total"] == 0
    assert runtime.store.search_history("Lighthouse'; DROP TABLE sessions; --")["total"] == 0
    assert runtime.store.sessions()["total"] == 1


def test_mixed_search_preserves_exact_grant_and_source_boundaries(client, runtime):
    for name, source, project in (
        ("allowed-claude", "claude", "/allowed"),
        ("allowed-codex", "codex", "/allowed"),
        ("prefix", "claude", "/allowed-copy"),
        ("other", "codex", "/other"),
    ):
        payload = sample_session(session_id=name, source=source, project=project, content="ECONNRESET")
        payload["session_context"] = {"session_title": "Lighthouse"}
        runtime.store.ingest(payload)
    grant = runtime.create_grant("Synthetic scoped history", "/allowed", [])
    headers = {"Authorization": "Bearer " + grant_token(runtime, grant)}
    params = {"q": "Lighthouse ECONNRESET"}
    response = client.get("/api/agent/history/search", params=params, headers=headers)
    assert response.status_code == 200 and response.json()["total"] == 2
    response = client.get(
        "/api/agent/history/search", params={**params, "source": "claude"}, headers=headers,
    )
    assert response.json()["total"] == 1
    assert response.json()["items"][0]["project"] == "/allowed"
    assert runtime.store.search_history("Lighthouse ECONNRESET", project="")["total"] == 0


@pytest.mark.parametrize("sort", ["relevance", "newest"])
def test_mixed_search_stable_pagination_uses_activity_then_id_for_ties(runtime, sort):
    for name, event in (
        ("one", "2026-10-05T11:00:00Z"),
        ("two", "2026-10-05T12:00:00Z"),
        ("three", "2026-10-05T12:00:00Z"),
        ("four", "2026-10-03T12:00:00Z"),
    ):
        payload = sample_session(session_id=name, content="ECONNRESET Lighthouse")
        payload["session_context"] = {"session_title": "Lighthouse", "last_event_at": event}
        runtime.store.ingest(payload)
    expected = [row["id"] for row in runtime.store.sessions()["items"]]
    full = runtime.store.search_history("Lighthouse ECONNRESET", sort=sort)
    assert [row["id"] for row in full["items"]] == expected
    assert expected[0:2] == sorted(expected[0:2])
    pages = [
        runtime.store.search_history("Lighthouse ECONNRESET", sort=sort, limit=1, offset=index)
        for index in range(4)
    ]
    assert [page["items"][0]["id"] for page in pages] == expected
    assert all(page["total"] == 4 for page in pages)
    assert [page["next_offset"] for page in pages] == [1, 2, 3, None]


def test_relevance_and_newest_remain_distinct_for_mixed_matches(runtime):
    strong = sample_session(session_id="strong", content="ECONNRESET " * 20)
    strong["session_context"] = {"session_title": "Lighthouse", "last_event_at": "2026-10-01T10:00:00Z"}
    weak = sample_session(session_id="weak", content="ECONNRESET " + "unrelated " * 1000)
    weak["session_context"] = {"session_title": "Lighthouse", "last_event_at": "2026-10-05T10:00:00Z"}
    for payload in (strong, weak):
        runtime.store.ingest(payload)
    newest = runtime.store.search_history("Lighthouse ECONNRESET", sort="newest")["items"]
    relevant = runtime.store.search_history("Lighthouse ECONNRESET", sort="relevance")["items"]
    assert newest[0]["activity_at"] == "2026-10-05T10:00:00.000+00:00"
    assert relevant[0]["activity_at"] == "2026-10-01T10:00:00.000+00:00"


def test_current_revision_reindexes_native_titles_and_agent_labels(runtime):
    payload = sample_session(content="ECONNRESET")
    payload["session_context"] = {
        "session_title": "Old lighthouse", "parent_session_id": "parent", "agent_path": "/root/old_worker",
        "last_event_at": "2026-10-01T10:00:00Z",
    }
    runtime.store.ingest(payload)
    changed = copy.deepcopy(payload)
    changed["session_context"].update({
        "session_title": "New beacon", "agent_path": "/root/new_reviewer",
        "last_event_at": "2026-10-05T10:00:00Z",
    })
    runtime.store.ingest(changed)
    assert runtime.store.search_history("old ECONNRESET")["total"] == 0
    assert runtime.store.search_history("beacon reviewer ECONNRESET")["total"] == 1
    row = runtime.store.sessions()["items"][0]
    assert runtime.store.session(row["id"])["revisions"] == 2
    assert runtime.store.session(row["id"])["payload"] == changed


def test_overview_dates_report_actual_activity_not_start_or_receipt(runtime):
    resumed = sample_session(session_id="resumed")
    resumed["session_context"] = {"last_event_at": "2026-10-05T12:00:00Z"}
    unknown = sample_session(session_id="unknown")
    unknown["timestamp"] = "invalid"
    for payload in (resumed, unknown):
        runtime.store.ingest(payload)
    result = runtime.store.overview()
    assert result["sources"][0]["sessions"] == 2
    assert result["sources"][0]["latest"] == "2026-10-05T12:00:00.000+00:00"
    assert result["days"] == [{"day": "2026-10-05", "sessions": 1}]
    assert result["recent"][0]["activity_at"] == result["recent"][0]["occurred_at"]


def test_stale_derived_scope_cannot_authorize_a_session_and_is_repaired(runtime):
    for name, project in (("allowed", "/allowed"), ("secret", "/secret")):
        payload = sample_session(session_id=name, project=project, content="ECONNRESET")
        payload["session_context"] = {"session_title": "Lighthouse"}
        runtime.store.ingest(payload)
    runtime.store.execute("UPDATE session_retrieval SET project='/allowed'")
    # Even an inconsistent derived index must agree with the authoritative row
    # before it can contribute titles, dates, counts, or search matches.
    assert runtime.store.sessions(project="/allowed")["total"] == 1
    assert runtime.store.search_history("Lighthouse ECONNRESET", project="/allowed")["total"] == 1
    runtime.store.execute("UPDATE history_documents SET digest='synthetic-stale-digest'")
    assert runtime.store.search_history("Lighthouse ECONNRESET")["total"] == 0
    runtime.store._backfill_session_retrieval()
    assert runtime.store.sessions(project="/secret")["total"] == 1
    assert runtime.store.search_history("Lighthouse ECONNRESET", project="/allowed")["total"] == 1
    assert runtime.store.search_history("Lighthouse ECONNRESET")["total"] == 2


def test_legacy_activity_and_search_backfill_preserves_originals_and_never_recovers_logs(
    client, owner, runtime, monkeypatch,
):
    store = runtime.store
    original = sample_session(source="codex", session_id="codex_migration", content="obsoleteword")
    original["timestamp"] = "2026-10-01T11:00:00+02:00"
    original["session_context"] = {
        "last_event_at": "2026-10-02T10:00:00Z", "session_title": "Lighthouse migration",
    }
    current = copy.deepcopy(original)
    current["session_context"]["last_event_at"] = "2026-10-05T14:00:00+02:00"
    current["chat_history"][0]["content"] = "ECONNRESET"
    for payload in (original, current):
        store.ingest(payload)
    identifier = store.sessions()["items"][0]["id"]
    unknown = sample_session(session_id="legacy-invalid")
    unknown["timestamp"] = "invalid"
    unknown["session_context"] = {"last_event_at": "invalid"}
    store.ingest(unknown)
    # Model old _timestamp's receipt-time fallback, which must not survive as
    # activity even though the original sessions.occurred_at must stay untouched.
    store.execute(
        "UPDATE sessions SET occurred_at=? WHERE source_session_id='legacy-invalid'",
        ("2026-10-05T20:00:00.000+00:00",),
    )
    store.setting("recording", True)
    store.setting("interval_seconds", 3600)
    store.setting("synthetic_custom", {"keep": True})
    runtime.create_grant("Synthetic unchanged grant", "/workspace/sample", [])
    for row in store.rows("SELECT id,digest FROM sessions"):
        payload = store.session(row["id"])["payload"]
        store.execute(
            "UPDATE history_documents SET body=? WHERE session_id=?",
            (Store._history_text(payload), row["id"]),
        )
        # Non-default compression makes byte-for-byte preservation meaningful.
        store.execute(
            "UPDATE snapshots SET payload=? WHERE digest=?",
            (zlib.compress(canonical(payload).encode(), level=0), row["digest"]),
        )
    tables = ("snapshots", "sessions", "session_metadata", "session_tools", "settings", "grants")
    before = {table: store.rows(f"SELECT * FROM {table} ORDER BY 1") for table in tables}
    exported = client.get(f"/api/sessions/{identifier}/export", headers=owner).content
    store.execute("DROP TABLE session_retrieval")

    def no_catalog_reads(_):
        raise AssertionError("Activity/search backfill must use retained captures, not agent catalogs")

    monkeypatch.setattr("adr_desktop.store.recover_codex_metadata", no_catalog_reads)
    store.close()
    runtime.store = Store(runtime.state_dir)
    migrated = runtime.store
    assert {table: migrated.rows(f"SELECT * FROM {table} ORDER BY 1") for table in tables} == before
    assert client.get(f"/api/sessions/{identifier}/export", headers=owner).content == exported
    assert migrated.session(identifier)["payload"] == current
    assert migrated.session(identifier)["revisions"] == 2
    assert migrated.search_history("lighthouse ECONNRESET")["total"] == 1
    assert migrated.search_history("obsoleteword")["total"] == 0
    assert migrated.sessions(since="2026-10-05T00:00:00Z")["total"] == 1
    assert migrated.sessions(before="2026-10-06T00:00:00Z")["total"] == 1
    assert migrated.sessions()["items"][-1]["activity_at"] == ""
    assert migrated.one("PRAGMA user_version")["user_version"] == 3
    assert len(migrated.rows("PRAGMA table_info(sessions)")) == 14
    assert len(migrated.rows("PRAGMA table_info(session_metadata)")) == 6
    index_before = migrated.rows("SELECT * FROM session_retrieval ORDER BY session_id")
    documents_before = migrated.rows("SELECT * FROM history_documents ORDER BY id")
    migrated.close()
    with monkeypatch.context() as patch:
        patch.setattr("adr_desktop.store.zlib.decompress", no_catalog_reads)
        runtime.store = Store(runtime.state_dir)  # A clean reopen must not reread/reindex any payload.
    assert runtime.store.rows("SELECT * FROM session_retrieval ORDER BY session_id") == index_before
    assert runtime.store.rows("SELECT * FROM history_documents ORDER BY id") == documents_before
    assert {table: runtime.store.rows(f"SELECT * FROM {table} ORDER BY 1") for table in tables} == before


def test_retrieval_migration_batches_are_atomic_restartable_and_versioned(runtime, monkeypatch):
    store = runtime.store
    for index in range(45):
        payload = sample_session(session_id=f"batch-{index}", content="ECONNRESET")
        payload["session_context"] = {
            "session_title": "Lighthouse", "last_event_at": "2026-10-05T12:00:00Z",
        }
        store.ingest(payload)
    snapshots = store.rows("SELECT * FROM snapshots ORDER BY digest")
    selection = store.rows("SELECT * FROM sessions ORDER BY id")
    store.execute("UPDATE session_retrieval SET index_version=0,activity_at=''")
    store.execute("UPDATE history_documents SET body='ECONNRESET'")  # Legacy transcript-only index.
    original_index = Store._index_session
    calls = []

    def interrupt_second_batch(self, connection, identifier, digest, payload):
        calls.append(identifier)
        original_index(self, connection, identifier, digest, payload)
        if len(calls) == 25:
            raise RuntimeError("Synthetic interruption during the second migration transaction")

    with monkeypatch.context() as patch:
        patch.setattr(Store, "_index_session", interrupt_second_batch)
        with pytest.raises(RuntimeError, match="Synthetic interruption"):
            store._backfill_session_retrieval()
    complete = store.rows(
        "SELECT session_id FROM session_retrieval WHERE index_version=?", (RETRIEVAL_INDEX_VERSION,),
    )
    assert {row["session_id"] for row in complete} == set(calls[:20])
    assert store.search_history("Lighthouse ECONNRESET")["total"] == 20
    resumed_calls = []

    def record_resumed(self, connection, identifier, digest, payload):
        resumed_calls.append(identifier)
        original_index(self, connection, identifier, digest, payload)

    store.close()
    with monkeypatch.context() as patch:
        patch.setattr(Store, "_index_session", record_resumed)
        runtime.store = Store(runtime.state_dir)
    assert len(resumed_calls) == 25 and not set(resumed_calls).intersection(calls[:20])
    assert runtime.store.search_history("Lighthouse ECONNRESET")["total"] == 45
    assert runtime.store.rows("SELECT * FROM snapshots ORDER BY digest") == snapshots
    assert runtime.store.rows("SELECT * FROM sessions ORDER BY id") == selection
    assert runtime.store.one(
        "SELECT count(*) AS n FROM session_retrieval WHERE index_version<>?", (RETRIEVAL_INDEX_VERSION,),
    )["n"] == 0


def retrieval_query_plan(store, operation):
    queries = []
    store.db.set_trace_callback(queries.append)
    try:
        operation()
    finally:
        store.db.set_trace_callback(None)
    query = next(query for query in queries if "ORDER BY" in query and "r.activity_at DESC" in query)
    return [row["detail"] for row in store.rows("EXPLAIN QUERY PLAN " + query)]


@pytest.mark.parametrize("filters, expected_indexes", [
    ({}, ("session_activity_recent",)),
    ({"project": "/allowed"}, ("session_activity_project",)),
    ({"source": "codex"}, ("session_activity_source",)),
    ({"project": "/allowed", "source": "codex"},
     ("session_activity_scope", "session_activity_project", "session_activity_source")),
])
def test_activity_browse_plans_use_ordered_indexes_without_temp_sort(runtime, filters, expected_indexes):
    payload = sample_session(source="codex", project="/allowed")
    payload["session_context"] = {"last_event_at": "2026-10-05T12:00:00Z"}
    runtime.store.ingest(payload)
    plan = retrieval_query_plan(
        runtime.store,
        lambda: runtime.store.sessions(
            **filters, grouped=True, since="2026-10-05T00:00:00Z", before="2026-10-06T00:00:00Z",
        ),
    )
    # SQLite may choose either selective scope prefix on a tiny fixture; require
    # the actual date-range/ordering index behavior, not one planner join order.
    assert any(
        any(index in step for index in expected_indexes) and "activity_at>?" in step for step in plan
    ), plan
    assert not any("TEMP B-TREE" in step for step in plan), plan
    print(json.dumps({"filters": filters, "plan": plan}))


@pytest.mark.parametrize("sort", ["relevance", "newest"])
@pytest.mark.parametrize("filters", [
    {},
    {"project": "/allowed", "since": "2026-10-05T00:00:00Z"},
])
def test_mixed_search_plans_use_fts_and_unique_session_lookups(runtime, sort, filters):
    payload = sample_session(content="ECONNRESET", project="/allowed")
    payload["session_context"] = {"session_title": "Lighthouse", "last_event_at": "2026-10-05T12:00:00Z"}
    runtime.store.ingest(payload)
    plan = retrieval_query_plan(
        runtime.store,
        lambda: runtime.store.search_history(
            "Lighthouse ECONNRESET", sort=sort, **filters,
        ),
    )
    assert any("history_search VIRTUAL TABLE INDEX" in step and "M" in step for step in plan), plan
    assert any(
        "SEARCH h USING INTEGER PRIMARY KEY" in step
        or "SEARCH h USING INDEX sqlite_autoindex_history_documents_1" in step for step in plan
    ), plan
    assert not any("SCAN s" in step or "SCAN m" in step for step in plan), plan
    print(json.dumps({"sort": sort, "filters": filters, "plan": plan}))


def test_purging_history_removes_derived_activity_and_mixed_search_documents(runtime):
    payload = sample_session(content="ECONNRESET")
    payload["session_context"] = {"session_title": "Lighthouse"}
    runtime.store.ingest(payload)
    runtime.store.purge_history()
    assert runtime.store.rows("SELECT * FROM session_retrieval") == []
    assert runtime.store.search_history("Lighthouse ECONNRESET")["total"] == 0


def test_sessions_stylesheet_is_served_without_widening_asset_access(client):
    assert client.get("/assets/sessions.css").status_code == 200
    assert client.get("/assets/store.py").status_code == 404


def test_browser_date_bounds_and_shareable_filter_state():
    node = shutil.which("node")
    if not node:
        playwright = importlib.util.find_spec("playwright")
        candidate = Path(playwright.origin).parent / "driver" / "node" if playwright else None
        node = str(candidate) if candidate and candidate.is_file() else None
    if not node:
        pytest.skip("A JavaScript runtime is required")
    source = Path(__file__).resolve().parents[1] / "adr_desktop" / "web" / "app.js"
    script = r"""
const fs = require("node:fs"), vm = require("node:vm"), assert = require("node:assert/strict");
process.env.TZ = "Europe/Amsterdam";
const source = fs.readFileSync(process.argv[1], "utf8");
const start = source.indexOf("function sessionQueryState(");
const end = source.indexOf("\nfunction sessionRow(", start);
const context = vm.createContext({URLSearchParams, Date});
vm.runInContext(source.slice(start, end), context);
const view = context.sessionQueryState("?q=retry+cache&source=codex&project=%2Fwork%2Fa+b&date=custom"
  + "&from=2026-10-25&to=2026-10-25&offset=30&sort=newest");
const bounds = context.sessionDateBounds(view);
assert.equal(bounds.since, "2026-10-24T22:00:00.000Z");
assert.equal(bounds.before, "2026-10-25T23:00:00.000Z");
assert.equal(Date.parse(bounds.before) - Date.parse(bounds.since), 25 * 3600 * 1000);
assert.equal(context.sessionsURL(view),
  "/sessions?q=retry+cache&source=codex&project=%2Fwork%2Fa+b&date=custom"
  + "&from=2026-10-25&to=2026-10-25&sort=newest&offset=30");
assert.equal(context.sessionQueryState("?offset=-30").offset, 0);
assert.equal(context.sessionQueryState("?offset=999999").offset, 100000);
assert.equal(context.sessionQueryState("?sort=invalid&date=invalid").sort, "relevance");
assert.equal(context.sessionQueryState("?date=invalid").date, "");
assert.throws(() => context.sessionDateBounds({date:"custom", from:"2026-02-30"}), /valid/);
assert.throws(() =>
  context.sessionDateBounds({date:"custom", from:"2026-10-07", to:"2026-10-01"}), /end date/);
assert.equal(context.sessionsURL(context.sessionQueryState("")), "/sessions");
console.log(JSON.stringify({ok:true}));
"""
    result = subprocess.run(
        [node, "-e", script, str(source)], capture_output=True, text=True, check=True, timeout=10,
    )
    assert json.loads(result.stdout) == {"ok": True}
