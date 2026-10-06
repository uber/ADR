"""Content-free credential-use attribution, independent of credential permissions."""

import json
import re

RUN_ID = re.compile(r"[a-f0-9]{32}")
NATIVE_SESSION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,511}")
SERVERS = ("adr", "adr_vault_env", "plugin_adr-agent_adr", "plugin_adr_agent_adr")
COMMAND_NAMES = {f"mcp__{server}__adr_run_command" for server in SERVERS} | {
    f"{server}_adr_run_command" for server in SERVERS
}
# Some sensor parsers retain only the head/tail of a large tool result. ADR puts
# its receipt first; never search command output or free text for an embedded ID.
RECEIPT_PREFIX = re.compile(r'^\s*\{\s*"run_id"\s*:\s*"([a-f0-9]{32})"\s*[,}]')


def credential_command(name, server=None):
    return isinstance(name, str) and (
        name in COMMAND_NAMES or (name == "adr_run_command" and server in SERVERS)
    )


def result_run_ids(value, depth=0):
    """Read only ADR/MCP result envelopes, not arbitrary nested program output."""
    if depth > 6:
        return set()
    if isinstance(value, str):
        if len(value) > 256 * 1024:
            return set()
        try:
            decoded = json.loads(value)
        except (ValueError, RecursionError):
            match = RECEIPT_PREFIX.match(value)
            return {match[1]} if match else set()
        return result_run_ids(decoded, depth + 1)
    if isinstance(value, list):
        result = set()
        for item in value[:32]:
            if isinstance(item, dict) and item.get("type") == "text":
                result.update(result_run_ids(item.get("text"), depth + 1))
        return result
    if not isinstance(value, dict):
        return set()
    if "run_id" in value:
        identifier = value["run_id"]
        return {identifier} if isinstance(identifier, str) and RUN_ID.fullmatch(identifier) else set()
    result = set()
    # Known harness wrappers only. In particular, stdout/stderr/arguments are
    # never traversed, even if a program prints a receipt from an older command.
    for key in ("structuredContent", "content", "result", "Ok", "output"):
        if key in value:
            result.update(result_run_ids(value[key], depth + 1))
    if value.get("type") == "text":
        result.update(result_run_ids(value.get("text"), depth + 1))
    return result


def session_run_ids(payload):
    result = set()
    for message in payload.get("chat_history", []):
        tools = message.get("tools")
        if not isinstance(tools, list):
            continue
        for tool in tools:
            if not isinstance(tool, dict) or not credential_command(
                tool.get("tool_name"), tool.get("server_name")
            ):
                continue
            identifiers = result_run_ids(tool.get("result"))
            if len(identifiers) == 1:
                result.update(identifiers)
    return result


def reported_source_id(harness, session_id):
    if not session_id:
        return ""
    if session_id.startswith(harness + "_"):
        return session_id
    if harness == "opencode":
        session_id = session_id.removeprefix("ses_")
    return f"{harness}_{session_id}"


def record_session(store, run_id, grant_id, harness, session_id):
    """A hook may associate only an existing run from its verified MCP grant."""
    if not NATIVE_SESSION_ID.fullmatch(session_id):
        return False
    with store.transaction() as connection:
        run = connection.execute(
            "SELECT id FROM environment_runs WHERE id=? AND grant_id=?", (run_id, grant_id)
        ).fetchone()
        if not run:
            return False
        connection.execute(
            """INSERT INTO environment_run_context(run_id,harness,session_id,ambiguous)
               VALUES (?,?,?,0)
               ON CONFLICT(run_id) DO UPDATE SET ambiguous=(
                   environment_run_context.ambiguous OR environment_run_context.harness<>excluded.harness
                   OR environment_run_context.session_id<>excluded.session_id)""",
            (run_id, harness, session_id),
        )
    return True


def _captured_session(store, run):
    rows = store.rows(
        """SELECT s.id,s.source,s.source_session_id,s.title,
                  coalesce(m.parent_id,'') AS parent_id,coalesce(m.forked_from_id,'') AS forked_from_id
           FROM credential_session_receipts c JOIN sessions s ON s.id=c.session_id
           JOIN session_retrieval r ON r.session_id=s.id AND r.digest=s.digest
           LEFT JOIN session_metadata m ON m.session_id=s.id
           WHERE c.run_id=? ORDER BY s.id LIMIT 33""",
        (run["id"],),
    )
    if run["ambiguous"] or len(rows) > 32:
        return None, "ambiguous"
    if not rows:
        return None, "not_captured" if run["reported_session_id"] else "unavailable"
    # Forks/subagents can contain a copy of their ancestor's tool result. Do not
    # label those copies as new uses or choose by recency/project/grant name.
    candidates = {row["id"] for row in rows}
    originals = []
    for row in rows:
        ancestors = [value for value in (row["parent_id"], row["forked_from_id"]) if value]
        seen = set()
        inherited = False
        while ancestors:
            ancestor = ancestors.pop()
            if ancestor == row["id"] or len(seen) >= 64:
                return None, "ambiguous"
            if ancestor in seen:
                continue
            if ancestor in candidates:
                inherited = True
                break
            seen.add(ancestor)
            parent = store.one(
                """SELECT s.id,coalesce(m.parent_id,'') AS parent_id,
                          coalesce(m.forked_from_id,'') AS forked_from_id
                   FROM sessions s LEFT JOIN session_metadata m ON m.session_id=s.id WHERE s.id=?""",
                (ancestor,),
            )
            if not parent:
                # The original may simply not have been captured yet.
                return None, "not_captured"
            ancestors.extend(value for value in (parent["parent_id"], parent["forked_from_id"]) if value)
        if not inherited:
            originals.append(row)
    if len(originals) != 1:
        return None, "ambiguous"
    match = originals[0]
    if run["harness"] and run["harness"] != match["source"]:
        return None, "ambiguous"
    return {key: match[key] for key in ("id", "source", "source_session_id", "title")}, "captured"


def recent_runs(store):
    rows = store.rows(
        """SELECT r.id,r.state,r.created_at,r.exit_code,g.name AS agent,
                  coalesce(c.harness,'') AS harness,coalesce(c.session_id,'') AS reported_session_id,
                  coalesce(c.ambiguous,0) AS ambiguous
           FROM environment_runs r JOIN grants g ON g.id=r.grant_id
           LEFT JOIN environment_run_context c ON c.run_id=r.id
           ORDER BY r.created_at DESC,r.id DESC LIMIT 10"""
    )
    for row in rows:
        row["session"], row["session_status"] = _captured_session(store, row)
        row["session_id"] = (
            row["session"]["source_session_id"] if row["session"]
            else reported_source_id(row["harness"], row["reported_session_id"])
        )
        for key in ("harness", "reported_session_id", "ambiguous"):
            row.pop(key)
    return rows
