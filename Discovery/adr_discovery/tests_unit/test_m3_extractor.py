"""M3 -- extractor.

Two things are asserted on every case: the declarations that survived, and
the count that was reported. The count is checked against the file rather
than against what the parser produced, which is the only way the isolation
claim can be measured at all.
"""

from __future__ import annotations

from adr_discovery.contracts.records import Candidate, Kind
from adr_discovery.extractor import extract

CFG = "/proj/.mcp.json"


def read(world, document, path=CFG):
    world.json(path, document)
    return extract(world.gate(), Candidate(kind="marker_file", path=path, source="sweep"))


def test_u3_01_one_bad_record_does_not_remove_its_siblings(world):
    result = read(world, {"mcpServers": {
        "a": {"command": "npx", "args": ["-y", "a@1.0.0"]},
        "b": {"command": "uvx", "args": ["b"]},
        "c": "not a mapping",
        "d": {"command": "docker", "args": ["run", "img:tag"]},
        "e": {"url": "https://h.example/sse"},
    }})

    assert len(result.declarations) == 4
    assert len(result.errors) == 1
    assert result.declared == 5, "the reported count is what was in the file"


def test_u3_02_args_as_a_string_is_a_shape_error_not_a_split(world):
    result = read(world, {"mcpServers": {"x": {"command": "npx", "args": "--port 8080"}}})

    assert result.declarations == ()
    assert "array" in result.errors[0].reason
    assert result.declared == 1


def test_u3_03_env_must_be_a_mapping(world):
    result = read(world, {"mcpServers": {"y": {"command": "c", "env": ["A=1"]}}})

    assert "mapping" in result.errors[0].reason


def test_u3_04_a_real_parser_reads_toml(world):
    world.file("/proj/config.toml",
               '[mcp_servers.z]\ncommand = "docker"\nargs = ["run", "ghcr.io/x/y@sha256:ab34"]\n')
    result = extract(world.gate(), Candidate("marker_file", "/proj/config.toml", "sweep"))

    (declaration,) = result.declarations
    assert declaration.args == ("run", "ghcr.io/x/y@sha256:ab34"), "not split on the colon"


def test_u3_05_a_url_keeps_its_port_and_loses_its_query(world):
    result = read(world, {"mcpServers": {"r": {"url": "https://u:pw@h.example:8443/sse?tok=SECRET#f"}}})

    (declaration,) = result.declarations
    assert declaration.url == "https://h.example:8443/sse"
    assert "SECRET" not in declaration.url and "pw" not in declaration.url


def test_u3_06_a_digest_reference_survives_whole(world):
    result = read(world, {"mcpServers": {
        "d": {"command": "docker", "args": ["run", "ghcr.io/x/y@sha256:ab34cd56"]}}})

    assert result.declarations[0].args[-1] == "ghcr.io/x/y@sha256:ab34cd56"


def test_u3_07_every_settings_scope_is_read(world):
    scopes = {
        "/Users/a/.claude/settings.json": "user",
        "/proj/.mcp.json": "project",
        "/proj/settings.local.json": "project_local",
        "/proj/plugins/p/mcp.json": "plugin",
    }
    seen = set()
    for path in scopes:
        result = read(world, {"mcpServers": {"s": {"command": "x"}}}, path=path)
        assert result.declared == 1, f"{path} was not read"
        seen.add(result.declarations[0].scope)

    assert seen == set(scopes.values()), "reading two of four and reporting the total is the defect"


def test_u3_08_a_cap_reports_the_true_count(world, monkeypatch):
    import adr_discovery.extractor as extractor

    monkeypatch.setattr(extractor, "RECORD_CAP", 3)
    result = read(world, {"mcpServers": {f"s{i}": {"command": "x"} for i in range(10)}})

    assert len(result.declarations) == 3
    assert result.declared == 10, "the true count, not the capped one"
    assert result.truncated


def test_u3_09_an_unrepresentable_construct_is_refused_not_guessed(world):
    world.file("/proj/config.yaml", "mcp_servers:\n  q: &anchor\n    command: x\n")
    result = extract(world.gate(), Candidate("marker_file", "/proj/config.yaml", "sweep"))

    assert result.declarations == ()
    assert "Unrepresentable" in result.errors[0].reason


def test_hooks_are_emitted_individually_beside_mcp_servers(world):
    result = read(world, {
        "mcpServers": {"s": {"command": "node", "args": ["server.js"]}},
        "hooks": {"PreToolUse": [{"matcher": "*", "hooks": [
            {"type": "command", "command": "audit --event pre"},
            {"type": "command", "command": "audit --token secret"},
        ]}]},
    }, path="/Users/a/.claude/settings.json")

    assert result.declared == 3
    assert [d.kind for d in result.declarations] == [Kind.MCP_SERVER, Kind.HOOK, Kind.HOOK]


def test_instruction_files_are_declared_without_reading_the_body(world):
    world.file("/Users/a/.codex/AGENTS.md", "private instructions")
    result = extract(world.gate(), Candidate("instruction_file", "/Users/a/.codex/AGENTS.md", "sweep"))

    assert result.declared == 1
    assert result.declarations[0].kind is Kind.INSTRUCTIONS
    assert "private instructions" not in repr(result.declarations[0])


def test_shell_profile_keeps_credential_names_and_drops_values(world):
    world.file("/Users/a/.bashrc", "export PATH=/bin\nexport ANTHROPIC_API_KEY=top-secret\n")
    result = extract(world.gate(), Candidate("shell_profile", "/Users/a/.bashrc", "app_state:config"))

    assert result.declared == 1
    assert result.declarations[0].env_names == ("ANTHROPIC_API_KEY",)
    assert "top-secret" not in repr(result.declarations[0])


def test_malformed_mcp_bundle_is_inventory_not_a_server(world):
    path = "/Users/a/.mcpb/broken/manifest.json"
    world.file(path, '{"name": "broken", "server": {')
    result = extract(world.gate(), Candidate("marker_file", path, "sweep"))

    assert result.declared == 1
    assert result.declarations[0].kind is Kind.MCP_BUNDLE
    assert result.declarations[0].raw["flags"] == ("malformed",)


def test_managed_config_has_enterprise_scope(world):
    result = read(world, {"mcpServers": {"s": {"command": "node"}}},
                  path="/etc/adr/managed-mcp.json")

    assert result.declarations[0].scope == "enterprise_managed"
