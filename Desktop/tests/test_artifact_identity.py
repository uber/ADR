import hashlib
import json
import os
from pathlib import Path

import pytest

from adr_desktop.artifact_identity import (
    IdentityBudget,
    identify_event,
    inspect_command,
    inspect_file,
    inspect_mcp_definition,
    read_mcp_configurations,
)


@pytest.fixture(autouse=True)
def isolated_identity_home(tmp_path, monkeypatch):
    home = tmp_path / "identity-home"
    home.mkdir(exist_ok=True)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setenv("HOME", str(home))
    for key in tuple(os.environ):
        if key.lower().startswith(("pip_", "npm_config_", "uv_", "xdg_")) or key == "VIRTUAL_ENV":
            monkeypatch.delenv(key)
    monkeypatch.setenv("CODEX_HOME", str(home / ".codex"))
    return home


def subjects(evidence):
    return [item.subject for item in evidence.candidates]


def packages(evidence):
    return [item for item in subjects(evidence) if item["kind"] == "package"]


@pytest.mark.parametrize("command,ecosystem,name", [
    ("npm install fixture-package@1.2.3", "npm", "fixture-package"),
    ("npm i -D fixture-package@1.2.3", "npm", "fixture-package"),
    ("npm install @fixture/pkg@1.2.3", "npm", "@fixture/pkg"),
    ("npm install alias@npm:@fixture/pkg@1.2.3", "npm", "@fixture/pkg"),
    ("npm exec --package fixture-package@1.2.3 -- fixture --flag", "npm", "fixture-package"),
    ("npx -y fixture-package@1.2.3 --arg", "npm", "fixture-package"),
    ("npx --package=fixture-package@1.2.3 fixture --flag", "npm", "fixture-package"),
    ("command -- npm install fixture-package@1.2.3", "npm", "fixture-package"),
    ("env -i npm install fixture-package@1.2.3", "npm", "fixture-package"),
    ("bash -lc 'npm install fixture-package@1.2.3'", "npm", "fixture-package"),
    ("pip install Fixture_Package==1.2.3", "pypi", "fixture-package"),
    ("pip3 install fixture-package==1.2.3", "pypi", "fixture-package"),
    ("python3.11 -m pip install fixture-package==1.2.3", "pypi", "fixture-package"),
    ("uv pip install fixture-package==1.2.3", "pypi", "fixture-package"),
    ("uvx fixture-package==1.2.3", "pypi", "fixture-package"),
    ("uv tool run --from fixture-package==1.2.3 fixture", "pypi", "fixture-package"),
    ("uv tool install fixture-package==1.2.3", "pypi", "fixture-package"),
])
def test_literal_package_identity(command, ecosystem, name, tmp_path):
    result = inspect_command(command, str(tmp_path), environment={})
    assert packages(result) == [{
        "kind": "package", "ecosystem": ecosystem, "name": name, "version": "1.2.3",
        "registry": "https://registry.npmjs.org" if ecosystem == "npm" else "https://pypi.org",
    }]


@pytest.mark.parametrize("command", [
    "echo npm install fixture-package@1.2.3",
    "printf '%s' 'npm install fixture-package@1.2.3'",
    "echo ';' npm install fixture-package@1.2.3",
    "# npm install fixture-package@1.2.3",
    "git commit -m 'npm install fixture-package@1.2.3'",
    "npm uninstall fixture-package@1.2.3",
    "pip uninstall fixture-package==1.2.3",
])
def test_benign_mentions_and_removals_are_not_installs(command, tmp_path):
    assert not packages(inspect_command(command, str(tmp_path), environment={}))


@pytest.mark.parametrize("command", [
    "npm install $PACKAGE",
    "eval 'npm install fixture-package@1.2.3'",
    "npm install fixture-package@1.2.3 | cat",
    "npm install fixture-package@1.2.3 > out",
    "npm install $(printf fixture-package@1.2.3)",
    "npm install --prefix /another/project fixture-package@1.2.3",
    "pip install -r requirements.txt",
    "pip install https://example.invalid/package.whl",
])
def test_unsupported_grammar_never_guesses_identity(command, tmp_path):
    assert not packages(inspect_command(command, str(tmp_path), environment={}))


@pytest.mark.parametrize("command", ["npm install fixture-package@latest",
                                     "npm install fixture-package@^1.2.3",
                                     "pip install fixture-package"])
def test_unknown_release_is_not_guessed(command, tmp_path):
    result = inspect_command(command, str(tmp_path), environment={})
    assert packages(result)[0]["version"] is None
    assert "package_version_unresolved" in result.unresolved


def test_simple_segments_and_static_directory_changes(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / ".npmrc").write_text("registry=https://private.example.invalid/npm/\n")
    result = inspect_command(
        f"cd '{project}' && npm install fixture-package@1.2.3; echo done", str(tmp_path), environment={},
    )
    assert packages(result)[0]["registry"] == "https://private.example.invalid/npm"
    assert result.candidates[0].location == str(project)


@pytest.mark.parametrize("prefix", ["source private.sh", "python configure.py", "unset NPM_CONFIG_REGISTRY"])
def test_opaque_prior_command_cannot_establish_later_registry(prefix, tmp_path):
    result = inspect_command(f"{prefix}; npm install fixture-package@1.2.3",
                             str(tmp_path), environment={})
    assert not packages(result)
    assert result.unresolved


def test_prior_known_match_survives_unsupported_later_sequence(tmp_path):
    result = inspect_command(
        "npm install fixture-package@1.2.3; opaque-program; npm install other@1.2.3",
        str(tmp_path), environment={},
    )
    assert [item["name"] for item in packages(result)] == ["fixture-package"]
    assert result.unresolved

@pytest.mark.parametrize("command,environment,expected", [
    ("npm install fixture-package@1.2.3 --registry=https://private.example.invalid",
     {}, "https://private.example.invalid"),
    ("NPM_CONFIG_REGISTRY=https://private.example.invalid npm install fixture-package@1.2.3",
     {}, "https://private.example.invalid"),
    ("export NPM_CONFIG_REGISTRY=https://private.example.invalid; npm install fixture-package@1.2.3",
     {}, "https://private.example.invalid"),
    ("pip install fixture-package==1.2.3",
     {"PIP_INDEX_URL": "https://private.example.invalid/simple"}, "https://private.example.invalid/simple"),
    ("uvx fixture-package==1.2.3",
     {"UV_DEFAULT_INDEX": "https://private.example.invalid/simple"}, "https://private.example.invalid/simple"),
])
def test_explicit_and_environment_registry_provenance(command, environment, expected, tmp_path):
    result = inspect_command(command, str(tmp_path), environment=environment)
    assert packages(result)[0]["registry"] == expected


def test_npm_scoped_registry_is_not_mistaken_for_public(tmp_path):
    (tmp_path / ".npmrc").write_text("@fixture:registry=https://private.example.invalid/\n")
    result = inspect_command("npm install @fixture/pkg@1.2.3", str(tmp_path), environment={})
    assert packages(result)[0]["registry"] == "https://private.example.invalid"


def test_bare_shell_assignment_is_not_exported_to_package_process(tmp_path):
    command = "NPM_CONFIG_REGISTRY=https://private.example.invalid; npm install fixture-package@1.2.3"
    result = inspect_command(command, str(tmp_path), environment={})
    assert packages(result)[0]["registry"] == "https://registry.npmjs.org"
    inherited = inspect_command(command, str(tmp_path), environment={
        "NPM_CONFIG_REGISTRY": "https://registry.npmjs.org",
    })
    assert packages(inherited)[0]["registry"] == "https://private.example.invalid"


def test_registry_cli_precedence_and_relative_config_path(tmp_path):
    for command, environment in (
        ("npm install --registry=https://registry.npmjs.org fixture-package@1.2.3",
         {"NPM_CONFIG_REGISTRY": "https://private.example.invalid"}),
        ("pip install --index-url=https://pypi.org/simple fixture-package==1.2.3",
         {"PIP_INDEX_URL": "https://private.example.invalid/simple"}),
    ):
        assert "private" not in packages(inspect_command(command, str(tmp_path), environment=environment))[0][
            "registry"
        ]
    (tmp_path / "private.npmrc").write_text("registry=https://private.example.invalid\n")
    result = inspect_command("npm install fixture-package@1.2.3", str(tmp_path),
                             environment={"NPM_CONFIG_USERCONFIG": "private.npmrc"})
    assert packages(result)[0]["registry"] == "https://private.example.invalid"
    result = inspect_command(
        "npm exec fixture-package@1.2.3 --registry=https://private.example.invalid",
        str(tmp_path), environment={},
    )
    assert packages(result)[0]["registry"] == "https://private.example.invalid"


def test_global_npm_install_does_not_use_project_registry(tmp_path):
    (tmp_path / ".npmrc").write_text("registry=https://private.example.invalid\n")
    result = inspect_command("npm install -g fixture-package@1.2.3", str(tmp_path), environment={})
    assert packages(result)[0]["registry"] == "https://registry.npmjs.org"


@pytest.mark.parametrize("configuration", ["symlink", "malformed", "oversized", "array_setting"])
def test_explicit_unscoped_npm_registry_does_not_depend_on_lower_priority_files(
    tmp_path, configuration, isolated_identity_home,
):
    config = isolated_identity_home / ".npmrc"
    if configuration == "symlink":
        target = tmp_path / "npm-config"
        target.write_text("registry=https://private.example.invalid\n")
        config.symlink_to(target)
    elif configuration == "malformed":
        config.write_text("not an ini setting\n")
    elif configuration == "oversized":
        config.write_bytes(b"# inert padding\n" * 20000)
    else:
        config.write_text("ca[]=first inert value\nca[]=second inert value\n")
    budget = IdentityBudget()
    result = inspect_command(
        "npm install --registry=https://registry.npmjs.org fixture-package@1.2.3",
        str(tmp_path), budget=budget, environment={},
    )
    assert packages(result)[0]["registry"] == "https://registry.npmjs.org"
    assert not result.unresolved
    assert budget.files == 0


def test_explicit_unscoped_npm_registry_ignores_irrelevant_environment(tmp_path):
    result = inspect_command(
        "npm install --registry=https://registry.npmjs.org fixture-package@1.2.3",
        str(tmp_path), environment={
            "NPM_CONFIG_PREFIX": "/synthetic/prefix",
            "NPM_CONFIG_USERCONFIG": "__ADR_UNKNOWN_ENVIRONMENT_VALUE__",
            "NPM_CONFIG_REGISTRY": "https://private.example.invalid",
        },
    )
    assert packages(result)[0]["registry"] == "https://registry.npmjs.org"
    assert not result.unresolved


def test_explicit_npm_registry_does_not_override_a_scoped_registry_guess(tmp_path):
    (tmp_path / ".npmrc").write_text("@fixture:registry=https://private.example.invalid\n")
    result = inspect_command(
        "npm install --registry=https://registry.npmjs.org @fixture/pkg@1.2.3",
        str(tmp_path), environment={},
    )
    assert not packages(result)
    assert result.unresolved


@pytest.mark.parametrize("registry", ["https://registry.npmjs.org", "https://private.example.invalid"])
def test_symlinked_npm_config_keeps_actual_registry_identity(
    tmp_path, registry, isolated_identity_home,
):
    target = tmp_path / "npm-config"
    target.write_text(f"registry={registry}\n")
    (isolated_identity_home / ".npmrc").symlink_to(target)
    result = inspect_command("npm install fixture-package@1.2.3", str(tmp_path), environment={})
    assert packages(result)[0]["registry"] == registry
    assert not result.unresolved


def test_racing_npm_config_link_is_unresolved(tmp_path, isolated_identity_home, monkeypatch):
    from adr_desktop import artifact_identity

    target, changed = tmp_path / "first-config", tmp_path / "second-config"
    target.write_text("registry=https://registry.npmjs.org\n")
    changed.write_text("registry=https://private.example.invalid\n")
    link = isolated_identity_home / ".npmrc"
    link.symlink_to(target)
    read = artifact_identity._read_regular

    def retarget(path, budget, maximum):
        raw = read(path, budget, maximum)
        if path == target:
            link.unlink()
            link.symlink_to(changed)
        return raw

    monkeypatch.setattr(artifact_identity, "_read_regular", retarget)
    result = inspect_command("npm install fixture-package@1.2.3", str(tmp_path), environment={})
    assert not packages(result)
    assert result.unresolved


def test_cyclic_config_link_is_unresolved(tmp_path, isolated_identity_home):
    path = isolated_identity_home / ".npmrc"
    path.symlink_to(path)
    result = inspect_command("npm install fixture-package@1.2.3", str(tmp_path), environment={})
    assert not packages(result)
    assert result.unresolved


def test_symlinked_mcp_config_preserves_logical_format_and_location(tmp_path, isolated_identity_home):
    target = tmp_path / "configuration-data"
    target.write_text('[mcp_servers.fixture]\nurl="https://fixture.example.invalid/mcp"\n')
    config = isolated_identity_home / ".codex/config.toml"
    config.parent.mkdir(parents=True)
    config.symlink_to(target)
    event = {"tool_name": "mcp__fixture__lookup", "tool_input": {}, "cwd": str(tmp_path)}
    result = identify_event(event, "codex", tmp_path)
    assert subjects(result) == [{"kind": "mcp_endpoint", "url": "https://fixture.example.invalid/mcp"}]
    assert result.candidates[0].location == str(config)

def test_uv_nested_pip_configuration_and_explicit_config_file(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[tool.uv.pip]\nindex-url='https://private.example.invalid'\n")
    result = inspect_command("uv pip install fixture-package==1.2.3", str(tmp_path), environment={})
    assert packages(result)[0]["registry"] == "https://private.example.invalid"
    (tmp_path / "custom.toml").write_text("index-url='https://another.example.invalid'\n")
    result = inspect_command("uvx fixture-package==1.2.3", str(tmp_path),
                             environment={"UV_CONFIG_FILE": "custom.toml"})
    assert packages(result)[0]["registry"] == "https://another.example.invalid"


def test_ambiguous_indexes_and_credential_urls_are_unresolved(tmp_path):
    for environment in (
        {"PIP_EXTRA_INDEX_URL": "https://private.example.invalid"},
        {"PIP_INDEX_URL": "https://user:password@private.example.invalid"},
        {"NPM_CONFIG_REGISTRY": "https://user:password@private.example.invalid"},
    ):
        command = "npm install fixture-package@1.2.3" if "NPM_CONFIG_REGISTRY" in environment else (
            "pip install fixture-package==1.2.3"
        )
        if "PIP_EXTRA_INDEX_URL" in environment:
            command += " --index-url https://pypi.org/simple"
        result = inspect_command(command, str(tmp_path), environment=environment)
        assert not packages(result)
        assert result.unresolved
        assert "password" not in repr(result)


def test_configured_pip_and_uv_sources_do_not_assume_public(tmp_path, isolated_identity_home):
    pip = isolated_identity_home / ".config/pip"
    pip.mkdir(parents=True)
    (pip / "pip.conf").write_text("[global]\nindex-url=https://private.example.invalid/simple\n")
    result = inspect_command("pip install fixture-package==1.2.3", str(tmp_path), environment={})
    assert packages(result)[0]["registry"] == "https://private.example.invalid/simple"
    (tmp_path / "uv.toml").write_text("[[index]]\nurl='https://private.example.invalid/simple'\n")
    result = inspect_command("uv pip install fixture-package==1.2.3", str(tmp_path), environment={})
    assert not packages(result)
    assert result.unresolved
    # User-level uv tools do not read this local project configuration.
    assert packages(inspect_command("uvx fixture-package==1.2.3", str(tmp_path), environment={}))


def test_complete_file_hash_and_skill_identity(tmp_path):
    path = tmp_path / "SKILL.md"
    raw = b"---\nname: synthetic\n---\nInert test fixture.\n" + b"a" * 100000
    path.write_bytes(raw)
    result = inspect_file(path, skill=True)
    assert {item["kind"] for item in subjects(result)} == {"file_sha256", "skill_sha256"}
    assert {item["sha256"] for item in subjects(result)} == {hashlib.sha256(raw).hexdigest()}
    assert not result.unresolved
    other = tmp_path / "not-a-skill.txt"
    other.write_bytes(raw)
    assert {item["kind"] for item in subjects(inspect_file(other, skill=True))} == {"file_sha256"}


@pytest.mark.parametrize("harness,surface,tool_input", [
    ("claude", ".claude/skills", {"skill": "fixture"}),
    ("codex", ".agents/skills", {"skill": "fixture"}),
    ("opencode", ".opencode/skills", {"name": "fixture"}),
])
def test_named_skill_resolves_manifest_not_directory_name(tmp_path, harness, surface, tool_input):
    directory = "fixture" if harness == "opencode" else "different-directory"
    path = tmp_path / surface / directory / "SKILL.md"
    path.parent.mkdir(parents=True)
    path.write_text("---\nname: fixture\ndescription: inert fixture\n---\nNo action.\n")
    event = {"tool_name": "Skill", "tool_input": tool_input, "cwd": str(tmp_path)}
    result = identify_event(event, harness, tmp_path)
    assert {item["kind"] for item in subjects(result)} == {"file_sha256", "skill_sha256"}
    duplicate = path.parent.parent / "another" / "SKILL.md"
    if harness == "opencode":
        # A second documented source, with the same effective skill name.
        duplicate = Path.home() / ".claude/skills/fixture/SKILL.md"
    duplicate.parent.mkdir(parents=True)
    duplicate.write_bytes(path.read_bytes())
    result = identify_event(event, harness, tmp_path)
    assert not result.candidates
    assert result.unresolved == ["skill_name_ambiguous"]


def test_skill_custom_codex_home_and_explicit_path(tmp_path, monkeypatch):
    root = tmp_path / "alternate-codex"
    path = root / "skills" / "fixture" / "SKILL.md"
    path.parent.mkdir(parents=True)
    path.write_text("---\nname: fixture\n---\nInert.\n")
    monkeypatch.setenv("CODEX_HOME", str(root))
    event = {"tool_name": "Skill", "tool_input": {"skill": "fixture"}, "cwd": str(tmp_path)}
    assert identify_event(event, "codex", tmp_path).candidates
    event["tool_input"] = {"path": str(path)}
    assert identify_event(event, "codex", tmp_path).candidates
    event["tool_input"] = {"path": str(path.parent)}
    assert not identify_event(event, "codex", tmp_path).candidates


def test_hash_limits_and_nonregular_files_are_not_clean(tmp_path):
    path = tmp_path / "oversized"
    path.write_bytes(b"abcdef")
    for budget in (IdentityBudget(max_file_bytes=5), IdentityBudget(max_total_bytes=5),
                   IdentityBudget(max_files=0), IdentityBudget(seconds=-1)):
        result = inspect_file(path, budget=budget)
        assert not result.candidates and result.unresolved
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    assert inspect_file(fifo).unresolved
    assert inspect_file(tmp_path).unresolved
    assert inspect_file(tmp_path / "missing").unresolved


def test_symlink_and_hardlink_have_content_identity(tmp_path):
    original = tmp_path / "body"
    original.write_bytes(b"harmless fixture")
    symlink, hardlink = tmp_path / "symbolic", tmp_path / "hard"
    symlink.symlink_to(original)
    os.link(original, hardlink)
    expected = subjects(inspect_file(original))
    assert expected == subjects(inspect_file(symlink)) == subjects(inspect_file(hardlink))


def test_descriptor_change_is_not_a_partial_hash(tmp_path, monkeypatch):
    path = tmp_path / "changing"
    path.write_bytes(b"original")
    original = os.fstat
    calls = 0

    def change(fd):
        nonlocal calls
        calls += 1
        if calls == 2:
            path.write_bytes(b"changed bytes")
        return original(fd)

    monkeypatch.setattr(os, "fstat", change)
    result = inspect_file(path)
    assert not result.candidates and result.unresolved


def test_supported_file_reads_scripts_and_remediation(tmp_path):
    path = tmp_path / "SKILL.md"
    path.write_text("Inert fixture")
    for command in (f"cat '{path}'", f"python3 '{path}'", f"bash -c 'head {path}'"):
        assert subjects(inspect_command(command, str(tmp_path), environment={}))[0]["kind"] == "file_sha256"
    for tool in ("Write", "Edit", "Delete"):
        assert not identify_event(
            {"tool_name": tool, "tool_input": {"file_path": str(path)}, "cwd": str(tmp_path)},
            "codex", tmp_path,
        ).candidates


def test_shell_quoted_tilde_is_not_a_home_path(tmp_path):
    path = Path.home() / "SKILL.md"
    path.write_text("Inert fixture")
    assert inspect_command("cat ~/SKILL.md", str(tmp_path), environment={}).candidates
    assert not inspect_command("cat '~/SKILL.md'", str(tmp_path), environment={}).candidates
    assert not inspect_command("python3 '~/SKILL.md'", str(tmp_path), environment={}).candidates


@pytest.mark.parametrize("prefix", ["sed -n '1,260p'", "sed -n 4p", "sed -n -- '1,260p'",
                                   "sed -n '1,260p' --"])
def test_numeric_range_sed_reader_hashes_complete_bytes(prefix, tmp_path):
    path = tmp_path / "SKILL.md"
    path.write_bytes(b"first line\n" + b"unprinted fixture\n" * 400)
    result = inspect_command(f"{prefix} '{path}'", str(tmp_path), environment={})
    assert {item["sha256"] for item in subjects(result)} == {hashlib.sha256(path.read_bytes()).hexdigest()}
    assert {item["kind"] for item in subjects(result)} == {"file_sha256", "skill_sha256"}


@pytest.mark.parametrize("command", [
    "sed -i '' '1,260p' SKILL.md",
    "sed -n '1,260w copy' SKILL.md",
    "sed -n '1,260e' SKILL.md",
    "sed -n 'r SKILL.md' other",
    "sed -n -e '1,260p' SKILL.md",
    "echo \"sed -n '1,260p' SKILL.md\"",
])
def test_sed_remediation_scripts_and_mentions_are_not_literal_reads(command, tmp_path):
    (tmp_path / "SKILL.md").write_text("Inert fixture")
    assert not inspect_command(command, str(tmp_path), environment={}).candidates
def test_jsonc_mcp_definition_and_alias(tmp_path, isolated_identity_home):
    config = tmp_path / "opencode.jsonc"
    config.write_text('{"mcp": {/* note */ "fixture": {"type":"remote",'
                      '"url":"https://fixture.example.invalid/mcp",},},}')
    event = {"tool_name": "fixture_lookup", "tool_input": {}, "cwd": str(tmp_path)}
    result = identify_event(event, "opencode", tmp_path)
    assert subjects(result) == [{"kind": "mcp_endpoint", "url": "https://fixture.example.invalid/mcp"}]
    config.write_text('{"mcp":{"fixture":{"command":["npx","fixture-package@1.2.3"]}}}')
    assert packages(identify_event(event, "opencode", tmp_path))[0]["name"] == "fixture-package"


def test_mcp_fresh_config_conflicts_and_provenance(tmp_path, isolated_identity_home):
    project = tmp_path / ".mcp.json"
    project.write_text(json.dumps({"mcpServers": {"fixture": {"url": "https://one.example.invalid/mcp"}}}))
    event = {"tool_name": "mcp__fixture__lookup", "tool_input": {}, "cwd": str(tmp_path)}
    assert subjects(identify_event(event, "claude", tmp_path))[0]["url"] == "https://one.example.invalid/mcp"
    project.write_text(json.dumps({"mcpServers": {"fixture": {"url": "https://two.example.invalid/mcp"}}}))
    assert subjects(identify_event(event, "claude", tmp_path))[0]["url"] == "https://two.example.invalid/mcp"
    user = isolated_identity_home / ".claude.json"
    user.write_text(project.read_text())
    result = identify_event(event, "claude", tmp_path)
    assert not result.candidates and "mcp_definition_conflict" in result.unresolved
    event["mcp_server"] = {"name": "fixture", "source": "project"}
    assert subjects(identify_event(event, "claude", tmp_path))[0]["url"] == "https://two.example.invalid/mcp"
    event["mcp_server"]["source"] = "plugin"
    assert not identify_event(event, "claude", tmp_path).candidates


def test_mcp_duplicate_keys_invalid_shapes_and_secret_fields(tmp_path):
    (tmp_path / ".mcp.json").write_text('{"mcpServers":{"a":{},"a":{}}}')
    records, errors = read_mcp_configurations("claude", str(tmp_path))
    assert not records and errors
    for definition in (
        {"url": "https://secret@fixture.example.invalid/mcp"},
        {"url": "https://fixture.example.invalid/mcp?token=secret"},
        {"url": "https://fixture.example.invalid/mcp", "command": "npx"},
        {"command": ["npx", "$PACKAGE"]},
        {"command": ["npx", "fixture-package@1.2.3"], "args": ["extra"]},
        {"command": "npx", "args": "fixture-package@1.2.3"},
    ):
        result = inspect_mcp_definition(definition, tmp_path / "config.json", str(tmp_path), environment={})
        assert not result.candidates
        assert result.unresolved
        assert "secret" not in repr(result)


def test_mcp_private_registry_environment_and_disabled_definition(tmp_path):
    definition = {"command": ["npx", "fixture-package@1.2.3"],
                  "environment": {"NPM_CONFIG_REGISTRY": "https://private.example.invalid"}}
    result = inspect_mcp_definition(definition, tmp_path / "config.json", str(tmp_path), environment={})
    assert packages(result)[0]["registry"] == "https://private.example.invalid"
    definition["disabled"] = True
    assert not inspect_mcp_definition(definition, tmp_path / "config.json", str(tmp_path)).candidates
