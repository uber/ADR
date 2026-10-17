"""Windows text and argv, plus the narrow PowerShell profile privacy boundary."""

from __future__ import annotations

import json
import os
import subprocess

import pytest

from adr_discovery.contracts.commandline import windows_argv
from adr_discovery.contracts.powershell import environment_names
from adr_discovery.contracts.records import Candidate, Declaration, Kind
from adr_discovery.enumerator.sources.profiles import from_profiles
from adr_discovery.extractor import extract
from adr_discovery.extractor.formats import parse_bytes
from adr_discovery.judge.risk import launch_shape, package_of, pinning
from adr_discovery.pipeline import _dedupe_surfaces, _observation_from_declaration
from adr_discovery.redact.rules import scrub_argv
from adr_discovery.world.gate import Gate, Ok, Ran
from adr_discovery.world.platform import windows
from adr_discovery.world.platform.base import NullProviders
from adr_discovery.world.platform.windows import WindowsProviders


@pytest.mark.parametrize("argv", [
    (r"C:\Program Files\Node\npx.cmd", "-y", "@example/server@1.2.3"),
    ("tool.exe", "", "two words", "中文", "trailing space "),
    ("tool.exe", "backslashes\\\\", 'embedded"quote', 'space trailing\\'),
    ("tool.exe", 'before\\\\"quote', 'before\\"quote', "C:\\用户\\folder\\"),
])
def test_windows_argv_inverts_stdlib_windows_quoting(argv):
    assert windows_argv(subprocess.list2cmdline(argv)) == argv


def test_windows_argv_preserves_single_quotes_and_metacharacters():
    assert windows_argv("tool.exe 'two words' %USERPROFILE% & whoami") == (
        "tool.exe", "'two", "words'", "%USERPROFILE%", "&", "whoami",
    )
    assert windows_argv('tool.exe "a""b" "unterminated') == ("tool.exe", 'a"b', "unterminated")
    with pytest.raises(ValueError, match="unterminated"):
        windows_argv('tool.exe "unterminated', strict=True)
    with pytest.raises(ValueError):
        windows_argv("tool.exe\0payload")


def test_windows_provider_collects_argv_without_posix_quote_characters(tmp_path, monkeypatch):
    provider = WindowsProviders()
    argv = (r"C:\Program Files\Node\NPX.CMD", "-y", "example@1.2.3", "--token", "secret value")
    payload = json.dumps([{
        "ProcessId": 42, "ParentProcessId": 7, "ExecutablePath": argv[0],
        "CommandLine": subprocess.list2cmdline(argv),
    }])
    gate = Gate(str(tmp_path), providers=provider)
    monkeypatch.setattr(windows, "powershell_path", lambda: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", raising=False)
    monkeypatch.setattr(gate, "run_helper", lambda command: Ok(Ran(command, 0, payload)))
    result = provider.processes(gate)
    assert result.ok and result.value[0].argv == argv
    assert "secret value" not in repr(scrub_argv(result.value[0].argv))


@pytest.mark.parametrize("command", ["NPX.CMD", r"C:\Program Files\Node\npx.cmd", "c:/Tools/NPX.EXE", "npx.bat", "C:NPX.CMD", r"\\server\share\npx.CmD"])
def test_windows_runner_pinning_and_package_identity(command):
    args = ("-y", "@example/server@1.2.3")
    assert pinning(command, args) == (True, ())
    assert launch_shape(command, args) == "package_runner"
    assert package_of(command, args) == ("npm", "@example/server", "1.2.3")
    assert pinning(command, ("example",))[0] is False


def test_quoted_windows_commandline_and_docker_drive_mount():
    line = '"C:\\Program Files\\Node\\npx.cmd" -y "@example/server@1.2.3"'
    assert package_of(line, ()) == ("npm", "@example/server", "1.2.3")
    assert pinning(line, ())[0] is True
    command = r"C:\Program Files\Docker\DOCKER.EXE"
    args = ("run", "-v", r"C:\work:/data", "ghcr.io/example/server@sha256:abcdef123456")
    assert pinning(command, args)[0] is True
    assert launch_shape(command, args) == "container"
    assert launch_shape(r"C:\Program Files\local.exe", (), separated=True) == "local"


@pytest.mark.parametrize("command", ["cmd.exe", "CMD.EXE", r"C:\Windows\System32\cmd.exe", "powershell.exe", "pwsh.exe", "CMD", "PowerShell", "PWSH"])
def test_shell_wrapper_is_opaque_unknown_and_drops_script_arguments(command):
    args = ("/c", "npx example@1.2.3 --token SECRET")
    assert launch_shape(command, args) == "unknown"
    assert pinning(command, args) == (None, ())
    assert package_of(command, args) is None
    declaration = Declaration(Kind.MCP_SERVER, "wrapped", "/config.json", command=command, args=args)
    assert "SECRET" not in repr(declaration)


def test_package_flag_keeps_its_identity_and_shell_call_bodies_are_redacted():
    declaration = Declaration(Kind.MCP_SERVER, "x", "/config.json", command="NPX.CMD",
                              args=("-p", "@example/server@1.2.3", "server", "--token", "SECRET"))
    assert package_of(declaration.command, declaration.args) == ("npm", "@example/server", "1.2.3")
    assert "SECRET" not in repr(declaration)
    assert "SECRET" not in repr(scrub_argv(("npx.cmd", "--call=echo SECRET")))
    assert "SECRET" not in repr(scrub_argv(("npx.cmd", "-cecho SECRET")))


@pytest.mark.parametrize("runner", ["docker.exe", "podman.exe"])
@pytest.mark.parametrize("args", [("login", "-p", "SECRET"), ("login", "-pSECRET"),
                                  ("run", "image", "-p", "SECRET"), ("run", "--", "image", "-pSECRET")])
def test_container_password_and_forwarded_short_flags_remain_redacted(runner, args):
    assert "SECRET" not in repr(scrub_argv((runner, *args)))


@pytest.mark.parametrize("argv", [
    ("npx.cmd", "@anthropic-ai/claude-code", "-p", "SECRET"),
    ("npx.cmd", "-p", "package@1.2.3", "command", "-p", "SECRET"),
    ("uvx.exe", "agent", "-pSECRET"),
    ("pnpm.cmd", "dlx", "agent", "--", "-p", "SECRET"),
    ("npx.cmd", "--", "-p", "SECRET"),
])
def test_package_runner_forwarded_prompt_flags_remain_redacted(argv):
    safe = scrub_argv(argv)
    assert "SECRET" not in repr(safe)
    if "package@1.2.3" in argv:
        assert "package@1.2.3" in safe


@pytest.mark.parametrize("program", [r"\\server\share\My Tool\server.exe", "//server/share/My Tool/server.exe"])
def test_bare_unc_executable_with_spaces_is_not_split(tmp_path, program):
    _gate, result = _config(tmp_path, {"mcpServers": {"unc": {"command": program}}})
    assert result.declarations[0].command == program
    assert result.declarations[0].args == ()


def test_invalid_command_diagnostics_do_not_expose_the_line(tmp_path):
    gate, result = _config(tmp_path, {"mcpServers": {
        "bad": {"command": 'npx.cmd "SECRET'},
        "good": {"command": "npx.cmd", "args": ["example@1.2.3"]},
    }})
    assert result.declared == 2 and len(result.errors) == 1 and len(result.declarations) == 1
    assert "SECRET" not in repr(result) + repr(gate.ledger.freeze())


class _WindowsProfiles(NullProviders):
    command_syntax = "windows"

    def __init__(self, paths=()):
        self.paths = paths

    def powershell_profile_paths(self, _gate):
        return self.paths


def _config(tmp_path, document):
    (tmp_path / "config.json").write_text(json.dumps(document), encoding="utf-8")
    gate = Gate(str(tmp_path), providers=_WindowsProfiles())
    return gate, extract(gate, Candidate("marker_file", "/config.json", "test"))


def test_config_distinguishes_explicit_argv_from_legacy_line_and_scrubs_inline_secrets(tmp_path):
    program = r"C:\Program Files\Node\npx.cmd"
    gate, result = _config(tmp_path, {"mcpServers": {
        "explicit": {"command": program, "args": []},
        "line": {"command": f'"{program}" -y example@1.2.3 --token "SECRET VALUE"'},
        "wrapper": {"command": "powershell.exe", "args": ["-Command", "$env:OPENAI_API_KEY='SECRET'"]},
    }})
    assert not result.errors
    explicit, line, wrapper = result.declarations
    assert explicit.command == program and explicit.args == ()
    assert line.command == program and line.args == ("-y", "example@1.2.3", "--token", "<redacted>")
    assert wrapper.args == ("<redacted>",)
    assert all(row.raw["command_format"] == "argv" for row in result.declarations)
    assert "SECRET" not in repr(result) + repr(gate.ledger.freeze())


@pytest.mark.parametrize("encoding", ["utf-8-sig", "utf-16", "utf-16-be"])
def test_json_bom_decodes_unicode_exactly(tmp_path, encoding):
    document = {"mcpServers": {"示例": {"command": "npx.cmd", "args": ["example@1.2.3"]}}}
    data = json.dumps(document, ensure_ascii=False).encode(encoding)
    if encoding == "utf-16-be":
        data = b"\xfe\xff" + data
    assert parse_bytes(data, "json") == document
    (tmp_path / "config.json").write_bytes(data)
    gate = Gate(str(tmp_path))
    assert json.loads(gate.read_text("/config.json").value) == document
    result = extract(gate, Candidate("marker_file", "/config.json", "test"))
    assert result.declarations[0].name == "示例"


def test_utf8_bom_toml_and_invalid_encoding_report_degraded_without_source_bytes(tmp_path):
    assert parse_bytes(b"\xef\xbb\xbfname = 'test'", "toml") == {"name": "test"}
    for data in (b'{"secret":"SECRET"}\xff', b"\xff\xfe{", b"\xff\xfe\x00\x00SECRET"):
        (tmp_path / "config.json").write_bytes(data)
        gate = Gate(str(tmp_path))
        read = gate.read_text("/config.json")
        result = extract(gate, Candidate("marker_file", "/config.json", "test"))
        assert not read.ok and read.reason == "invalid_encoding"
        assert result.errors and not result.declarations
        assert any(probe.status == "degraded" for probe in gate.ledger.freeze().probes)
        assert "SECRET" not in repr(result) + repr(read) + repr(gate.ledger.freeze())
    with pytest.raises(ValueError, match="UTF-16"):
        parse_bytes("name = 'test'".encode("utf-16"), "toml")


def _profile(tmp_path, *, redirected=False):
    logical = ("/Redirected Personal" if redirected else "/Users/Alice/Documents") + "/PowerShell/Microsoft.PowerShell_profile.ps1"
    target = tmp_path / logical.lstrip("/")
    target.parent.mkdir(parents=True)
    target.write_bytes("$env:OPENAI_API_KEY = 'SECRET'\r\n$ENV:anthropic_api_key='OTHER'\r\n".encode("utf-16"))
    gate = Gate(str(tmp_path), providers=_WindowsProfiles((logical,)))
    return gate, logical, target


@pytest.mark.parametrize("redirected", [False, True])
def test_only_known_profiles_are_enumerated_and_only_names_survive(tmp_path, redirected):
    gate, logical, target = _profile(tmp_path, redirected=redirected)
    neighbor = target.with_name("private.txt")
    neighbor.write_text("PRIVATE", encoding="utf-8")
    candidates = from_profiles(gate)
    assert len(candidates) == 1 and candidates[0].path == logical
    assert _dedupe_surfaces(gate, candidates)[0].kind == "shell_profile"
    result = extract(gate, candidates[0])
    assert result.declarations[0].env_names == ("ANTHROPIC_API_KEY", "OPENAI_API_KEY")
    observation = _observation_from_declaration(candidates[0], result.declarations[0], gate)
    assert observation.modified is not None
    assert not gate.read_profile(logical.rsplit("/", 1)[0] + "/private.txt").ok
    assert not gate.read_profile(logical.rsplit("/", 1)[0] + "/profile.ps1").ok
    if not redirected:
        assert not gate.read_bytes(logical).ok
        assert not gate.list_dir("/Users/Alice/Documents").ok
    assert "SECRET" not in repr(result) + repr(observation) + repr(gate.ledger.freeze())


def test_profile_parser_skips_comments_and_multiline_strings():
    source = '''# $env:OPENAI_API_KEY='comment'
<#
$env:OPENAI_API_KEY='block'
#>
$value = @"
$env:OPENAI_API_KEY='here'
"@
$value = 'multiline
$env:OPENAI_API_KEY=''string''
'
$env:ANTHROPIC_API_KEY='actual'
[Environment]::SetEnvironmentVariable('OPENAI_API_KEY','not evaluated')
'''
    assert environment_names(source) == ("ANTHROPIC_API_KEY",)


def test_profile_replacement_after_validation_is_refused(tmp_path):
    gate, logical, target = _profile(tmp_path)

    def replace(_resolved):
        target.rename(target.with_suffix(".saved"))
        target.write_text("$env:OPENAI_API_KEY='replacement'", encoding="utf-8")

    gate.on_validated = replace
    result = gate.read_profile(logical)
    assert not result.ok and result.reason == "swapped"


def test_profile_file_symlink_is_refused(tmp_path):
    gate, logical, target = _profile(tmp_path)
    outside = tmp_path / "private.txt"
    outside.write_text("SECRET", encoding="utf-8")
    target.unlink()
    try:
        target.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"file symlinks unavailable: {exc}")
    assert not gate.read_profile(logical).ok
    assert from_profiles(gate) == ()


@pytest.mark.parametrize("logical,requested", [
    ("/Users/Alice/.ssh/PowerShell/profile.ps1", "/Users/Alice/.ssh/PowerShell/profile.ps1"),
    ("/.ssh/PowerShell/profile.ps1", ".ssh/PowerShell/profile.ps1"),
    ("/.ssh/PowerShell/profile.ps1", "folder/../.ssh/PowerShell/profile.ps1"),
])
def test_profile_exception_does_not_bypass_other_personal_boundaries(tmp_path, logical, requested):
    target = tmp_path / logical.lstrip("/")
    target.parent.mkdir(parents=True)
    target.write_text("$env:OPENAI_API_KEY='SECRET'", encoding="utf-8")
    gate = Gate(str(tmp_path), providers=_WindowsProfiles((logical,)))
    assert gate.read_profile(requested).reason == "personal_path"


def test_profile_hardlink_is_refused(tmp_path):
    gate, logical, target = _profile(tmp_path)
    os.link(target, target.with_suffix(".other"))
    assert not gate.read_profile(logical).ok


@pytest.mark.skipif(os.name != "nt", reason="native Windows junction boundary")
def test_profile_ancestor_junction_is_refused(tmp_path):
    gate, logical, target = _profile(tmp_path)
    original = target.parent
    moved = original.with_name("redirected")
    original.rename(moved)
    made = subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J", str(original), str(moved)],
                          check=False, capture_output=True)
    assert made.returncode == 0, made.stderr.decode(errors="replace")
    try:
        assert not gate.read_profile(logical).ok
        assert from_profiles(gate) == ()
    finally:
        os.rmdir(original)
