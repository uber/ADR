"""Literal shell-read coverage, including the real Codex Bash hook envelope."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from adr_desktop.policy import evaluate


def snapshot(path, *, action="block", strict=False):
    return {
        "version": 1,
        "enabled": True,
        "strict_execution": strict,
        "opaque_tools": "ask",
        "rules": [
            {"id": "fixture", "path": str(path), "kind": "file", "action": action, "label": "Protected"}
        ],
        "control_paths": [],
    }


def bash(cwd, command, **arguments):
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command, **arguments},
        "cwd": str(cwd),
        "session_id": "synthetic-live-regression",
    }


@pytest.mark.parametrize(
    "command",
    [
        "/bin/cat protected.txt",
        "cat -n protected.txt",
        "cat --number -- protected.txt",
        "/bin/sh -c '/bin/cat protected.txt'",
        "bash -lc 'cat protected.txt'",
        "head -n 2 protected.txt",
        "head -c10 protected.txt",
        "tail --lines=2 protected.txt",
        "tail -n +2 protected.txt",
    ],
)
def test_literal_shell_read_checks_the_same_file_rules(tmp_path, command):
    protected = tmp_path / "protected.txt"
    result = evaluate(bash(tmp_path, command), "codex", snapshot(protected))
    assert result.decision == "deny"
    assert result.paths == [str(protected)]
    assert result.rule_id == "fixture"


def test_literal_shell_read_of_public_file_remains_native(tmp_path):
    result = evaluate(
        bash(tmp_path, "cat public.txt"), "codex", snapshot(tmp_path / "protected.txt")
    )
    assert result.decision == "pass"
    assert result.rule_id is None


def test_quoted_filename_and_explicit_workdir_are_resolved(tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    protected = other / "private file.txt"
    result = evaluate(
        bash(tmp_path, "cat 'private file.txt'", workdir=str(other)), "codex", snapshot(protected)
    )
    assert result.decision == "deny"
    assert result.paths == [str(protected)]


@pytest.mark.parametrize("tool", ["cat", "head", "tail"])
def test_bsd_options_after_an_operand_are_checked_as_filenames(tmp_path, tool):
    protected = tmp_path / "-n"
    result = evaluate(
        bash(tmp_path, f"{tool} public.txt -n"), "codex", snapshot(protected)
    )
    assert result.decision == "deny"
    assert str(protected) in result.paths


@pytest.mark.parametrize("filename", ["'~/protected.txt'", '"~/protected.txt"', r"\~/protected.txt"])
def test_quoted_or_escaped_tilde_is_a_literal_relative_directory(tmp_path, filename):
    protected = tmp_path / "~" / "protected.txt"
    result = evaluate(bash(tmp_path, "cat " + filename), "codex", snapshot(protected))
    assert result.decision == "deny"
    assert result.paths == [str(protected)]


def test_only_unquoted_leading_tilde_expands_home():
    protected = Path.home() / "adr-synthetic-never-created-test.txt"
    result = evaluate(
        bash("/", "cat ~/adr-synthetic-never-created-test.txt"), "codex", snapshot(protected)
    )
    assert result.decision == "deny"


def test_comments_are_not_paths_and_do_not_hide_a_real_operand(tmp_path):
    protected = tmp_path / "protected.txt"
    assert evaluate(
        bash(tmp_path, "cat public.txt # protected.txt"), "codex", snapshot(protected)
    ).decision == "pass"
    assert evaluate(
        bash(tmp_path, "cat protected.txt # comment; with 'unclosed quote"),
        "codex",
        snapshot(protected),
    ).decision == "deny"


def test_hash_in_a_quoted_or_unquoted_filename_is_not_a_comment(tmp_path):
    protected = tmp_path / "private#file"
    for filename in ("private#file", "'private#file'"):
        assert evaluate(bash(tmp_path, "cat " + filename), "codex", snapshot(protected)).decision == "deny"
    protected = tmp_path / "#private"
    assert evaluate(
        bash(tmp_path, "cat '#private'"), "codex", snapshot(protected)
    ).decision == "deny"


def test_unified_exec_cmd_and_workdir_are_supported(tmp_path):
    protected = tmp_path / "protected.txt"
    event = {
        "tool_name": "exec_command",
        "tool_input": {"cmd": "cat protected.txt", "workdir": str(tmp_path)},
        "cwd": "/",
    }
    assert evaluate(event, "codex", snapshot(protected)).decision == "deny"


def test_shell_alias_resolves_symlink_and_does_not_read_secret_value(tmp_path):
    protected = tmp_path / "protected.txt"
    protected.write_text("synthetic-value-do-not-disclose")
    alias = tmp_path / "alias"
    alias.symlink_to(protected)
    result = evaluate(bash(tmp_path, "cat alias"), "codex", snapshot(protected))
    assert result.decision == "deny"
    assert "synthetic-value" not in json.dumps(result.as_dict())
    assert "cat alias" not in json.dumps(result.as_dict())


@pytest.mark.parametrize(
    "command",
    [
        "cat protected.txt | head",
        "cat protected.txt; echo done",
        "cat protected.txt && echo done",
        "cat $FILE",
        "cat *.txt",
        "python -c 'print(1)'",
        "cat < protected.txt",
        "cat --unknown-option protected.txt",
        "head -n not-a-number protected.txt",
        "bash -c 'cat protected.txt' unused-positional",
    ],
)
def test_opaque_or_compound_commands_keep_explicit_strict_policy(tmp_path, command):
    event = bash(tmp_path, command)
    protected = tmp_path / "protected.txt"
    assert evaluate(event, "codex", snapshot(protected)).decision == "pass"
    assert evaluate(event, "codex", snapshot(protected, strict=True)).decision == "ask"


def test_strict_mode_still_reviews_even_a_public_literal_command(tmp_path):
    result = evaluate(
        bash(tmp_path, "cat public.txt"), "codex", snapshot(tmp_path / "protected.txt", strict=True)
    )
    assert result.decision == "ask"
    assert result.reason_code == "execution_policy"


def test_shell_read_resolves_ask_policy_without_weakened_scope(tmp_path):
    result = evaluate(
        bash(tmp_path, "cat protected.txt"), "codex", snapshot(tmp_path / "protected.txt", action="ask")
    )
    assert result.decision == "ask"
    assert result.rule_id == "fixture"


def test_explicit_command_block_has_priority_over_file_ask(tmp_path):
    policy = snapshot(tmp_path / "protected.txt", action="ask", strict=True)
    policy["opaque_tools"] = "block"
    result = evaluate(bash(tmp_path, "cat protected.txt"), "codex", policy)
    assert result.decision == "deny"
    assert result.reason_code == "execution_policy"


def test_native_codex_hook_blocks_literal_read_with_daemon_offline(runtime, tmp_path):
    protected = tmp_path / "protected.txt"
    runtime.change_policy(add={"path": str(protected), "action": "block", "kind": "file"})
    result = subprocess.run(
        [
            sys.executable, "-m", "adr_desktop", "hook",
            "--harness", "codex", "--state-dir", str(runtime.state_dir),
        ],
        input=json.dumps(bash(tmp_path, "/bin/cat protected.txt")),
        capture_output=True,
        text=True,
        timeout=8,
    )
    assert result.returncode == 0
    output = json.loads(result.stdout)
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
