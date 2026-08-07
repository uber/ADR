"""Tests for main_benchmark helpers."""

import asyncio
import os
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from main_benchmark import CommandBuilder, Config, MCPServerManager, TaskExecutor, TaskManager


class TestConfig:
    def test_default_max_concurrent_tasks(self, tmp_path: Path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        config = Config()
        assert config.max_concurrent_tasks == 10

    def test_disallowed_tools_loaded_from_config(self, detection_root: Path, monkeypatch):
        monkeypatch.chdir(detection_root)
        config = Config()
        disallowed = config.disallowed_tools
        assert "Write" in disallowed
        assert "ReadFile" in disallowed
        assert len(disallowed) > 10


class TestCommandBuilder:
    def test_builds_claude_command(self, tmp_path: Path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        builder = CommandBuilder(Config())
        cmd = builder.build_claude_command(
            {"user_prompt": "analyze logs"},
            ["mcp__demo__tool"],
        )
        assert cmd[0] == "claude"
        assert "-p" in cmd
        assert "analyze logs" in cmd
        assert "--output-format" in cmd
        assert "json" in cmd

    def test_adds_permission_bypass_flag(self, tmp_path: Path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        builder = CommandBuilder(Config())
        cmd = builder.build_claude_command({"user_prompt": "test"}, [])
        assert "--dangerously-skip-permissions" in cmd


class TestTaskManager:
    def test_filter_tasks_by_range(self, tmp_path: Path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        manager = TaskManager(Config())
        tasks = [{"task_id": i, "description": "d", "user_prompt": "p", "mcp_servers": []} for i in range(1, 6)]
        filtered = manager.filter_tasks_by_range(tasks, "2-3")
        assert [t["task_id"] for t in filtered] == [2, 3]

    def test_filter_tasks_by_csv_and_range(self, tmp_path: Path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        manager = TaskManager(Config())
        tasks = [{"task_id": i, "description": "d", "user_prompt": "p", "mcp_servers": []} for i in range(1, 11)]
        filtered = manager.filter_tasks_by_range(tasks, "1,3-4,10")
        assert [t["task_id"] for t in filtered] == [1, 3, 4, 10]

    def test_validate_task_requires_fields(self, tmp_path: Path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        manager = TaskManager(Config())
        valid = {"task_id": 1, "description": "d", "user_prompt": "p", "mcp_servers": []}
        invalid = {"task_id": 1, "description": "d"}
        assert manager.validate_task(valid) is True
        assert manager.validate_task(invalid) is False


class TestMCPServerManager:
    def test_create_mcp_config_writes_workspace_file(self, tmp_path: Path):
        manager = MCPServerManager(MagicMock())
        workspace = tmp_path / "task_001" / "workspace"
        workspace.mkdir(parents=True)

        server_configs = {
            "demo_server": {
                "command": "uv",
                "args_template": ["run", "python", "demo.py"],
                "capabilities": ["mcp__demo_server__tool"],
            }
        }
        _, allowed_tools = manager.create_mcp_config(server_configs, workspace)

        mcp_file = workspace / ".mcp.json"
        assert mcp_file.exists()
        assert "mcp__demo_server__tool" in allowed_tools

    def test_process_arg_template_replaces_workspace_path(self, tmp_path: Path):
        manager = MCPServerManager(MagicMock())
        workspace = tmp_path / "bench" / "task_001" / "workspace"
        workspace.mkdir(parents=True)
        result = manager._process_arg_template("--cwd={workspace_path}", workspace)
        assert result == "--cwd=."


class TestConcurrencyGuard:
    def test_rejects_zero_concurrency(self):
        max_concurrent = 0
        with pytest.raises(ValueError, match="max_concurrent_tasks must be >= 1"):
            if max_concurrent < 1:
                raise ValueError(f"max_concurrent_tasks must be >= 1, got {max_concurrent}")


class TestTaskExecutorExecuteCommand:
    """Covers _execute_command's process lifecycle, in particular that a timed-out
    claude CLI subprocess is actually killed rather than left running (previously
    asyncio.wait_for's timeout only cancelled the await, not the child process)."""

    def _make_executor(self, tmp_path: Path, monkeypatch, max_execution_time: float) -> TaskExecutor:
        monkeypatch.chdir(tmp_path)
        config = Config()
        config._config["execution"]["max_execution_time"] = max_execution_time
        return TaskExecutor(config)

    @pytest.mark.asyncio
    async def test_kills_process_on_timeout(self, tmp_path: Path, monkeypatch):
        executor = self._make_executor(tmp_path, monkeypatch, max_execution_time=0.05)

        real_create_subprocess_exec = asyncio.create_subprocess_exec
        spawned = {}

        async def spying_create_subprocess_exec(*args, **kwargs):
            process = await real_create_subprocess_exec(*args, **kwargs)
            spawned["process"] = process
            return process

        monkeypatch.setattr(asyncio, "create_subprocess_exec", spying_create_subprocess_exec)

        cmd = [sys.executable, "-c", "import time; time.sleep(5)"]
        success, error_message, result = await executor._execute_command(cmd, tmp_path)

        assert success is False
        assert "timed out" in error_message.lower()
        assert result is None

        # The process must have been killed and reaped, not left running in the
        # background after _execute_command returns.
        process = spawned["process"]
        assert process.returncode is not None

    @staticmethod
    def _wait_until_process_gone(pid: int, timeout: float = 3.0) -> bool:
        """Poll until a pid is fully reaped rather than asserting immediately -
        os.kill(pid, 0) on a not-yet-reaped zombie still succeeds, so a single
        check right after sending the kill signal can be a false negative."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return True
            except PermissionError:
                return False
            time.sleep(0.1)
        return False

    @pytest.mark.asyncio
    @pytest.mark.skipif(os.name != "posix", reason="process-group kill is POSIX-only")
    async def test_kills_grandchild_process_holding_inherited_stdio(self, tmp_path: Path, monkeypatch):
        """A descendant that inherits the CLI's stdout/stderr pipes must also be
        killed on timeout - process.kill() alone only signals the direct child,
        and a surviving descendant holding those pipes open can block
        process.wait() indefinitely instead of just leaking (see PR #20 review)."""
        executor = self._make_executor(tmp_path, monkeypatch, max_execution_time=0.2)

        real_create_subprocess_exec = asyncio.create_subprocess_exec
        spawned = {}

        async def spying_create_subprocess_exec(*args, **kwargs):
            process = await real_create_subprocess_exec(*args, **kwargs)
            spawned["process"] = process
            return process

        monkeypatch.setattr(asyncio, "create_subprocess_exec", spying_create_subprocess_exec)

        pidfile = tmp_path / "grandchild.pid"
        # The direct child spawns its own child ("grandchild") without
        # redirecting its stdout/stderr, so it inherits the same pipes
        # asyncio set up for the direct child - reproducing the scenario
        # where a descendant keeps those pipes open past the timeout.
        script = (
            "import subprocess, sys, time\n"
            "gc = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])\n"
            "open(sys.argv[1], 'w').write(str(gc.pid))\n"
            "time.sleep(30)\n"
        )
        cmd = [sys.executable, "-c", script, str(pidfile)]

        start = time.monotonic()
        success, error_message, result = await executor._execute_command(cmd, tmp_path)
        elapsed = time.monotonic() - start

        assert success is False
        assert "timed out" in error_message.lower()

        # Must return promptly, not hang for anywhere near the grandchild's
        # 30s sleep - proves process.wait() wasn't blocked on inherited pipes.
        assert elapsed < 10

        process = spawned["process"]
        assert process.returncode is not None

        for _ in range(30):
            if pidfile.exists():
                break
            await asyncio.sleep(0.1)
        assert pidfile.exists(), "grandchild never reported its pid"

        grandchild_pid = int(pidfile.read_text())
        assert self._wait_until_process_gone(grandchild_pid), "grandchild process was left running"

    @pytest.mark.asyncio
    async def test_returns_parsed_json_on_success(self, tmp_path: Path, monkeypatch):
        executor = self._make_executor(tmp_path, monkeypatch, max_execution_time=30)

        cmd = [sys.executable, "-c", "import json, sys; sys.stdout.write(json.dumps({'session_id': 'abc123'}))"]
        success, error_message, result = await executor._execute_command(cmd, tmp_path)

        assert success is True
        assert error_message is None
        assert result == {"session_id": "abc123"}

    @pytest.mark.asyncio
    async def test_reports_nonzero_exit_without_leaving_error_message_empty(self, tmp_path: Path, monkeypatch):
        executor = self._make_executor(tmp_path, monkeypatch, max_execution_time=30)

        cmd = [sys.executable, "-c", "import sys; sys.stderr.write('boom'); sys.exit(1)"]
        success, error_message, result = await executor._execute_command(cmd, tmp_path)

        assert success is False
        assert "boom" in error_message
        assert result is None
