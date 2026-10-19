"""Tests for benchmark JSONL pack/inflate."""

import json
from pathlib import Path

import pytest

from benchmark.benchmark_pack import cmd_deflate, cmd_inflate


class TestBenchmarkPackRoundTrip:
    def test_deflate_and_inflate_round_trip(self, tmp_path: Path):
        bench_dir = tmp_path / "mini_bench"
        bench_dir.mkdir()
        tasks = {"tasks": [{"task_id": 1, "description": "demo"}]}
        with open(tmp_path / "tasks.json", "w", encoding="utf-8") as f:
            json.dump(tasks, f)

        task_dir = bench_dir / "task_001" / "workspace"
        task_dir.mkdir(parents=True)
        conversation = {"messages": [{"role": "user", "content": "hi"}]}
        with open(task_dir / "claude_conversation.json", "w", encoding="utf-8") as f:
            json.dump(conversation, f)
        with open(bench_dir / "task_001" / "result.json", "w", encoding="utf-8") as f:
            json.dump({"ok": True}, f)

        jsonl_path = tmp_path / "mini_bench.jsonl"
        cmd_deflate(bench_dir, tasks_file_arg=str(tmp_path / "tasks.json"), output=jsonl_path)

        out_dir = tmp_path / "restored"
        cmd_inflate(jsonl_path, out_dir)

        assert (out_dir / "tasks.json").exists()
        assert (out_dir / "task_001" / "workspace" / "claude_conversation.json").exists()
        assert (out_dir / "task_001" / "result.json").exists()


    def test_deflate_skips_raw_agentdojo_run_dirs(self, tmp_path: Path):
        bench_dir = tmp_path / "agentdojo_20260101_000000"
        bench_dir.mkdir()
        workspace = bench_dir / "task_001" / "workspace"
        workspace.mkdir(parents=True)
        with open(workspace / "claude_conversation.json", "w", encoding="utf-8") as f:
            json.dump([{"role": "user", "content": "hi"}], f)
        # Raw AgentDojo output written next to the converted task directory.
        (bench_dir / "task_001_agentdojo_run" / "slack").mkdir(parents=True)

        jsonl_path = tmp_path / "out.jsonl"
        cmd_deflate(bench_dir, tasks_file_arg=None, output=jsonl_path)

        records = [json.loads(line) for line in jsonl_path.read_text().splitlines()]
        assert records[0]["task_count"] == 1
        assert [r["task_id"] for r in records[1:]] == ["task_001"]

class TestBenchmarkPackSecurity:
    def test_rejects_path_traversal_task_id(self, tmp_path: Path, sample_jsonl: Path, capsys):
        malicious = sample_jsonl.read_text().splitlines()
        malicious.append(
            json.dumps({"type": "task", "task_id": "..", "conversation": {"x": 1}})
        )
        bad_jsonl = tmp_path / "bad.jsonl"
        bad_jsonl.write_text("\n".join(malicious) + "\n")

        out_dir = tmp_path / "out"
        cmd_inflate(bad_jsonl, out_dir)

        assert not (tmp_path / "claude_conversation.json").exists()
        captured = capsys.readouterr()
        assert "unsafe task_id" in captured.err or "escapes output_dir" in captured.err

    def test_rejects_non_string_task_id(self, tmp_path: Path, capsys):
        jsonl_path = tmp_path / "bad.jsonl"
        with open(jsonl_path, "w", encoding="utf-8") as f:
            f.write(json.dumps({"type": "manifest", "benchmark_name": "x", "task_count": 1}) + "\n")
            f.write(json.dumps({"type": "task", "task_id": 1, "conversation": {}}) + "\n")

        out_dir = tmp_path / "out"
        cmd_inflate(jsonl_path, out_dir)
        assert not any(out_dir.iterdir()) or not (out_dir / "task_1").exists()
        assert "invalid task_id" in capsys.readouterr().err

    def test_skips_invalid_json_lines(self, tmp_path: Path, sample_jsonl: Path, capsys):
        content = sample_jsonl.read_text() + "not-json\n"
        bad_jsonl = tmp_path / "broken.jsonl"
        bad_jsonl.write_text(content)

        out_dir = tmp_path / "out"
        cmd_inflate(bad_jsonl, out_dir)
        assert (out_dir / "task_001").exists()
        assert "not valid JSON" in capsys.readouterr().err
