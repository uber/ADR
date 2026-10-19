#!/usr/bin/env python3
"""
Benchmark JSONL Pack/Inflate Utility

Packs a benchmark directory tree into a single self-contained JSONL file,
or inflates a JSONL file back into the directory structure.

Usage:
  deflate: python benchmark_pack.py deflate <benchmark_dir> [--tasks-file <path>] [--output <file.jsonl>]
  inflate: python benchmark_pack.py inflate <file.jsonl> [--output-dir <dir>]
"""

import argparse
import json
import re
import sys
from pathlib import Path


def _find_tasks_file(benchmark_dir: Path, tasks_file_arg: str | None) -> Path | None:
    """Locate the tasks.json file."""
    if tasks_file_arg:
        p = Path(tasks_file_arg)
        if p.exists():
            return p
        print(f"Warning: --tasks-file {tasks_file_arg!r} not found", file=sys.stderr)
        return None

    # Default: <benchmark_dir>/../tasks.json, then <benchmark_dir>/tasks.json
    candidates = [
        benchmark_dir.parent / "tasks.json",
        benchmark_dir / "tasks.json",
    ]
    for c in candidates:
        if c.exists():
            return c
    print("Warning: tasks.json not found; manifest will omit task definitions", file=sys.stderr)
    return None


def _find_ground_truth_file(benchmark_dir: Path) -> Path | None:
    """Locate a ground_truth.json file alongside the benchmark directory."""
    candidates = [
        benchmark_dir / "ground_truth.json",
        benchmark_dir.parent / "ground_truth.json",
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def _load_json_file(path: Path) -> object:
    """Load JSON from a file, returning None on error."""
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"Warning: could not read {path}: {e}", file=sys.stderr)
        return None


def cmd_deflate(benchmark_dir: Path, tasks_file_arg: str | None, output: Path | None) -> None:
    """Pack a benchmark directory into a JSONL file."""
    if not benchmark_dir.is_dir():
        print(f"Error: {benchmark_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    benchmark_name = benchmark_dir.name
    if output is None:
        output = benchmark_dir.parent / f"{benchmark_name}.jsonl"

    tasks_path = _find_tasks_file(benchmark_dir, tasks_file_arg)
    tasks_content = None
    if tasks_path:
        tasks_content = _load_json_file(tasks_path)

    ground_truth_path = _find_ground_truth_file(benchmark_dir)
    ground_truth_content = None
    if ground_truth_path:
        ground_truth_content = _load_json_file(ground_truth_path)
        print(f"Including ground truth from {ground_truth_path}")
    else:
        print("Warning: ground_truth.json not found; manifest will omit ground truth", file=sys.stderr)

    # Discover task directories (task_NNN), skipping raw AgentDojo output
    # directories (task_NNN_agentdojo_run) that hold no conversation
    task_dirs = sorted(
        d for d in benchmark_dir.iterdir()
        if d.is_dir() and d.name.startswith("task_") and not d.name.endswith("_agentdojo_run")
    )
    task_count = len(task_dirs)

    print(f"Deflating {benchmark_name}: {task_count} tasks → {output}")

    with open(output, "w", encoding="utf-8") as out:
        # Line 1: manifest
        manifest = {
            "type": "manifest",
            "benchmark_name": benchmark_name,
            "task_count": task_count,
        }
        if tasks_content is not None:
            manifest["tasks"] = tasks_content
        if ground_truth_content is not None:
            manifest["ground_truth"] = ground_truth_content
        out.write(json.dumps(manifest, separators=(",", ":")) + "\n")

        # One line per task
        for task_dir in task_dirs:
            task_id = task_dir.name  # e.g. "task_001"

            # Load claude_conversation.json
            conversation = None
            conv_path = task_dir / "workspace" / "claude_conversation.json"
            if conv_path.exists():
                conversation = _load_json_file(conv_path)

            # Load result.json
            result = None
            result_path = task_dir / "result.json"
            if result_path.exists():
                result = _load_json_file(result_path)

            record = {
                "type": "task",
                "task_id": task_id,
                "conversation": conversation,
                "result": result,
            }
            out.write(json.dumps(record, separators=(",", ":")) + "\n")

    total_lines = task_count + 1
    print(f"Done: {output} ({total_lines} lines)")


def _write_json(path: Path, data: object, indent: int | None = None) -> None:
    """Write JSON to a file, exiting on error."""
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=indent)
    except (OSError, TypeError, ValueError) as e:
        print(f"Error: could not write {path}: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_inflate(jsonl_path: Path, output_dir: Path | None) -> None:
    """Recreate a benchmark directory tree from a JSONL file."""
    if not jsonl_path.exists():
        print(f"Error: {jsonl_path} not found", file=sys.stderr)
        sys.exit(1)

    if output_dir is None:
        name = jsonl_path.stem  # strip .jsonl
        output_dir = jsonl_path.parent / name

    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    print(f"Inflating {jsonl_path.name} → {output_dir}")

    tasks_written = 0
    with open(jsonl_path, encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"Warning: line {line_num} is not valid JSON: {e}", file=sys.stderr)
                continue

            rec_type = record.get("type")

            if rec_type == "manifest":
                tasks_content = record.get("tasks")
                if tasks_content is not None:
                    _write_json(output_dir / "tasks.json", tasks_content, indent=2)
                    print(f"  Wrote tasks.json")
                ground_truth_content = record.get("ground_truth")
                if ground_truth_content is not None:
                    _write_json(output_dir / "ground_truth.json", ground_truth_content, indent=2)
                    print(f"  Wrote ground_truth.json")

            elif rec_type == "task":
                task_id = record.get("task_id")
                if not isinstance(task_id, str) or not task_id:
                    print(f"Warning: line {line_num} has invalid task_id {task_id!r}, skipping", file=sys.stderr)
                    continue
                if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", task_id) or ".." in task_id:
                    print(f"Warning: line {line_num} has unsafe task_id {task_id!r}, skipping", file=sys.stderr)
                    continue
                task_dir = (output_dir / task_id).resolve()
                try:
                    task_dir.relative_to(output_dir)
                except ValueError:
                    print(f"Warning: line {line_num} task_id escapes output_dir, skipping", file=sys.stderr)
                    continue
                workspace_dir = task_dir / "workspace"
                workspace_dir.mkdir(parents=True, exist_ok=True)

                conversation = record.get("conversation")
                if conversation is not None:
                    _write_json(workspace_dir / "claude_conversation.json", conversation, indent=2)

                result = record.get("result")
                if result is not None:
                    _write_json(task_dir / "result.json", result, indent=2)

                tasks_written += 1

    print(f"Done: {tasks_written} tasks written to {output_dir}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Pack/inflate benchmark directory trees to/from JSONL"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # deflate subcommand
    p_deflate = sub.add_parser("deflate", help="Pack benchmark dir into a JSONL file")
    p_deflate.add_argument("benchmark_dir", type=Path, help="Benchmark directory to pack")
    p_deflate.add_argument(
        "--tasks-file", dest="tasks_file",
        help="Path to tasks.json (default: <benchmark_dir>/../tasks.json)"
    )
    p_deflate.add_argument(
        "--output", type=Path,
        help="Output JSONL path (default: <benchmark_dir>.jsonl)"
    )

    # inflate subcommand
    p_inflate = sub.add_parser("inflate", help="Expand JSONL file into a benchmark directory")
    p_inflate.add_argument("jsonl_file", type=Path, help="JSONL file to expand")
    p_inflate.add_argument(
        "--output-dir", dest="output_dir", type=Path,
        help="Output directory (default: <jsonl_file> without .jsonl extension)"
    )

    args = parser.parse_args()

    if args.command == "deflate":
        cmd_deflate(
            benchmark_dir=args.benchmark_dir.resolve(),
            tasks_file_arg=args.tasks_file,
            output=args.output,
        )
    elif args.command == "inflate":
        cmd_inflate(
            jsonl_path=args.jsonl_file.resolve(),
            output_dir=args.output_dir,
        )


if __name__ == "__main__":
    main()
