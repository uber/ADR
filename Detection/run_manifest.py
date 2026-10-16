"""Best-effort run provenance for detector analysis output."""

from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence

_HASH_ALGORITHM = "sha256"
_GIT_TIMEOUT_SECONDS = 2

def read_text_with_sha256(
    path: Path, *, encoding: Optional[str] = None
) -> tuple[str, Optional[str]]:
    """Read once, returning parser input and a best-effort hash of those raw bytes.

    Preserve the caller's text-mode encoding and newline handling. Read/decode
    errors still reach the existing input loader; only provenance is nonfatal.
    """
    content = path.read_bytes()
    with io.TextIOWrapper(io.BytesIO(content), encoding=encoding) as handle:
        text = handle.read()
    try:
        digest = hashlib.sha256(content).hexdigest()
    except Exception:
        digest = None
    return text, digest

def _sha256_file(path: Path) -> Optional[str]:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except (OSError, PermissionError):
        return None

def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()

def _git_output(repo_root: Path, *args: str) -> Optional[str]:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=repo_root,
            capture_output=True,
            check=True,
            text=True,
            timeout=_GIT_TIMEOUT_SECONDS,
        )
        return completed.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None

def _git_provenance(repo_root: Path) -> Dict[str, Any]:
    commit = _git_output(repo_root, "rev-parse", "HEAD")
    status = _git_output(repo_root, "status", "--porcelain")
    return {
        "commit": commit or None,
        "dirty": None if status is None else bool(status),
    }

def collect_source_metadata(detection_root: Path) -> Dict[str, Any]:
    """Capture source and lockfile metadata before detector analysis starts."""
    try:
        source = _git_provenance(detection_root.parent)
    except Exception:
        source = {"commit": None, "dirty": None}
    try:
        uv_lock = _sha256_file(detection_root / "uv.lock")
    except Exception:
        uv_lock = None
    return {"source": source, "uv_lock": uv_lock}

def _task_id(task_dir: Path) -> Optional[int]:
    try:
        return int(task_dir.name.removeprefix("task_"))
    except ValueError:
        return None

def _conversation_provenance(
    task_dirs: Iterable[Path], conversation_hashes: Mapping[str, Optional[str]]
) -> Dict[str, Any]:
    selected: list[Dict[str, Any]] = []
    missing: list[int] = []
    for task_dir in task_dirs:
        task_id = _task_id(task_dir)
        if task_id is None:
            continue
        digest = conversation_hashes.get(task_dir.name)
        if digest is None:
            missing.append(task_id)
        else:
            selected.append({"task_id": task_id, "sha256": digest})

    selected.sort(key=lambda item: int(item["task_id"]))
    missing.sort()
    return {
        "algorithm": _HASH_ALGORITHM,
        "count": len(selected),
        "aggregate_sha256": _canonical_sha256(selected),
        "missing_task_ids": missing,
    }

def _effective_labels_provenance(
    task_dirs: Iterable[Path], effective_labels: Mapping[str, bool]
) -> Dict[str, Any]:
    labels = []
    missing = []
    for task_dir in task_dirs:
        task_id = _task_id(task_dir)
        if task_id is None:
            continue
        key = task_dir.name
        if key not in effective_labels:
            missing.append(task_id)
        else:
            labels.append({"task_id": task_id, "is_malicious": bool(effective_labels[key])})
    labels.sort(key=lambda item: item["task_id"])
    missing.sort()
    return {
        "algorithm": _HASH_ALGORITHM,
        "count": len(labels),
        "sha256": _canonical_sha256(labels),
        "missing_task_ids": missing,
    }

def collect_run_manifest(
    *,
    benchmark_type: str,
    task_dirs: Sequence[Path],
    effective_labels: Mapping[str, bool],
    resolved_concurrency: int,
    conversation_hashes: Mapping[str, Optional[str]],
    artifact_hashes: Mapping[str, Optional[str]],
    source: Mapping[str, Any],
) -> Dict[str, Any]:
    """Collect nonfatal, privacy-safe provenance for one detector run.

    Assemble only metadata captured at input load time, without rereading files
    or Git after analysis. Exclude paths, directory basenames, host names,
    environment values, and file contents. Any unavailable metadata is null.
    """
    selected_task_ids = sorted(
        task_id for task_dir in task_dirs if (task_id := _task_id(task_dir)) is not None
    )

    try:
        conversations = _conversation_provenance(task_dirs, conversation_hashes)
    except Exception:
        conversations = None
    try:
        labels = _effective_labels_provenance(task_dirs, effective_labels)
    except Exception:
        labels = None
    artifacts = {
        "config_detector": artifact_hashes.get("config_detector"),
        "uv_lock": artifact_hashes.get("uv_lock"),
        "tasks": artifact_hashes.get("tasks") if benchmark_type == "adr_bench" else None,
        "agentdojo_ground_truth": (
            artifact_hashes.get("agentdojo_ground_truth") if benchmark_type == "agentdojo" else None
        ),
    }

    return {
        "schema_version": 1,
        "kind": "run_provenance",
        "benchmark_type": benchmark_type,
        "resolved_concurrency": resolved_concurrency,
        "selected_task_ids": selected_task_ids,
        "source": {"commit": source.get("commit"), "dirty": source.get("dirty")},
        "inputs": {
            "conversations": conversations,
            "effective_labels": labels,
            "artifacts": {"algorithm": _HASH_ALGORITHM, **artifacts},
        },
        "runtime": {"python_version": sys.version.split()[0]},
    }
