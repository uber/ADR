"""Reuse ADR collectors in bounded, isolated workers; never configure an exporter."""

import contextlib
import json
import logging
import os
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

from .config import MAX_JSON_BYTES, atomic_json, command_prefix, strict_json, utcnow

SOURCE_LABELS = {
    "claude": "Claude Code",
    "cursor": "Cursor",
    "codex": "Codex",
    "copilot": "GitHub Copilot CLI",
    "dsh": "DeepSeek Harness",
    "opencode": "opencode",
    "gemini": "Gemini CLI",
    "cline": "Cline",
    "warp": "Warp Terminal",
    "claude_desktop": "Claude Desktop",
}


def capture_worker(destination: Path, history_days: int) -> int:
    """Only this subprocess imports parsers. Its stdout is not the native IPC channel."""
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        with contextlib.redirect_stdout(sys.stderr):
            from adr_sensor.observer import AgentObserver

            logging.getLogger("adr_sensor").setLevel(logging.CRITICAL)
            observer = AgentObserver(output_dir=destination, max_age_days=history_days)
            entries, _ = observer.ingest_all()
            diagnostics = observer.get_diagnostic_records()
        with (destination / "sessions.jsonl").open("w", encoding="utf-8") as handle:
            for entry in entries:
                handle.write(json.dumps(entry.to_dict(), ensure_ascii=False, allow_nan=False) + "\n")
        atomic_json(destination / "result.json", {"ok": True, "diagnostics": diagnostics})
        return 0
    except Exception:
        atomic_json(destination / "result.json", {"ok": False, "error": "Sensor worker failed"})
        return 1


def inventory_worker(destination: Path) -> int:
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        with contextlib.redirect_stdout(sys.stderr):
            from importlib.resources import files

            from adr_discovery.catalog.load import loads
            from adr_discovery.coverage.ledger import Ledger
            from adr_discovery.judge import Policy
            from adr_discovery.pipeline import discover
            from adr_discovery.reporter import to_json
            from adr_discovery.world.budget import Budget
            from adr_discovery.world.gate import Gate
            from adr_discovery.world.platform import for_host

            catalog = loads(files("adr_discovery.catalog").joinpath("catalog.json").read_text())
            gate = Gate(
                root="/",
                ledger=Ledger(),
                budget=Budget(max_entries=15000, reserved_walk_entries=3000, max_seconds=20),
                providers=for_host(),
                env={"HOME": str(Path.home()), "PATH": os.environ.get("PATH", "")},
            )
            snapshot = discover(gate, catalog, Policy(), timestamp=utcnow())
            result = strict_json(to_json(snapshot))
        atomic_json(destination / "inventory.json", result)
        return 0
    except Exception:
        atomic_json(destination / "result.json", {"ok": False, "error": "Inventory worker failed"})
        return 1


class Collector:
    def __init__(self, store, state_dir: Path):
        self.store = store
        self.state_dir = state_dir
        self.stop_event = threading.Event()
        self.wake = threading.Event()
        self.status_lock = threading.Lock()
        self.capture_lock = threading.Lock()
        self.inventory_lock = threading.Lock()
        self.process_lock = threading.Lock()
        self.processes: set[subprocess.Popen] = set()
        self.state = {
            "phase": "idle",
            "last_scan": None,
            "last_success": None,
            "error": None,
            "diagnostics": [],
            "new_snapshots": 0,
            "inventory_phase": "idle",
        }
        self.thread = threading.Thread(target=self._loop, daemon=True, name="adr-collection")

    def start(self):
        self.thread.start()

    def status(self):
        with self.status_lock:
            return {**self.state, "recording": self.store.settings()["recording"]}

    def _set(self, **changes):
        with self.status_lock:
            self.state.update(changes)

    def _worker(self, arguments: list[str], timeout: int):
        process = subprocess.Popen(
            [*command_prefix(), *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=self.state_dir,
        )
        with self.process_lock:
            self.processes.add(process)
        try:
            return process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
            raise RuntimeError("Collection timed out; existing history was preserved") from None
        finally:
            with self.process_lock:
                self.processes.discard(process)

    def _loop(self):
        while not self.stop_event.is_set():
            settings = self.store.settings()
            if settings["recording"]:
                self.scan()
            self.wake.wait(settings["interval_seconds"])
            self.wake.clear()

    def scan(self):
        if not self.capture_lock.acquire(blocking=False):
            return
        self._set(phase="collecting", error=None, last_scan=utcnow())
        try:
            staging = self.state_dir / "staging"
            staging.mkdir(exist_ok=True, mode=0o700)
            with tempfile.TemporaryDirectory(prefix="sensor-", dir=staging) as folder:
                target = Path(folder)
                code = self._worker(
                    [
                        "capture",
                        "--destination",
                        str(target),
                        "--history-days",
                        str(self.store.settings()["history_days"]),
                    ],
                    timeout=90,
                )
                result = strict_json((target / "result.json").read_bytes())
                if code != 0 or not result.get("ok"):
                    raise RuntimeError("Sensor capture failed; no existing data was removed")
                changed = 0
                refused = 0
                with (target / "sessions.jsonl").open("rb") as handle:
                    while line := handle.readline(MAX_JSON_BYTES + 1):
                        if len(line) > MAX_JSON_BYTES:
                            while line and not line.endswith(b"\n"):
                                line = handle.readline(MAX_JSON_BYTES + 1)
                            refused += 1
                            continue
                        if not self.store.settings()["recording"] or self.stop_event.is_set():
                            break
                        try:
                            changed += int(self.store.ingest(strict_json(line)))
                        except (ValueError, TypeError, RecursionError):
                            refused += 1
                diagnostics = result.get("diagnostics", [])
                partial = refused or any(item.get("status") in ("failed", "partial") for item in diagnostics)
                self._set(
                    phase="partial" if partial else "ready",
                    error=f"{refused} sessions exceeded limits or could not be stored" if refused else None,
                    diagnostics=diagnostics,
                    new_snapshots=changed,
                    last_success=utcnow(),
                )
        except Exception as error:
            if not self.store.settings()["recording"]:
                self._set(phase="paused", error=None)
            else:
                self._set(
                    phase="error",
                    error=str(error) if isinstance(error, RuntimeError) else "Collection failed",
                )
        finally:
            self.capture_lock.release()

    def scan_inventory(self):
        if not self.inventory_lock.acquire(blocking=False):
            return
        self._set(inventory_phase="scanning")
        try:
            staging = self.state_dir / "staging"
            staging.mkdir(exist_ok=True, mode=0o700)
            with tempfile.TemporaryDirectory(prefix="inventory-", dir=staging) as folder:
                target = Path(folder)
                code = self._worker(["capture-inventory", "--destination", str(target)], timeout=45)
                if code != 0:
                    raise RuntimeError("Inventory scan failed")
                snapshot = strict_json((target / "inventory.json").read_bytes())
                self.store.setting("inventory_snapshot", snapshot)
                self.store.setting("inventory_updated_at", utcnow())
            self._set(inventory_phase="ready")
        except Exception:
            self._set(inventory_phase="error")
        finally:
            self.inventory_lock.release()

    def pause(self):
        self.store.setting("recording", False)
        with self.process_lock:
            for process in tuple(self.processes):
                if process.poll() is None:
                    process.terminate()
        self._set(phase="paused")

    def resume(self):
        self.store.setting("recording", True)
        self.wake.set()

    def close(self):
        self.stop_event.set()
        self.wake.set()
        with self.process_lock:
            processes = tuple(self.processes)
        for process in processes:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
        if self.thread.is_alive():
            self.thread.join(timeout=5)
