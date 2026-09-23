"""Hash-only acknowledgements for incremental OTLP session delivery."""

import hashlib
import json
import os
import re
import tempfile
from dataclasses import asdict
from pathlib import Path
from typing import Dict, List

from ..schemas.agent_event_schema import AgentEvent
from .config import OpenTelemetryConfig
from .opentelemetry import SCHEMA_VERSION, _validate_credential_provider

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class DeliveryCheckpointError(RuntimeError):
    """Raised when a successful export cannot be durably checkpointed."""


def _fingerprint(value: object) -> str:
    serialized = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


class DeliveryCheckpoint:
    """Remember delivered session snapshots separately from their local JSON files.

    Select pending entries before export, then call commit only after flush and
    shutdown succeed. Losing or corrupting this cache causes retries, never skips.
    """

    def __init__(self, output_dir: Path, config: OpenTelemetryConfig):
        _validate_credential_provider()
        destination = {
            "config": asdict(config),
            "schema_version": SCHEMA_VERSION,
            "checkpoint_version": 1,
        }
        if not config.headers:
            # The HTTP exporter falls back to these variables for empty headers.
            destination["environment_headers"] = os.environ.get(
                "OTEL_EXPORTER_OTLP_LOGS_HEADERS", os.environ.get("OTEL_EXPORTER_OTLP_HEADERS", "")
            )
        for setting in ("CLIENT_CERTIFICATE", "CLIENT_KEY"):
            destination[setting] = os.environ.get(
                f"OTEL_EXPORTER_OTLP_LOGS_{setting}", os.environ.get(f"OTEL_EXPORTER_OTLP_{setting}", "")
            )
        self.path = Path(output_dir) / f".adr-otel-delivery.{_fingerprint(destination)}.json"
        self.load_failed = False
        self._delivered = self._load()
        self._pending: Dict[str, str] = {}

    def _load(self) -> Dict[str, str]:
        try:
            with self.path.open(encoding="utf-8") as checkpoint_file:
                data = json.load(checkpoint_file)
            if not isinstance(data, dict) or not all(
                isinstance(key, str) and _DIGEST.fullmatch(key) and isinstance(value, str) and _DIGEST.fullmatch(value)
                for key, value in data.items()
            ):
                raise ValueError("invalid checkpoint fingerprints")
            return data
        except FileNotFoundError:
            return {}
        except (OSError, ValueError):
            self.load_failed = True
            return {}

    def pending_entries(self, entries: List[AgentEvent]) -> List[AgentEvent]:
        """Select snapshots not acknowledged for this destination, including results."""
        self._pending = {}
        pending_entries = []
        for entry in entries:
            identity = _fingerprint([entry.source, entry.session_id, entry.hostname, entry.username])
            payload = _fingerprint(entry.get_non_null_fields())
            if self._delivered.get(identity) != payload:
                pending_entries.append(entry)
                self._pending[identity] = payload
        return pending_entries

    def commit(self) -> None:
        """Atomically persist only the snapshots selected for a successful export."""
        if not self._pending:
            return
        temporary_path = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            # Merge recent acknowledgements; concurrent writers may cause extra
            # retries, but can never acknowledge a payload they have not exported.
            delivered = self._load()
            delivered.update(self._pending)
            fd, temporary_name = tempfile.mkstemp(prefix=f"{self.path.name}.", suffix=".tmp", dir=self.path.parent)
            temporary_path = Path(temporary_name)
            with os.fdopen(fd, "w", encoding="utf-8") as checkpoint_file:
                json.dump(delivered, checkpoint_file, sort_keys=True, separators=(",", ":"))
                checkpoint_file.flush()
                os.fsync(checkpoint_file.fileno())
            os.replace(temporary_path, self.path)
            temporary_path = None
            if os.name != "nt":
                directory_fd = os.open(self.path.parent, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            self._delivered = delivered
            self._pending = {}
        except OSError as exc:
            raise DeliveryCheckpointError(
                "could not save the OpenTelemetry delivery checkpoint; a later run may resend delivered sessions"
            ) from exc
        finally:
            if temporary_path is not None:
                try:
                    temporary_path.unlink()
                except OSError:
                    pass
