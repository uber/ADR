"""Private parent/child IPC. Vault secrets are never returned by this protocol."""

import json
import sys
import threading
import uuid
from concurrent.futures import Future, TimeoutError


class NativeUnavailable(RuntimeError):
    pass


class NativeTimedOut(NativeUnavailable):
    pass


class NativeBridge:
    def __init__(self, enabled=False):
        self.enabled = enabled
        self.connected = enabled
        self.pending: dict[str, Future] = {}
        self.lock = threading.Lock()
        self.write_lock = threading.Lock()
        self.on_disconnect = None
        if enabled:
            threading.Thread(target=self._read, daemon=True, name="adr-native-bridge").start()

    def emit(self, message: dict):
        with self.write_lock:
            print(json.dumps(message, allow_nan=False), flush=True)

    def _read(self):
        try:
            for line in sys.stdin:
                if len(line) > 2 * 1024 * 1024:
                    continue
                try:
                    message = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(message, dict) or message.get("type") != "native_response":
                    continue
                with self.lock:
                    future = self.pending.pop(message.get("id"), None)
                if future is not None and not future.done():
                    future.set_result(message)
        finally:
            self.connected = False
            with self.lock:
                for future in self.pending.values():
                    if not future.done():
                        future.set_exception(NativeUnavailable("The menu-bar app disconnected"))
                self.pending.clear()
            if self.on_disconnect:
                self.on_disconnect()

    def call(self, operation: str, arguments: dict | None = None, timeout=30):
        if not self.connected:
            raise NativeUnavailable("This operation requires the macOS menu-bar app")
        identifier = uuid.uuid4().hex
        future: Future = Future()
        with self.lock:
            self.pending[identifier] = future
        self.emit(
            {
                "type": "native_request",
                "id": identifier,
                "operation": operation,
                "arguments": arguments or {},
            }
        )
        try:
            response = future.result(timeout=timeout)
        except TimeoutError:
            raise NativeTimedOut("The native operation timed out") from None
        finally:
            with self.lock:
                self.pending.pop(identifier, None)
        if not response.get("ok"):
            # Native error messages are closed, content-free codes.
            raise NativeUnavailable(str(response.get("error") or "Native operation failed"))
        return response.get("result") or {}
