"""Bounded FIFO admission for native hook approvals; waiting never grants access."""

import threading
import time
from collections import deque

APPROVAL_TIMEOUT_SECONDS = 90


class ApprovalQueue:
    def __init__(self, limit=8):
        self.limit = limit
        self._condition = threading.Condition()
        self._tickets = deque()
        self._closed = False

    def acquire(self, deadline):
        with self._condition:
            if self._closed:
                return None, "app_unavailable"
            if time.monotonic() >= deadline:
                return None, "approval_expired"
            if len(self._tickets) >= self.limit:
                return None, "approval_queue_full"
            ticket = object()
            self._tickets.append(ticket)
            while True:
                remaining = deadline - time.monotonic()
                if self._closed or remaining <= 0:
                    self._tickets.remove(ticket)
                    self._condition.notify_all()
                    return None, "app_unavailable" if self._closed else "approval_expired"
                if self._tickets[0] is ticket:
                    return ticket, None
                self._condition.wait(remaining)

    def release(self, ticket):
        with self._condition:
            if not self._tickets or self._tickets[0] is not ticket:
                raise RuntimeError("Only the active approval can release its place")
            self._tickets.popleft()
            self._condition.notify_all()

    @property
    def pending(self):
        with self._condition:
            return len(self._tickets)

    def close(self):
        with self._condition:
            self._closed = True
            self._condition.notify_all()
