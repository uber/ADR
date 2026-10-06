import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from adr_desktop.approval_queue import ApprovalQueue
from adr_desktop.native import NativeTimedOut, NativeUnavailable


def wait_pending(queue, expected):
    deadline = time.monotonic() + 3
    while queue.pending != expected and time.monotonic() < deadline:
        time.sleep(0.005)
    assert queue.pending == expected


def test_approvals_wait_in_fifo_order_and_capacity_is_bounded():
    queue = ApprovalQueue(limit=3)
    first, failure = queue.acquire(time.monotonic() + 5)
    assert failure is None
    with ThreadPoolExecutor(max_workers=2) as pool:
        second = pool.submit(queue.acquire, time.monotonic() + 5)
        wait_pending(queue, 2)
        third = pool.submit(queue.acquire, time.monotonic() + 5)
        wait_pending(queue, 3)
        assert queue.acquire(time.monotonic() + 5) == (None, "approval_queue_full")
        assert not second.done() and not third.done()
        queue.release(first)
        second_ticket, failure = second.result(timeout=2)
        assert failure is None and not third.done()
        queue.release(second_ticket)
        third_ticket, failure = third.result(timeout=2)
        assert failure is None
        queue.release(third_ticket)
    assert queue.pending == 0


def test_expired_waiter_is_removed_without_granting_access():
    queue = ApprovalQueue()
    first, _ = queue.acquire(time.monotonic() + 5)
    with ThreadPoolExecutor() as pool:
        waiting = pool.submit(queue.acquire, time.monotonic() + 0.05)
        assert waiting.result(timeout=2) == (None, "approval_expired")
    assert queue.pending == 1
    queue.release(first)
    assert queue.pending == 0


def test_shutdown_wakes_waiters_and_never_grants_access():
    queue = ApprovalQueue()
    first, _ = queue.acquire(time.monotonic() + 5)
    with ThreadPoolExecutor() as pool:
        waiting = pool.submit(queue.acquire, time.monotonic() + 5)
        wait_pending(queue, 2)
        queue.close()
        assert waiting.result(timeout=2) == (None, "app_unavailable")
    queue.release(first)
    assert queue.acquire(time.monotonic() + 5) == (None, "app_unavailable")


def request_approval(client, runtime, name="example"):
    return client.post(
        "/api/hooks/approve",
        headers={"Authorization": "Bearer " + runtime.hook_token},
        json={
            "harness": "codex",
            "event": {
                "tool_name": "Read",
                "tool_input": {"file_path": f"/example/protected/{name}"},
                "cwd": "/example/workspace",
            },
        },
    ).json()


def ask_rule(runtime):
    runtime.change_policy(add={"path": "/example/protected", "kind": "directory", "action": "ask"})


@pytest.mark.parametrize("block_while_queued", [False, True])
def test_concurrent_file_approvals_queue_and_recheck_policy(
    client, runtime, monkeypatch, block_while_queued
):
    ask_rule(runtime)
    entered = threading.Event()
    release = threading.Event()
    seen = []

    def native(_operation, arguments, timeout=30):
        seen.append(arguments)
        assert 0 < timeout <= 90
        assert arguments["expires_at"] > time.time()
        if len(seen) == 1:
            entered.set()
            assert release.wait(3)
        return {"allowed": True}

    monkeypatch.setattr(runtime.native, "call", native)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(request_approval, client, runtime, "first")
        assert entered.wait(3)
        second = pool.submit(request_approval, client, runtime, "second")
        try:
            wait_pending(runtime.hook_approvals, 2)
            assert not second.done()
            if block_while_queued:
                runtime.change_policy(
                    add={"path": "/example/protected/second", "kind": "file", "action": "block"}
                )
        finally:
            release.set()
        assert first.result(timeout=3) == {"allowed": True, "reason_code": "approved"}
        result = second.result(timeout=3)
    assert result == (
        {"allowed": False, "reason_code": "protected_path"} if block_while_queued
        else {"allowed": True, "reason_code": "approved"}
    )
    assert len(seen) == (1 if block_while_queued else 2)
    assert runtime.hook_approvals.pending == 0


def test_expired_queued_request_never_opens_a_dialog(client, runtime, monkeypatch):
    ask_rule(runtime)
    monkeypatch.setattr("adr_desktop.api.APPROVAL_TIMEOUT_SECONDS", 0.08)
    first, _ = runtime.hook_approvals.acquire(time.monotonic() + 5)
    try:
        assert request_approval(client, runtime) == {
            "allowed": False, "reason_code": "approval_expired"
        }
        assert runtime.native.calls == []
    finally:
        runtime.hook_approvals.release(first)


def test_full_queue_returns_its_real_reason(client, runtime):
    ask_rule(runtime)
    runtime.hook_approvals = ApprovalQueue(limit=1)
    first, _ = runtime.hook_approvals.acquire(time.monotonic() + 5)
    try:
        assert request_approval(client, runtime) == {
            "allowed": False, "reason_code": "approval_queue_full"
        }
        assert runtime.native.calls == []
    finally:
        runtime.hook_approvals.release(first)


@pytest.mark.parametrize(
    "failure,reason", [(NativeTimedOut, "approval_expired"), (NativeUnavailable, "app_unavailable")]
)
def test_native_failure_does_not_strand_the_queue(client, runtime, monkeypatch, failure, reason):
    ask_rule(runtime)

    def native(*_args, **_kwargs):
        raise failure("synthetic")

    monkeypatch.setattr(runtime.native, "call", native)
    assert request_approval(client, runtime) == {"allowed": False, "reason_code": reason}
    assert runtime.hook_approvals.pending == 0


def test_late_native_allow_cannot_outlive_request_deadline(client, runtime, monkeypatch):
    ask_rule(runtime)
    monkeypatch.setattr("adr_desktop.api.APPROVAL_TIMEOUT_SECONDS", 0.02)

    def native(*_args, **_kwargs):
        time.sleep(0.04)
        return {"allowed": True}

    monkeypatch.setattr(runtime.native, "call", native)
    assert request_approval(client, runtime) == {"allowed": False, "reason_code": "approval_expired"}
    assert runtime.hook_approvals.pending == 0


def test_unrelated_tool_never_opens_a_native_dialog(client, runtime):
    ask_rule(runtime)
    response = client.post(
        "/api/hooks/approve",
        headers={"Authorization": "Bearer " + runtime.hook_token},
        json={
            "harness": "codex",
            "event": {
                "tool_name": "Bash",
                "tool_input": {"command": "git status"},
                "cwd": "/example/workspace",
            },
        },
    )
    assert response.json()["allowed"] is True
    assert runtime.native.calls == []
