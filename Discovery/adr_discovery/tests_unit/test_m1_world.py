"""M1 -- world access.

The assertion surface is the return shape itself: every access returns data
or a recorded reason. A test that only checks the happy path checks nothing
this module exists for, so each case asserts on both halves -- what came
back, and what was written to the ledger.
"""

from __future__ import annotations

import os

from adr_discovery.world.budget import Budget


def test_u1_01_symlink_escape_is_refused(world):
    world.dir("/proj").symlink("/proj/escape.json", "/etc/passwd", outside=True)
    gate = world.gate()

    result = gate.read_text("/proj/escape.json")

    assert not result.ok
    assert result.reason == "outside_root"
    assert any(d.reason == "outside_root" for d in gate.ledger.freeze().denied)


def test_u1_02_containment_is_decided_on_the_resolved_target(world):
    world.file("/proj/ok.json", "{}")
    gate = world.gate()

    assert not gate.read_text("/proj/../../../etc/hosts").ok


def test_u1_03_deny_list_follows_the_symlink(world):
    world.file("/home/a/Documents/diary.txt", "private")
    world.symlink("/home/a/notes", "/home/a/Documents")
    gate = world.gate()

    result = gate.read_text("/home/a/notes/diary.txt")

    assert not result.ok and result.reason == "personal_path"


def test_u1_04_a_swap_between_check_and_open_is_refused(world):
    world.file("/race/target", "real")
    gate = world.gate()

    def swap(resolved: str) -> None:
        if resolved.endswith("/target"):
            os.remove(resolved)
            os.symlink("/etc/hosts", resolved)

    gate.on_validated = swap
    result = gate.read_text("/race/target")

    assert not result.ok and result.reason == "swapped"


def test_u1_05_truncation_reports_the_true_size(world):
    world.file("/big.bin", "x" * 5000)
    gate = world.gate(budget=Budget(max_read_bytes=1000))

    result = gate.read_bytes("/big.bin")

    assert result.ok and len(result.value) == 1000
    (record,) = gate.ledger.freeze().truncated
    assert record.kept == 1000 and record.true_count == 5000


def test_u1_06_depth_cap_is_recorded_with_the_path(world):
    path = ""
    for i in range(10):
        path += f"/d{i}"
        world.dir(path)
    gate = world.gate(budget=Budget(max_depth=4))

    list(gate.walk("/d0"))
    boundaries = gate.ledger.freeze().boundaries_hit

    assert any(b.boundary == "depth" for b in boundaries)


def test_u1_07_denied_is_not_empty(world):
    world.dir("/locked").unreadable("/locked")
    gate = world.gate()

    result = gate.list_dir("/locked")

    assert not result.ok
    assert gate.ledger.freeze().denied, "an unreadable surface must be recorded, not silently empty"


def test_u1_07b_absent_is_distinct_from_denied(world):
    """A surface that does not exist was not refused.

    Recording it as a denial would drown the real refusals and make
    `coverage.is_complete` meaningless.
    """
    gate = world.gate()

    result = gate.list_dir("/nothing/here")

    assert not result.ok and result.reason == "absent"
    assert not gate.ledger.freeze().denied


def test_u1_08_subprocess_timeout_is_a_refusal_not_an_answer(world):
    world.file("/slow", "#!/bin/sh\nsleep 5\necho 1.2.3\n")
    os.chmod(world.root + "/slow", 0o755)
    gate = world.gate(budget=Budget(max_subprocess_seconds=0.2))

    result = gate.run(("/slow",))

    assert not result.ok and result.reason == "timeout"
    assert any(p.status == "failed" for p in gate.ledger.freeze().probes)


def test_u1_09_a_missing_provider_is_unavailable_not_empty(world):
    gate = world.gate()

    result = gate.packages()

    assert not result.ok
    assert [u.provider for u in gate.ledger.freeze().unavailable] == ["packages"]


def test_u1_10_the_exe_is_reported_not_the_name(world):
    """`ps comm=` truncates at fifteen characters; resolving that name
    against PATH attributes /opt/agents/claude to /usr/bin/claude."""
    world.exe("/usr/bin/claude", "wrong")
    world.surface("processes", [{"pid": 4021, "exe": "/opt/agents/claude-code-cli"}])
    gate = world.gate()

    (process,) = gate.processes().value

    assert process.exe == "/opt/agents/claude-code-cli"
