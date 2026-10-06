"""Permission guidance is evidence-based and does not require host probes."""

from __future__ import annotations

import errno
import json
import os

import pytest

from adr_discovery.contracts.snapshot import (
    BoundaryHit,
    Coverage,
    Denied,
    ProbeRun,
    Skipped,
    Snapshot,
    Unavailable,
)
from adr_discovery.coverage.ledger import Ledger
from adr_discovery.coverage.reasons import classify_denial
from adr_discovery.coverage.report import location_root, summarize_coverage
from adr_discovery.enumerator.roots import ordered_roots
from adr_discovery.reporter.delta import diff
from adr_discovery.reporter.snapshot import from_dict, stats, to_json
from adr_discovery.world.budget import Budget
from adr_discovery.world.platform.darwin import DarwinProviders


@pytest.mark.parametrize(("number", "section", "category"), [
    (errno.EACCES, "access", "filesystem_permissions"),
    (errno.EPERM, "access", "os_privacy_or_policy"),
    (errno.ENOENT, "skipped", "missing"),
    (errno.ENOTDIR, "skipped", "not_directory"),
    (errno.ELOOP, "skipped", "symlink_safety"),
    (errno.EIO, "skipped", "io_error"),
    (errno.EMFILE, "skipped", "io_error"),
])
def test_errno_classification_does_not_depend_on_localised_error_text(number, section, category):
    assert classify_denial("unfamiliar or localised OS message", number) == (section, category)


def test_eperm_never_claims_that_full_disk_access_is_missing():
    assert classify_denial("Operation not permitted", errno.EPERM) == ("access", "os_privacy_or_policy")
    assert classify_denial("unfamiliar denial") == ("access", "unclassified_access")


def test_repeated_denials_keep_occurrences_operations_and_different_reasons():
    ledger = Ledger()
    for _ in range(4):
        ledger.deny("/app/data", "Permission denied", errno=errno.EACCES, operation="stat")
    ledger.deny("/app/data", "Permission denied", errno=errno.EACCES, operation="list_directory")
    ledger.deny("/app/data", "Operation not permitted", errno=errno.EPERM, operation="read")
    ledger.deny("/app/other", "Permission denied", errno=errno.EACCES, operation="read")
    coverage = ledger.freeze()
    assert len(coverage.denied) == 3
    assert coverage.denied[0].occurrences == 5
    assert coverage.denied[0].operations == ("stat", "list_directory")
    summary = summarize_coverage(coverage)["access"]
    assert summary["path_count"] == 2
    assert summary["diagnostic_count"] == 3
    assert summary["occurrences"] == 7
    assert summary["categories"] == ["filesystem_permissions", "os_privacy_or_policy"]
    assert summary["category_counts"]["filesystem_permissions"] == {
        "path_count": 2, "diagnostic_count": 2, "occurrences": 6,
    }
    assert summary["category_counts"]["os_privacy_or_policy"]["path_count"] == 1


@pytest.mark.parametrize("reason", [
    "personal_path", "outside_root", "target swapped after validation", "Not a directory",
])
def test_legacy_nonpermission_deny_calls_are_still_recorded_separately(reason):
    ledger = Ledger()
    ledger.deny("/example", reason)
    coverage = ledger.freeze()
    assert not coverage.denied
    assert len(coverage.skipped) == 1
    assert coverage.skipped[0].detail == reason
    assert not coverage.is_complete


def test_skip_deduplication_does_not_drop_reason_detail():
    ledger = Ledger()
    ledger.skip("/example", "changed_path", "first observation", operation="stat")
    ledger.skip("/example", "changed_path", "first observation", operation="read")
    ledger.skip("/example", "changed_path", "different observation", operation="read")
    first, second = ledger.freeze().skipped
    assert first.occurrences == 2
    assert first.operations == ("stat", "read")
    assert second.detail == "different observation"


@pytest.mark.parametrize("operation", ["read_bytes", "stat", "list_dir"])
@pytest.mark.parametrize("number", [errno.EPERM, errno.EACCES, errno.EIO, errno.ENOTDIR])
def test_gate_records_os_error_number_and_kind(world, monkeypatch, operation, number):
    world.dir("/unreadable")
    gate = world.gate()
    real_open, real_stat = os.open, os.stat

    def fail_open(path, *args, **kwargs):
        if path == world.root + "/unreadable":
            raise OSError(number, os.strerror(number))
        return real_open(path, *args, **kwargs)

    def fail_stat(path, *args, **kwargs):
        if path == world.root + "/unreadable":
            raise OSError(number, os.strerror(number))
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", fail_open)
    if operation == "stat":
        monkeypatch.setattr(os, "stat", fail_stat)
    result = getattr(gate, operation)("/unreadable")
    assert not result.ok and result.errno == number
    coverage = gate.ledger.freeze()
    if number in (errno.EPERM, errno.EACCES):
        assert len(coverage.denied) == 1 and not coverage.skipped
        assert coverage.denied[0].errno == number
    else:
        assert not coverage.denied and len(coverage.skipped) == 1
        assert coverage.skipped[0].errno == number


def test_os_read_failure_is_recorded_and_closes_the_descriptor(world, monkeypatch):
    world.file("/config", "{}")
    gate = world.gate()
    descriptors = []

    def fail_read(fd, size):
        descriptors.append(fd)
        raise PermissionError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(os, "read", fail_read)
    result = gate.read_bytes("/config")
    assert not result.ok and result.reason == "read_failed"
    assert gate.ledger.freeze().denied[0].operations == ("read",)
    with pytest.raises(OSError, match="Bad file descriptor"):
        os.fstat(descriptors[0])


def test_entry_metadata_failure_is_not_silently_dropped(world, monkeypatch):
    world.dir("/example")
    gate = world.gate()

    class Entry:
        name = "unreadable"

        def stat(self, **kwargs):
            raise PermissionError(errno.EACCES, "Permission denied")

    class Listing:
        def __enter__(self):
            return iter((Entry(),))

        def __exit__(self, *args):
            pass

    monkeypatch.setattr(os, "scandir", lambda fd: Listing())
    result = gate.list_dir("/example")
    assert result.ok and not result.value
    (denial,) = gate.ledger.freeze().denied
    assert denial.path == "/example/unreadable"
    assert denial.errno == errno.EACCES
    assert denial.operations == ("stat_entry",)


def test_absent_optional_file_is_not_a_denial_and_missing_root_is_named(world):
    gate = world.gate()
    assert gate.read_text("/missing/config.json").reason == "absent"
    assert not gate.ledger.freeze().skipped
    assert list(gate.walk("/missing")) == []
    coverage = gate.ledger.freeze()
    assert not coverage.denied and not coverage.roots_swept
    assert coverage.skipped[0].path == "/missing"
    assert coverage.skipped[0].reason == "missing"
    assert coverage.is_complete  # A proven-absent optional root is not blocked data.


def test_file_in_place_of_directory_is_not_a_permission_prompt(world):
    world.file("/root-is-file", "synthetic")
    gate = world.gate()
    assert list(gate.walk("/root-is-file")) == []
    coverage = gate.ledger.freeze()
    assert not coverage.denied and not coverage.roots_swept
    assert coverage.skipped[0].reason == "not_directory"
    assert not coverage.is_complete


def test_denied_root_is_not_reported_as_swept(world, monkeypatch):
    world.dir("/blocked")
    gate = world.gate()

    def deny_open(*args, **kwargs):
        raise PermissionError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(os, "open", deny_open)
    assert list(gate.walk("/blocked")) == []
    assert not gate.ledger.freeze().roots_swept
    assert gate.ledger.freeze().denied[0].path == "/blocked"


def test_budget_stopping_before_a_root_is_opened_does_not_report_it_swept(world):
    gate = world.gate(budget=Budget(max_entries=0))
    assert list(gate.walk("/never-opened")) == []
    assert not gate.ledger.freeze().roots_swept
    assert gate.ledger.freeze().boundaries_hit[0].boundary == "budget_exhausted"


def test_empty_readable_root_is_still_reported_as_swept(world):
    world.dir("/empty")
    gate = world.gate()
    assert list(gate.walk("/empty")) == []
    (root,) = gate.ledger.freeze().roots_swept
    assert root.path == "/empty" and root.entries == 0


def test_walk_reports_symlinks_without_following_them(world):
    world.file("/target/child", "synthetic").dir("/links").symlink("/links/alias", "/target")
    gate = world.gate()
    assert [item.path for item in gate.walk("/links")] == ["/links/alias"]
    (skip,) = gate.ledger.freeze().skipped
    assert skip.reason == "symlink_not_followed" and skip.path == "/links/alias"
    assert not gate.ledger.freeze().denied
    # Targeted, validated metadata reads still work; no new grant or scope.
    assert gate.stat("/links/alias").ok


def test_privacy_policy_stays_enforced_without_becoming_a_permission_issue(world):
    world.file("/Users/example/Documents/config.json", "{}")
    gate = world.gate()
    result = gate.read_text("/Users/example/Documents/config.json")
    assert result.reason == "personal_path"
    assert not gate.ledger.freeze().denied
    assert gate.ledger.freeze().skipped[0].reason == "personal_path"
    assert not gate.ledger.freeze().is_complete


def test_darwin_sweep_does_not_reintroduce_the_autofs_home_root(world):
    world.dir("/Users/example")
    gate = world.gate(providers=DarwinProviders())
    roots = [path for path, _ in ordered_roots(gate)]
    assert "/Users" in roots
    assert "/home" not in roots
    assert any(
        item.path == "/home" and item.reason == "platform_root"
        for item in gate.ledger.freeze().skipped
    )


@pytest.mark.parametrize(("path", "root"), [
    ("/Users/example/.codex/plugins/cache/one", "/Users/example/.codex"),
    ("/Users/example/.config/example/data", "/Users/example/.config/example"),
    ("/Users/example/Library/Application Support/Example/child", "/Users/example/Library/Application Support/Example"),
    ("/Users/example/Library/Containers/example.app-id/Data", "/Users/example/Library/Containers/example.app-id"),
    ("/Users/example/Library/Group Containers/group.example/Data", "/Users/example/Library/Group Containers/group.example"),
    ("/Library/Application Support/Example/child", "/Library/Application Support/Example"),
    ("/Applications/Example.app/Contents/Info.plist", "/Applications/Example.app"),
    ("/var/root/.config/example/child", "/var/root/.config/example"),
    ("/home/example/.tool/file", "/home/example/.tool"),
    ("/Volumes/Example/child", "/Volumes/Example"),
    (r"C:\Users\example\AppData\Local\Example\file", "C:/Users/example/AppData/Local/Example"),
    ("", "(unknown location)"),
])
def test_location_grouping_is_lexical_and_app_or_root_specific(path, root):
    assert location_root(path) == root


def test_large_number_of_paths_is_grouped_not_hidden():
    prefix = "/Users/example/Library/Application Support/Example"
    coverage = Coverage(denied=tuple(
        Denied(f"{prefix}/child-{number}", "Operation not permitted", errno.EPERM)
        for number in range(106)
    ))
    report = summarize_coverage(coverage, details_per_group=5)["access"]
    assert report["path_count"] == 106 and report["group_count"] == 1
    assert report["occurrences"] == 106
    assert report["groups"][0]["root"] == prefix
    assert report["groups"][0]["omitted_details"] == 101
    assert len(report["groups"][0]["details"]) == 5
    assert len(coverage.denied) == 106


def test_legacy_snapshot_duplicates_and_nonpermission_reasons_are_readable_without_rescanning():
    snapshot = from_dict({"coverage": {"denied": [
        {"path": "/Users/example/.tool/data", "reason": "Permission denied"},
        {"path": "/Users/example/.tool/data", "reason": "Permission denied"},
        {"path": "/Users/example/Documents", "reason": "personal_path"},
        {"path": "/outside", "reason": "outside_root"},
        {"path": "/not-dir", "reason": "Not a directory"},
        {"path": "/unknown", "reason": "an unfamiliar old denial"},
    ]}})
    report = summarize_coverage(snapshot.coverage)
    assert report["access"]["path_count"] == 2
    assert report["access"]["occurrences"] == 3
    assert "unclassified_access" in report["access"]["categories"]
    assert report["skipped"]["path_count"] == 3
    assert len(snapshot.coverage.denied) == 6, "the raw legacy evidence remains available"


def test_scanner_limits_optional_sources_and_policy_skips_remain_separate():
    coverage = Coverage(
        boundaries_hit=(
            BoundaryHit("/cache", "scope_excluded", "cache"),
            BoundaryHit("/wide", "budget_exhausted", "entry limit"),
            BoundaryHit("/deep", "depth", "depth limit"),
        ),
        unavailable=(Unavailable("dns_cache", "not enumerable"),),
        probes=(ProbeRun("parser", "degraded", "not parsed"),),
        skipped=(Skipped("/not-installed", "missing"),),
    )
    report = summarize_coverage(coverage)
    assert report["access"]["path_count"] == 0
    assert report["skipped"]["path_count"] == 2
    assert report["limits"]["count"] == 2
    assert report["unavailable"]["count"] == 1
    assert report["failed_probes"]["count"] == 1


def test_unfamiliar_explicit_skip_remains_visible_without_inventing_a_permission_failure():
    coverage = Coverage(skipped=(Skipped("/example", "future_reason", "original explanation"),))
    report = summarize_coverage(coverage)
    assert report["access"]["path_count"] == 0
    assert report["skipped"]["categories"] == ["other_skip"]
    assert report["skipped"]["category_counts"]["other_skip"]["path_count"] == 1
    detail = report["skipped"]["groups"][0]["details"][0]
    assert detail["reason"] == "future_reason" and detail["detail"] == "original explanation"


def test_group_and_other_record_truncation_has_explicit_omission_counts():
    coverage = Coverage(
        denied=tuple(Denied(f"/Users/example/.app-{i}/file", "eacces") for i in range(4)),
        unavailable=tuple(Unavailable(f"provider-{i}", "absent") for i in range(4)),
    )
    report = summarize_coverage(coverage, group_limit=2, item_limit=1)
    assert report["access"]["group_count"] == 4
    assert report["access"]["omitted_groups"] == 2
    assert report["unavailable"]["count"] == 4
    assert report["unavailable"]["omitted"] == 3


@pytest.mark.parametrize("value", [0, -1, 101, 1.5, True, "20"])
def test_summary_bounds_are_validated(value):
    with pytest.raises(ValueError, match="bounded"):
        summarize_coverage(Coverage(), group_limit=value)


def test_new_evidence_survives_json_round_trip():
    ledger = Ledger()
    ledger.deny("/blocked", "Permission denied", errno=errno.EACCES, operation="stat")
    ledger.deny("/blocked", "Permission denied", errno=errno.EACCES, operation="read")
    ledger.skip("/private", "personal_path", "policy", operation="resolve")
    original = Snapshot("fixture", "example", "darwin", "", coverage=ledger.freeze())
    restored = from_dict(json.loads(to_json(original)))
    assert restored.coverage == original.coverage
    assert stats(restored)["coverage_gaps"] == 2
    assert restored.schema_version == "1.1"


def test_legacy_policy_reclassification_does_not_claim_the_location_became_readable():
    before = Snapshot("fixture", "example", "darwin", "", coverage=Coverage(
        denied=(Denied("/private", "personal_path"),),
    ), schema_version="1.0")
    after = Snapshot("fixture", "example", "darwin", "", coverage=Coverage(
        skipped=(Skipped("/private", "personal_path"),),
    ))
    assert diff(before, after).is_empty


def test_a_denial_not_reobserved_after_a_budget_stop_is_not_a_success_claim():
    before = Snapshot("fixture", "example", "darwin", "", coverage=Coverage(
        denied=(Denied("/blocked", "eacces"),),
    ))
    after = Snapshot("fixture", "example", "darwin", "", coverage=Coverage(
        boundaries_hit=(BoundaryHit("/", "budget_exhausted"),),
    ))
    assert diff(before, after).coverage_delta == ("access denial no longer observed: /blocked",)
