"""Windows inventory is sampled once per Gate and refreshed for each scan.

The helper boundary supplies JSON inventory rows here; no PowerShell or
host inventory is executed, so these cases also protect non-Windows CI.
"""

from __future__ import annotations

import json

import pytest

from adr_discovery import pipeline
from adr_discovery.enumerator.sources.network import from_network
from adr_discovery.enumerator.sources.registries import from_applications, from_kernel, from_packages
from adr_discovery.world.gate import Gate, Ok, Ran, Refused
from adr_discovery.world.platform import windows
from adr_discovery.world.platform.windows import WindowsProviders


def _application(version="1"):
    return {"Id": "test-agent", "Name": "Test Agent", "Version": version, "Path": r"C:\Tools\Agent"}


def _socket(port=11434):
    return {"State": "Listen", "LocalPort": port, "OwningProcess": 42}


class _Helpers:
    def __init__(self, **responses):
        self.responses = responses
        self.calls = []

    def __call__(self, argv):
        script = argv[-1]
        if "Get-CimInstance" in script:
            surface = "processes"
        elif "Get-NetTCPConnection" in script:
            surface = "sockets"
        elif "Get-AppxPackage" in script:
            surface = "applications"
        else:
            raise AssertionError(f"unexpected inventory helper: {argv!r}")
        self.calls.append(surface)
        response = self.responses[surface]
        if isinstance(response, (Ok, Refused)):
            return response
        sources = getattr(windows, "_APPLICATION_SOURCES", ())
        if surface == "applications" and sources:
            response = [{"Source": source, "Ok": True, "Rows": response if index == 0 else []}
                        for index, source in enumerate(sources)]
        return Ok(Ran(tuple(argv), 0, json.dumps(response)))


def _gate(tmp_path, monkeypatch, helpers, providers=None):
    # Keep these lifecycle checks independent of how the provider locates
    # its native helper; all helper execution is replaced by _Helpers.
    monkeypatch.setattr(windows, "powershell_path", lambda: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                        raising=False)
    gate = Gate(str(tmp_path), providers=providers or WindowsProviders())
    monkeypatch.setattr(gate, "run_helper", helpers)
    return gate


def test_packages_applications_and_ownership_share_one_inventory(tmp_path, monkeypatch):
    helpers = _Helpers(applications=[_application()])
    gate = _gate(tmp_path, monkeypatch, helpers)

    packages = from_packages(gate)
    applications = from_applications(gate)
    owners = [gate.package_owner(r"C:\Tools\Agent" + "\\" + name) for name in ("agent.exe", "worker.exe")]

    assert helpers.calls == ["applications"]
    assert packages[0].detail["name"] == "test-agent"
    assert applications[0].detail["ident"] == "test-agent"
    assert all(owner.ok and owner.value.name == "test-agent" for owner in owners)
    assert {("packages", "ran"), ("applications", "ran")} <= {
        (probe.name, probe.status) for probe in gate.ledger.freeze().probes
    }


def test_kernel_and_network_share_one_socket_inventory(tmp_path, monkeypatch):
    helpers = _Helpers(processes=[], sockets=[_socket()])
    gate = _gate(tmp_path, monkeypatch, helpers)
    monkeypatch.setattr(gate, "dns_cache", lambda: Ok(()))

    kernel = from_kernel(gate)
    network = from_network(gate, kernel)

    assert helpers.calls == ["processes", "sockets"]
    assert [(candidate.kind, candidate.detail["port"]) for candidate in kernel] == [
        ("listening_socket", 11434),
    ]
    assert [(candidate.kind, candidate.detail["port"]) for candidate in network] == [
        ("model_port", 11434),
    ]
    assert any(probe.name == "sockets" and probe.status == "ran" for probe in gate.ledger.freeze().probes)


@pytest.mark.parametrize("surface", ["applications", "sockets"])
@pytest.mark.parametrize(
    "response",
    [[], Refused("spawn_failed", "helper unavailable"), Ok(Ran((), 1, "")), Ok(Ran((), 0, "invalid JSON"))],
    ids=["empty", "spawn-failure", "helper-failure", "invalid-json"],
)
def test_empty_and_failed_queries_are_cached_with_their_coverage(tmp_path, monkeypatch, surface, response):
    helpers = _Helpers(**{surface: response})
    gate = _gate(tmp_path, monkeypatch, helpers)
    query = getattr(gate, surface)

    first = query()
    assert query() is first
    assert query() is first
    assert helpers.calls == [surface]
    coverage = gate.ledger.freeze()
    if response == []:
        assert first.ok and first.value == ()
        assert not any(entry.provider == surface for entry in coverage.unavailable)
    else:
        assert not first.ok
        assert [entry.provider for entry in coverage.unavailable if entry.provider == surface] == [surface]
    if isinstance(response, Ok) and response.value.stdout == "invalid JSON":
        assert any(probe.name == surface and probe.status == "degraded" for probe in coverage.probes) or any(
            entry.provider == surface and "JSON" in entry.reason for entry in coverage.unavailable
        )


@pytest.mark.parametrize("surface", ["applications", "sockets"])
@pytest.mark.parametrize("first_fails", [False, True], ids=["success", "failure"])
def test_shared_provider_keeps_gate_results_and_ledgers_separate(tmp_path, monkeypatch, surface, first_fails):
    providers = WindowsProviders()
    rows = [_application("1")] if surface == "applications" else [_socket(11434)]
    changed = [_application("2")] if surface == "applications" else [_socket(11435)]
    first_helpers = _Helpers(**{surface: Refused("spawn_failed") if first_fails else rows})
    second_helpers = _Helpers(**{surface: changed})
    first_gate = _gate(tmp_path, monkeypatch, first_helpers, providers)
    second_gate = _gate(tmp_path, monkeypatch, second_helpers, providers)

    first = getattr(first_gate, surface)()
    second = getattr(second_gate, surface)()

    assert first != second
    assert second.ok
    assert getattr(first_gate, surface)() is first
    assert getattr(second_gate, surface)() is second
    assert first_helpers.calls == second_helpers.calls == [surface]
    assert not any(entry.provider == surface for entry in second_gate.ledger.freeze().unavailable)
    assert any(entry.provider == surface for entry in first_gate.ledger.freeze().unavailable) == first_fails


def test_discover_refreshes_failed_and_empty_snapshots_on_a_reused_gate(tmp_path, monkeypatch):
    helpers = _Helpers(applications=Refused("spawn_failed"), sockets=[])
    gate = _gate(tmp_path, monkeypatch, helpers)
    observed = []

    def enumerate_inventory(current_gate):
        applications = current_gate.applications()
        sockets = current_gate.sockets()
        observed.append((applications, sockets))
        assert current_gate.applications() is applications
        assert current_gate.sockets() is sockets
        return ()

    # Keep this lifecycle regression at the pipeline/provider seam rather
    # than depending on unrelated Windows filesystem support.
    monkeypatch.setattr(pipeline, "enumerate_candidates", enumerate_inventory)
    monkeypatch.setattr(pipeline, "homes", lambda current_gate: ())

    first = pipeline.discover(gate)
    helpers.responses.update(applications=[_application("2")], sockets=[_socket(11435)])
    pipeline.discover(gate)
    helpers.responses.update(applications=[_application("3")], sockets=[_socket(11436)])
    pipeline.discover(gate)

    assert helpers.calls == ["applications", "sockets"] * 3
    assert not observed[0][0].ok
    assert observed[0][1].value == ()
    assert observed[1][0].value[0].version == "2"
    assert observed[1][1].value[0].local_port == 11435
    assert observed[2][0].value[0].version == "3"
    assert observed[2][1].value[0].local_port == 11436
    assert [entry.provider for entry in first.coverage.unavailable if entry.provider == "applications"] == ["applications"]
