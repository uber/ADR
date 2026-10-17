"""Windows inventory parsing plus native helper checks on Windows CI only."""

from __future__ import annotations

import io
import json
import os
import sys
import threading
import time

import pytest

from adr_discovery.contracts.records import Candidate, Declaration, Kind, Verdict
from adr_discovery.enumerator.sources.network import from_network
from adr_discovery.pipeline import _observation_from, _observation_from_declaration
from adr_discovery.resolver import resolve
from adr_discovery.world import gate as gate_module
from adr_discovery.world.budget import Budget
from adr_discovery.world.gate import Gate, Ok, Ran, Refused, Stat
from adr_discovery.world.platform import windows, windows_system
from adr_discovery.world.platform.base import NullProviders

SOURCES = (
    "applications:machine", "applications:machine32", "applications:current_user", "applications:appx_current_user",
)
NATIVE = pytest.mark.skipif(os.name != "nt", reason="requires the Windows system PowerShell")


def _gate(tmp_path, monkeypatch, payload, *, code=0, refused=None):
    gate = Gate(str(tmp_path), providers=windows.WindowsProviders())
    calls = []

    def run(argv):
        calls.append(argv)
        return refused if refused is not None else Ok(Ran(tuple(argv), code, payload))

    monkeypatch.setattr(windows, "powershell_path", lambda: r"D:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
    monkeypatch.setattr(gate, "run_helper", run)
    return gate, calls


def _unavailable(gate):
    return {entry.provider: entry.reason for entry in gate.ledger.freeze().unavailable}


def _sources():
    return [{"Source": source, "Ok": True, "Rows": []} for source in SOURCES]


@pytest.mark.parametrize("payload", ["", " \r\n", "[]", "\ufeff[]", '{"Name":"one"}', '[{"Name":"one"},{"Name":"two"}]'])
def test_json_accepts_empty_singleton_array_and_bom(tmp_path, monkeypatch, payload):
    gate, calls = _gate(tmp_path, monkeypatch, payload)
    result = gate.providers._ps_json(gate, "test-query", "test_surface")
    assert result.ok
    assert len(calls) == 1
    assert "UTF8Encoding" in calls[0][-1]
    assert "$ErrorActionPreference='Stop'" in calls[0][-1]
    assert "-NoProfile" in calls[0]
    assert "$PSModuleAutoLoadingPreference='None'" in calls[0][-1]
    assert "Microsoft.PowerShell.Utility.psd1" in calls[0][-1]


@pytest.mark.parametrize("surface,module", [("processes", "CimCmdlets"), ("sockets", "NetTCPIP"), ("dns_cache", "DnsClient")])
def test_native_surface_imports_are_explicit_and_trusted(tmp_path, monkeypatch, surface, module):
    gate, calls = _gate(tmp_path, monkeypatch, "[]")
    result = gate.providers._ps_json(gate, "test-query", surface)
    assert result.ok
    assert f"$PSHOME+'\\Modules\\{module}\\{module}.psd1'" in calls[0][-1]
    assert "CimCmdlets.psd1" in calls[0][-1]


@pytest.mark.parametrize("payload", ["null", "42", '"text"', "[null,42]", "{invalid"])
def test_malformed_json_is_unavailable_not_empty(tmp_path, monkeypatch, payload):
    gate, _ = _gate(tmp_path, monkeypatch, payload)
    result = gate.providers._ps_json(gate, "test-query", "test_surface")
    assert not result.ok
    assert "test_surface" in _unavailable(gate)


def test_valid_records_survive_malformed_siblings(tmp_path, monkeypatch):
    gate, _ = _gate(tmp_path, monkeypatch, '[null,{"Name":"one"},false]')
    result = gate.providers._ps_json(gate, "test-query", "test_surface")
    assert result.ok and result.value == ({"Name": "one"},)
    assert "test_surface:records" in _unavailable(gate)


def test_json_exceeding_decoder_depth_is_unavailable(tmp_path, monkeypatch):
    gate, _ = _gate(tmp_path, monkeypatch, "[" * 2000 + "{}" + "]" * 2000)
    result = gate.providers._ps_json(gate, "test-query", "test_surface")
    assert not result.ok and "test_surface" in _unavailable(gate)


@pytest.mark.parametrize("reason", ["timeout", "pipe_timeout", "read_failed", "output_limit", "spawn_failed", "invalid_encoding"])
def test_helper_refusal_preserves_its_reason(tmp_path, monkeypatch, reason):
    gate, _ = _gate(tmp_path, monkeypatch, "", refused=Refused(reason, "private detail"))
    result = gate.dns_cache()
    assert not result.ok
    assert reason in _unavailable(gate)["dns_cache"]
    assert "private detail" not in str(gate.ledger.freeze())


def test_nonzero_exit_is_not_a_successful_empty_inventory(tmp_path, monkeypatch):
    gate, _ = _gate(tmp_path, monkeypatch, "[]", code=1)
    assert not gate.sockets().ok
    assert "code 1" in _unavailable(gate)["sockets"]


def test_missing_trusted_helper_does_not_fall_back_to_path(tmp_path, monkeypatch):
    gate, calls = _gate(tmp_path, monkeypatch, "[]")

    def unavailable():
        raise OSError("not available")

    monkeypatch.setattr(windows, "powershell_path", unavailable)
    assert not gate.processes().ok
    assert calls == []
    assert "processes" in _unavailable(gate)


def test_appx_failure_preserves_registry_records_and_scope(tmp_path, monkeypatch):
    sources = _sources()
    sources[0]["Rows"] = [{"Id": "agent-id", "Name": "测试 Agent", "Path": r"D:\工具\Agent"}]
    sources[-1] = {"Source": SOURCES[-1], "Ok": False, "Error": "UnauthorizedAccessException"}
    gate, _ = _gate(tmp_path, monkeypatch, json.dumps(sources))

    result = gate.applications()

    assert result.ok and len(result.value) == 1
    assert result.value[0].name == "测试 Agent"
    assert result.value[0].path == r"D:\工具\Agent"
    assert _unavailable(gate)[SOURCES[-1]] == "UnauthorizedAccessException"
    assert "applications:other_users" in _unavailable(gate)
    assert any(probe.name == SOURCES[0] and probe.status == "ran" for probe in gate.ledger.freeze().probes)


def test_all_application_sources_failing_is_unavailable(tmp_path, monkeypatch):
    sources = [{"Source": source, "Ok": False, "Error": "secret path and token"} for source in SOURCES]
    gate, _ = _gate(tmp_path, monkeypatch, json.dumps(sources))
    assert not gate.applications().ok
    assert set(SOURCES).issubset(_unavailable(gate))
    assert "applications" in _unavailable(gate)
    assert "secret path and token" not in str(gate.ledger.freeze())


def test_empty_application_sources_are_successful_and_missing_sources_are_reported(tmp_path, monkeypatch):
    sources = _sources()[:-1]
    gate, _ = _gate(tmp_path, monkeypatch, json.dumps(sources))
    result = gate.applications()
    assert result.ok and result.value == ()
    assert "missing" in _unavailable(gate)[SOURCES[-1]]
    assert all(source not in _unavailable(gate) for source in SOURCES[:-1])


def test_malformed_application_records_do_not_crash_or_remove_other_sources(tmp_path, monkeypatch):
    sources = _sources()
    sources[0]["Rows"] = None
    sources[1]["Rows"] = [None, {"Id": [], "Name": "bad"}, {"Id": "valid", "Name": "Good", "Path": {}}]
    sources.append({"Source": [], "Ok": True, "Rows": []})
    gate, _ = _gate(tmp_path, monkeypatch, json.dumps(sources))
    result = gate.applications()
    assert result.ok and [app.ident for app in result.value] == ["valid"]
    assert SOURCES[0] in _unavailable(gate)
    assert SOURCES[1] + ":records" in _unavailable(gate)
    assert "applications:records" in _unavailable(gate)


def test_socket_states_are_explicit_and_malformed_fields_are_reported(tmp_path, monkeypatch):
    rows = [
        {"State": "Listen", "LocalPort": 11434, "OwningProcess": 42},
        {"State": 5, "LocalPort": 1234, "RemotePort": 443, "RemoteAddress": "::1", "OwningProcess": 42},
        {"State": "2", "LocalPort": 1235, "OwningProcess": 42},
        {"State": "TimeWait"},
        {"State": [], "LocalPort": 80},
        {"State": "Listen", "LocalPort": 65536},
        {"State": "Listen", "LocalPort": 80, "OwningProcess": "invalid"},
    ]
    gate, calls = _gate(tmp_path, monkeypatch, json.dumps(rows))
    result = gate.sockets()
    assert result.ok and [row.state for row in result.value] == ["LISTEN", "ESTABLISHED", "LISTEN"]
    assert "[string]$_.State" in calls[0][-1]
    assert "sockets:records" in _unavailable(gate)


def test_process_visibility_and_unknown_owner_reach_the_asset(tmp_path, monkeypatch):
    rows = [
        {"ProcessId": 42, "ParentProcessId": 1, "ExecutablePath": r"D:\Agent\agent.exe", "CommandLine": "agent.exe"},
        {"ProcessId": 43, "ExecutablePath": None},
        {"ProcessId": "invalid", "ExecutablePath": r"D:\Agent\bad.exe"},
    ]
    gate, _ = _gate(tmp_path, monkeypatch, json.dumps(rows))
    (process,) = gate.processes().value
    monkeypatch.setattr(gate, "stat", lambda path: Refused("unreadable"))
    candidate = Candidate(kind="process", path=process.exe, source="kernel", detail={"user": process.user})
    observation = _observation_from(gate, candidate, Verdict("agent", Kind.CLI_AGENT))
    (asset,) = resolve((observation,))
    assert process.user == observation.owner == asset.owner == "unknown"
    assert {"process_paths", "process_owners", "processes:records"}.issubset(_unavailable(gate))


@pytest.mark.parametrize("install_root", [None, r"D:\Agent"])
def test_unknown_file_owner_is_not_replaced_with_system(tmp_path, monkeypatch, install_root):
    gate, _ = _gate(tmp_path, monkeypatch, "[]")
    path = r"D:\Agent"
    stat = Stat(path, path, "1:1", 0, 0o40755, 0, gate.providers.owner_of(0))
    monkeypatch.setattr(gate, "stat", lambda value: Ok(stat))
    candidate = Candidate(kind="application", path=path, source="app_registry")
    observation = _observation_from(gate, candidate, Verdict("agent", Kind.APP, install_root=install_root))
    (asset,) = resolve((observation,))
    assert stat.owner == observation.owner == asset.owner == "unknown"


@pytest.mark.parametrize("providers,expected", [(windows.WindowsProviders(), "unknown"), (NullProviders(), "system")])
def test_unattributed_assets_use_the_platform_fallback(tmp_path, monkeypatch, providers, expected):
    gate = Gate(str(tmp_path), providers=providers)
    monkeypatch.setattr(gate, "stat", lambda path: Refused("unreadable"))
    candidate = Candidate(kind="application", path=r"D:\Agent", source="app_registry")
    observation = _observation_from(gate, candidate, Verdict("agent", Kind.APP))
    declaration = Declaration(Kind.MCP_SERVER, "agent", r"D:\config.json")
    declared = _observation_from_declaration(candidate, declaration, gate)
    assert observation.owner == declared.owner == expected
    assert all(asset.owner == expected for asset in resolve((observation, declared)))


def test_dns_cache_is_deduplicated_and_never_resolves_names(tmp_path, monkeypatch):
    rows = [{"Entry": "API.ANTHROPIC.COM.", "Type": "A"}, {"Name": "api.anthropic.com", "Type": "AAAA"},
            {"Entry": "api.anthropic.com", "Type": "CNAME"}, {"Entry": []}]
    gate, calls = _gate(tmp_path, monkeypatch, json.dumps(rows))
    monkeypatch.setattr(gate, "sockets", lambda: Ok(()))

    def no_lookup(hostnames):
        raise AssertionError("reading the DNS cache must not perform a lookup")

    monkeypatch.setattr(gate, "resolve", no_lookup)
    candidates = from_network(gate)
    assert [candidate.path for candidate in candidates] == ["api.anthropic.com"]
    assert len(calls) == 1 and "Get-DnsClientCache" in calls[0][-1]
    assert "dns_cache:records" in _unavailable(gate)


def test_execution_history_is_explicitly_unavailable(tmp_path, monkeypatch):
    gate, calls = _gate(tmp_path, monkeypatch, "[]")
    result = gate.exec_journal()
    assert not result.ok and "collector" in result.detail
    assert calls == []


@pytest.mark.parametrize("wow64", [False, True])
def test_system_helpers_use_os_directories_and_a_minimal_environment(monkeypatch, wow64):
    monkeypatch.setattr(windows_system, "_directories", lambda: (r"D:\WinOS", r"D:\WinOS\System32", wow64))
    monkeypatch.setenv("SystemRoot", r"C:\Untrusted")
    monkeypatch.setenv("PATH", r"C:\Untrusted")
    monkeypatch.setenv("SECRET_TOKEN", "do-not-inherit")
    helper = windows_system.powershell_path()
    env = windows_system.helper_environment()
    expected_directory = "Sysnative" if wow64 else "System32"
    assert helper == "D:\\WinOS\\" + expected_directory + r"\WindowsPowerShell\v1.0\powershell.exe"
    assert env["SystemRoot"] == env["WINDIR"] == r"D:\WinOS"
    assert env["PATH"].split(";") == [r"D:\WinOS\System32", r"D:\WinOS\System32\Wbem",
                                      r"D:\WinOS\System32\WindowsPowerShell\v1.0"]
    assert "Sysnative" not in env["PATH"]
    assert "SECRET_TOKEN" not in env and "Untrusted" not in str(env)


@pytest.mark.parametrize("size", [1024, 1025])
def test_fast_exit_waits_for_output_and_rechecks_the_limit(monkeypatch, size):
    exited = threading.Event()

    class AfterExit(io.BytesIO):
        def read(self, size=-1):
            assert exited.wait(timeout=2)
            return super().read(size)

    class Process:
        stdout = AfterExit(b"x" * size)
        stderr = io.BytesIO()
        returncode = 0

        def poll(self):
            exited.set()
            return 0

        def wait(self):
            return 0

    proc = Process()
    monkeypatch.setattr(gate_module.subprocess, "Popen", lambda *args, **kwargs: proc)
    gate = Gate("/", budget=Budget(max_subprocess_output_bytes=1024))
    result = gate.run_helper((sys.executable,))
    if size == 1024:
        assert result.ok and result.value.stdout == "x" * size
    else:
        assert not result.ok and result.reason == "output_limit"
    assert proc.stdout.closed and proc.stderr.closed


def test_pipe_timeout_does_not_close_an_active_reader(monkeypatch):
    release = threading.Event()
    closed = threading.Event()
    closed_early = threading.Event()

    class InheritedPipe(io.BytesIO):
        def read(self, size=-1):
            release.wait(timeout=2)
            return b""

        def close(self):
            if not release.is_set():
                closed_early.set()
            super().close()
            closed.set()

    class Process:
        stdout = InheritedPipe()
        stderr = io.BytesIO()
        returncode = 0

        def poll(self):
            return 0

        def wait(self):
            return 0

    monkeypatch.setattr(gate_module.subprocess, "Popen", lambda *args, **kwargs: Process())
    gate = Gate("/", budget=Budget(max_subprocess_seconds=0.05))
    try:
        result = gate.run_helper((sys.executable,))
        assert not result.ok and result.reason == "pipe_timeout"
        assert not closed.is_set() and not closed_early.is_set()
    finally:
        release.set()
        assert closed.wait(timeout=2)


@NATIVE
def test_native_inherited_pipe_cannot_hold_up_the_scan(tmp_path):
    gate = Gate("/", budget=Budget(max_subprocess_seconds=1))
    script = (
        "import subprocess,sys; "
        "subprocess.Popen([sys.executable,'-c','import time; time.sleep(3)'],close_fds=False); "
        "sys.stdout.write('done'); sys.stdout.flush()"
    )
    started = time.monotonic()
    result = gate.run_helper((sys.executable, "-c", script))
    assert not result.ok and result.reason == "pipe_timeout", result
    assert time.monotonic() - started < 2.5


@NATIVE
def test_native_powershell_preserves_non_ascii_json(tmp_path, monkeypatch, capfd):
    # Diagnose the first system PowerShell on a cold CI host without starting
    # a separate warmup process. Only this diagnostic has a longer deadline;
    # the production default and the remaining native checks stay at 5s.
    gate = Gate("/", providers=windows.WindowsProviders(), budget=Budget(max_subprocess_seconds=15))
    stages = []
    labels = {"script_start", "prefix_done", "utility_start", "utility_done", "query_done"}
    started = time.time()
    elapsed_start = time.monotonic()
    original_popen = gate_module.subprocess.Popen

    class DiagnosticStderr:
        def __init__(self, stream):
            self.stream = stream
            self.pending = b""

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def read(self, size=-1):
            chunk = self.stream.read(size)
            self.pending += chunk
            while b"\n" in self.pending:
                line, _, self.pending = self.pending.partition(b"\n")
                fields = line.rstrip(b"\r").split(b":")
                if len(fields) == 3 and fields[0] == b"ADR_NATIVE_DIAG":
                    label = fields[1].decode("ascii", "ignore")
                    if label in labels and fields[2].isdigit():
                        stages.append((label, int(fields[2]) / 1000 - started))
            # Error text is neither retained indefinitely nor printed.
            self.pending = self.pending[-1024:]
            return chunk

    def instrumented_popen(*args, **kwargs):
        proc = original_popen(*args, **kwargs)
        proc.stderr = DiagnosticStderr(proc.stderr)
        return proc

    def marker(label):
        return ("[Console]::Error.WriteLine('ADR_NATIVE_DIAG:" + label
                + ":'+[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()); ")

    original_import = windows._import_module

    def instrumented_import(name):
        return marker("utility_start") + original_import(name) + marker("utility_done")

    monkeypatch.setattr(gate_module.subprocess, "Popen", instrumented_popen)
    monkeypatch.setattr(windows, "_PS_PREFIX", marker("script_start") + windows._PS_PREFIX + marker("prefix_done"))
    monkeypatch.setattr(windows, "_import_module", instrumented_import)
    result = gate.providers._ps_json(
        gate, "[pscustomobject]@{Name='中文';Path='D:\\测试 空格\\Agent'} | ConvertTo-Json -Compress; "
        + marker("query_done"), "unicode",
    )
    with capfd.disabled():
        for label, elapsed in stages:
            print(f"native_ps_diag stage={label} elapsed={elapsed:.3f}s", flush=True)
        status = "ok" if result.ok else "refused"
        print(f"native_ps_diag stage=complete elapsed={time.monotonic() - elapsed_start:.3f}s status={status}", flush=True)
    assert result.ok, result
    assert result.value == ({"Name": "中文", "Path": r"D:\测试 空格\Agent"},)


@NATIVE
def test_native_socket_script_serializes_enum_names(tmp_path, monkeypatch):
    gate = Gate("/", providers=windows.WindowsProviders())
    original = gate.run_helper
    stub = (
        "function Get-NetTCPConnection { [CmdletBinding()]param(); "
        "[pscustomobject]@{State=[System.Net.NetworkInformation.TcpState]::Listen;LocalPort=11434;"
        "RemoteAddress='::';RemotePort=0;OwningProcess=42} }; "
    )

    def stub_after_imports(argv):
        script = argv[-1].replace("Get-NetTCPConnection -ErrorAction Stop", stub + "Get-NetTCPConnection -ErrorAction Stop", 1)
        return original((*argv[:-1], script))

    monkeypatch.setattr(gate, "run_helper", stub_after_imports)
    result = gate.sockets()
    assert result.ok, result
    assert [(row.state, row.local_port) for row in result.value] == [("LISTEN", 11434)]


@NATIVE
def test_native_application_script_keeps_per_source_errors(tmp_path, monkeypatch):
    gate = Gate("/", providers=windows.WindowsProviders())
    original = gate.run_helper

    def stub_after_imports(argv):
        script = argv[-1].replace(
            "if(Test-Path -LiteralPath", "function Test-Path { [CmdletBinding()]param([string]$LiteralPath); $false }; if(Test-Path -LiteralPath",
        ).replace(
            "$rows=@(Get-AppxPackage", "function Get-AppxPackage { [CmdletBinding()]param(); throw [UnauthorizedAccessException]::new('private') }; $rows=@(Get-AppxPackage",
        )
        return original((*argv[:-1], script))

    monkeypatch.setattr(gate, "run_helper", stub_after_imports)
    result = gate.applications()
    assert result.ok and result.value == (), result
    assert SOURCES[-1] in _unavailable(gate)
    assert all(source not in _unavailable(gate) for source in SOURCES[:-1])
    assert "private" not in str(gate.ledger.freeze())


@NATIVE
@pytest.mark.parametrize("surface,query", [
    ("processes", "Get-CimInstance Win32_Process -ErrorAction Stop | Select-Object -First 1 ProcessId"),
    ("sockets", "Get-NetTCPConnection -State Listen -ErrorAction Stop | Select-Object -First 1 LocalPort"),
    ("dns_cache", "Get-DnsClientCache -ErrorAction Stop | Select-Object -First 1 Entry"),
])
def test_native_inventory_modules_finish_or_report_access_failure(surface, query):
    gate = Gate("/", providers=windows.WindowsProviders())
    result = gate.providers._ps_json(gate, query + " | ConvertTo-Json -Compress", surface)
    assert gate.budget.max_subprocess_seconds == 5.0
    if result.ok:
        assert len(result.value) <= 1
    else:
        # OS edition/service/permissions can make an inventory unavailable;
        # a module-discovery timeout is never an acceptable empty result.
        assert result.reason == "unavailable"
        assert "PowerShell exited with code" in result.detail, result
        assert surface in _unavailable(gate)


@NATIVE
def test_native_helper_rejects_invalid_utf8(tmp_path):
    gate = Gate("/")
    result = gate.run_helper((windows_system.powershell_path(), "-NoProfile", "-NonInteractive", "-Command",
                              "[Console]::OpenStandardOutput().WriteByte(255)"))
    assert not result.ok and result.reason == "invalid_encoding", result


@NATIVE
def test_native_helper_timeout_remains_bounded(tmp_path):
    gate = Gate("/", budget=Budget(max_subprocess_seconds=0.1))
    result = gate.run_helper((windows_system.powershell_path(), "-NoProfile", "-NonInteractive", "-Command",
                              "Start-Sleep -Seconds 30"))
    assert not result.ok and result.reason == "timeout", result


@NATIVE
def test_native_helper_enforces_output_limit(tmp_path):
    gate = Gate("/", budget=Budget(max_subprocess_output_bytes=1024))
    result = gate.run_helper((windows_system.powershell_path(), "-NoProfile", "-NonInteractive", "-Command",
                              "[Console]::Out.Write('x' * 65536); Start-Sleep -Seconds 30"))
    assert not result.ok and result.reason == "output_limit", result
