"""Windows roots and evidence, independent of the native Gate access patch."""

from __future__ import annotations

import json
import os
import stat
import struct
import sys
from types import SimpleNamespace

import pytest

from adr_discovery.catalog.load import CatalogError, loads
from adr_discovery.contracts.records import Candidate, Priority
from adr_discovery.enumerator.roots import ordered_roots, source_paths, state_roots
from adr_discovery.enumerator.sources.appstate import from_app_state
from adr_discovery.identifier.ladder import _by_provenance
from adr_discovery.world.gate import Entry, Ok, Refused
from adr_discovery.world.platform import windows_locations
from adr_discovery.world.platform.base import Application, Package
from adr_discovery.world.platform.windows import WindowsProviders
from adr_discovery.world.platform.windows_go import UnsupportedBuildInfo, go_module
from adr_discovery.world.platform.windows_locations import absolute


class Ledger:
    def __init__(self):
        self.records = []

    def probe(self, *args):
        self.records.append(args)

    def unavailable(self, *args):
        self.records.append(args)


class Machine:
    def __init__(self, env=None):
        self.env = env or {}
        self.root = "/fixture"
        self.providers = WindowsProviders()
        self.scan_token = object()
        self.ledger = Ledger()
        self.dirs = {}
        self.files = {}
        self.listed = []

    def directory(self, path, *children):
        self.dirs[path] = [Entry(child, True, False, 0) for child in children]
        for child in children:
            self.dirs.setdefault(child, [])
        return self

    def list_dir(self, path):
        self.listed.append(path)
        return Ok(tuple(self.dirs[path])) if path in self.dirs else Refused("missing")

    def stat(self, path):
        if path in self.dirs or path in self.files:
            return Ok(SimpleNamespace(mode=stat.S_IFDIR if path in self.dirs else stat.S_IFREG,
                                      real_path=path, size=len(self.files.get(path, b""))))
        return Refused("missing")

    def read_text(self, path, limit=None):
        data = self.files.get(path)
        return Ok(data.decode("utf-8")) if data is not None else Refused("missing")

    def read_bytes(self, path, limit=None):
        data = self.files.get(path)
        return Ok(data[:limit]) if data is not None else Refused("missing")

    def package_owner(self, path):
        return Refused("not_owned")

    def run_helper(self, *args, **kwargs):
        pytest.fail("language discovery must not execute a helper")


@pytest.mark.parametrize("path", [r"D:\Profiles\中文 User", r"\\server\homes\Alice", "//server/homes"])
def test_accepts_drive_and_unc_locations(path):
    assert absolute(path) == path.replace("\\", "/")


@pytest.mark.parametrize("path", ["/Users/Alice", r"D:relative", r"\current-drive", r"\\?\D:\profile"])
def test_rejects_unanchored_and_device_locations(path):
    assert absolute(path) is None


def test_userprofile_without_home_and_without_drive_root_sweep():
    machine = Machine({"USERPROFILE": r"D:\中文 User", "APPDATA": r"E:\roaming"})
    machine.directory("D:/中文 User")
    assert machine.providers.homes(machine) == ("D:/中文 User",)
    assert machine.providers._locations(machine)[0].roaming == "E:/roaming"
    assert "D:/" not in machine.listed


def test_profilelist_redirects_are_per_user_and_caller_is_retained(monkeypatch):
    machine = Machine({"USERPROFILE": r"E:\Current", "APPDATA": r"F:\current-roaming",
                       "LOCALAPPDATA": r"F:\current-local", "SYSTEMDRIVE": "D:"})
    machine.directory("D:/Profiles", "D:/Profiles/Alice", "D:/Profiles/Public")
    machine.directory("E:/Current").directory("//server/homes/Bob")
    monkeypatch.setattr(windows_locations, "_registry_data", lambda gate: (
        "D:/Profiles", {"D:/Profiles/Alice": {"AppData": r"%USERPROFILE%\MovedRoaming"},
                        "//server/homes/Bob": {"Local AppData": r"G:\BobLocal"}}))
    profiles = {profile.home: profile for profile in machine.providers._locations(machine)}
    assert set(profiles) == {"D:/Profiles/Alice", "E:/Current", "//server/homes/Bob"}
    assert profiles["D:/Profiles/Alice"].roaming == "D:/Profiles/Alice/MovedRoaming"
    assert profiles["//server/homes/Bob"].roaming == "//server/homes/Bob/AppData/Roaming"
    assert profiles["//server/homes/Bob"].local == "G:/BobLocal"
    assert profiles["E:/Current"].local == "F:/current-local"


def test_locations_are_cached_only_for_the_current_scan(monkeypatch):
    machine = Machine({"USERPROFILE": "D:/Alice"}).directory("D:/Alice")
    calls = []

    def registry(gate):
        calls.append(gate)
        return None, {}

    monkeypatch.setattr(windows_locations, "_registry_data", registry)
    machine.providers.homes(machine)
    machine.providers.homes(machine)
    assert len(calls) == 1
    machine.scan_token = object()
    machine.providers.homes(machine)
    assert len(calls) == 2
    del machine.scan_token
    machine.providers.homes(machine)
    machine.providers.homes(machine)
    assert len(calls) == 4


@pytest.mark.parametrize("error,reason", [(FileNotFoundError, "hive or key unavailable"),
                                         (PermissionError, "access denied")])
def test_unreadable_user_hives_report_known_folder_fallback(monkeypatch, error, reason):
    sid = "S-1-5-21-1-2-3-1000"
    profile_list = windows_locations._PROFILE_LIST
    data = {
        (1, profile_list): {"ProfilesDirectory": "D:/Profiles"},
        (1, profile_list + "\\" + sid): {"ProfileImagePath": "D:/Profiles/Bob"},
    }

    class Key:
        def __init__(self, values):
            self.values = values

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def open_key(hive, path, *args):
        if hive == 2:
            raise error("unavailable")
        return Key(data[(hive, path)])

    registry = SimpleNamespace(HKEY_LOCAL_MACHINE=1, HKEY_USERS=2, HKEY_CURRENT_USER=3,
                               KEY_READ=1, KEY_WOW64_64KEY=2, OpenKey=open_key,
                               QueryValueEx=lambda key, name: (key.values[name], 1),
                               QueryInfoKey=lambda key: (1, 0, 0), EnumKey=lambda key, index: sid)
    monkeypatch.setitem(sys.modules, "winreg", registry)
    monkeypatch.setattr(windows_locations, "os", SimpleNamespace(name="nt"))
    gate = SimpleNamespace(env={}, _live=True, ledger=Ledger())
    root, profiles = windows_locations._registry_data(gate)
    assert root == "D:/Profiles"
    assert profiles == {"D:/Profiles/Bob": {}}
    assert any(record[:2] == ("known_folders", "degraded") and reason in record[2]
               for record in gate.ledger.records)


def test_legacy_or_fixture_gate_never_queries_host_registry(monkeypatch):
    monkeypatch.setattr(windows_locations, "os", SimpleNamespace(name="nt"))
    gate = SimpleNamespace(root="D:/", ledger=Ledger())
    assert windows_locations._registry_data(gate) == (None, {})
    assert gate.ledger.records
    gate._live = False
    assert windows_locations._registry_data(gate) == (None, {})


def test_system_roots_and_state_use_windows_locations():
    machine = Machine({"USERPROFILE": "D:/Alice", "APPDATA": "E:/Roaming",
                       "LOCALAPPDATA": "E:/Local", "ProgramFiles": "F:/Apps",
                       "ProgramData": "F:/Shared"}).directory("D:/Alice")
    machine.directory("E:/Roaming/Claude")
    roots = ordered_roots(machine)
    assert ("F:/Apps", Priority.SYSTEM) in roots
    assert ("E:/Local/Programs", Priority.SYSTEM) in roots
    assert all(not path.startswith(("/opt", "/usr", "/Users", "/home")) for path, _ in roots)
    assert "E:/Roaming/Claude" in state_roots(machine)
    assert not any("/Documents" in path for path, _ in roots)


def test_redirected_browser_profiles_and_existing_configs_are_enumerated():
    machine = Machine({"USERPROFILE": "D:/Alice", "APPDATA": "E:/Roaming",
                       "LOCALAPPDATA": "E:/Local"}).directory("D:/Alice")
    browser = "E:/Local/Google/Chrome/User Data"
    machine.directory(browser, browser + "/Default", browser + "/Profile 2", browser + "/Guest Profile")
    machine.directory(browser + "/Profile 2/Extensions", browser + "/Profile 2/Extensions/known-id")
    firefox = "E:/Roaming/Mozilla/Firefox/Profiles"
    machine.directory(firefox, firefox + "/abc.default")
    machine.directory(firefox + "/abc.default/extensions")
    machine.dirs[firefox + "/abc.default/extensions"].append(
        Entry(firefox + "/abc.default/extensions/extension@example.org.xpi", False, False, 8))
    config = "E:/Roaming/Claude/claude_desktop_config.json"
    machine.files[config] = b"{}"
    candidates = from_app_state(machine, machine.providers.homes(machine))
    assert any(c.detail.get("profile") == "Profile 2" for c in candidates)
    assert any(c.detail.get("extension_id") == "extension@example.org" for c in candidates)
    assert any(c.path == config for c in candidates)
    assert not any(c.detail.get("profile") == "Guest Profile" for c in candidates)
    assert "E:/Local/BraveSoftware/Brave-Browser/User Data" in machine.listed
    assert "E:/Local/Microsoft/Edge/User Data" in machine.listed


def test_models_managed_config_and_precise_profile_allowlist(monkeypatch):
    machine = Machine({"USERPROFILE": "D:/Alice", "ProgramFiles": "F:/Apps",
                       "OLLAMA_MODELS": "G:/models", "HF_HOME": "H:/hf"}).directory("D:/Alice")
    monkeypatch.setattr(windows_locations, "_registry_data", lambda gate: (
        None, {"D:/Alice": {"Personal": "//server/docs/Alice"}}))
    homes = machine.providers.homes(machine)
    assert source_paths(machine, "models", (), homes)[:2] == ("G:/models", "H:/hf/hub")
    assert "F:/Apps/ClaudeCode/managed-mcp.json" in source_paths(machine, "config", (), homes)
    profiles = machine.providers.powershell_profile_paths(machine)
    assert len(profiles) == 4
    assert "//server/docs/Alice/PowerShell/profile.ps1" in profiles
    assert "//server/docs/Alice" not in machine.providers.system_roots(machine)


def test_language_packages_survive_unavailable_application_registry(monkeypatch):
    machine = Machine({"USERPROFILE": "D:/Alice", "APPDATA": "E:/Roaming",
                       "LOCALAPPDATA": "E:/Local", "NPM_CONFIG_PREFIX": "F:/npm"}).directory("D:/Alice")
    machine.directory("F:/npm/node_modules", "F:/npm/node_modules/@vendor")
    package = "F:/npm/node_modules/@vendor/tool"
    machine.directory("F:/npm/node_modules/@vendor", package)
    machine.files[package + "/package.json"] = b'{"name":"@vendor/tool","version":"1.2"}'
    machine.directory("E:/Local/pipx/pipx/venvs", "E:/Local/pipx/pipx/venvs/tool")
    machine.directory("E:/Roaming/uv/data/tools", "E:/Roaming/uv/data/tools/tool")
    machine.files["D:/Alice/.cargo/.crates2.json"] = b'{"installs":{"tool 2.0 (registry+test)":{}}}'
    python = "E:/Local/Programs/Python"
    metadata = python + "/Python313/Lib/site-packages/tool-3.0.dist-info"
    machine.directory(python, python + "/Python313")
    machine.directory(python + "/Python313/Lib/site-packages", metadata)
    machine.files[metadata + "/METADATA"] = b"Metadata-Version: 2.1\nName: tool\nVersion: 3.0\n\nDescription"
    monkeypatch.setattr(machine.providers, "applications", lambda gate: Refused("unavailable"))
    result = machine.providers.packages(machine)
    assert result.ok
    assert {p.manager for p in result.value} == {"npm", "pipx", "uv", "cargo", "pip"}
    assert Package("npm", "@vendor/tool", "1.2", package) in result.value
    assert Package("pip", "tool", "3.0", metadata) in result.value
    assert any(record[:2] == ("packages", "degraded") for record in machine.ledger.records)
    assert not any(path.startswith("/usr") for path in machine.listed)


def test_application_packages_retain_stable_ids(monkeypatch):
    machine = Machine()
    monkeypatch.setattr(machine.providers, "applications", lambda gate: Ok((
        Application("stable-id", "Friendly Name", "2.1", path="D:/App"),)))
    assert machine.providers.packages(machine).value == (Package("windows", "stable-id", "2.1", "D:/App"),)


def test_official_ollama_installer_id_matches_shipped_catalog(catalog):
    candidate = Candidate("application", "D:/Apps/Ollama", "app_registry",
                          detail={"ident": "{44E83376-CE68-45EB-8FC1-393500EB558C}_is1",
                                  "name": "Localized display name"})
    assert _by_provenance(Machine(), candidate, catalog)[0].id == "ollama"
    assert catalog.match("binaries", "OLLAMA.EXE").id == "ollama"
    unknown = Candidate("application", "D:/Other", "app_registry",
                        detail={"ident": "unrelated-key", "name": "Ollama"})
    assert _by_provenance(Machine(), unknown, catalog)[0] is None


def catalog(*, target=None, registry="stable-id"):
    fingerprints = {"registry_names": [registry]}
    if target:
        fingerprints["install_layouts"] = [{"target": target}]
    return loads(json.dumps({"entries": [{"id": "tool", "name": "Tool", "vendor": "Vendor",
                                          "kind": "cli_agent", "fingerprints": fingerprints}]}))


@pytest.mark.parametrize("kind,source,detail", [
    ("application", "app_registry", {"ident": "STABLE-ID", "name": "anything"}),
    ("package", "package:windows", {"name": "stable-id"}),
])
def test_registry_names_use_exact_identity(kind, source, detail):
    candidate = Candidate(kind, "D:/App", source, detail=detail)
    assert _by_provenance(Machine(), candidate, catalog())[0].id == "tool"
    detail = {**detail, "ident": "other", "name": "stable-id"} if kind == "application" else {"name": "other"}
    candidate = Candidate(kind, "D:/App", source, detail=detail)
    assert _by_provenance(Machine(), candidate, catalog())[0] is None


@pytest.mark.parametrize("target,path", [
    (r"D:\Apps\Tool\*.exe", r"d:\apps\TOOL\tool.EXE"),
    (r"\\server\apps\Tool\*.exe", "//SERVER/apps/tool/Tool.EXE"),
    ("~/.tool/versions/*.exe", r"E:\Profiles\Alice\.TOOL\versions\1.EXE"),
])
def test_windows_install_layouts_match_case_and_nonstandard_homes(target, path):
    machine = Machine({"USERPROFILE": "E:/Profiles/Alice"}).directory("E:/Profiles/Alice")
    candidate = Candidate("process", path, "kernel")
    assert _by_provenance(machine, candidate, catalog(target=target))[0].id == "tool"


@pytest.mark.parametrize("target", [r"D:relative\*.exe", r"\\?\D:\Apps\*.exe", r"\Apps\*.exe"])
def test_layouts_reject_relative_and_device_paths(target):
    with pytest.raises(CatalogError):
        catalog(target=target)


def test_windows_layout_duplicate_case_is_rejected():
    entries = [{"id": name, "name": name, "vendor": "v", "kind": "cli_agent",
                "fingerprints": {"install_layouts": [{"target": target}]}}
               for name, target in (("a", "D:/Apps/Tool/*.exe"), ("b", "d:/apps/tool/*.EXE"))]
    with pytest.raises(CatalogError, match="ambiguous"):
        loads(json.dumps({"entries": entries}))


def test_layout_home_matching_observes_directory_boundary():
    machine = Machine({"USERPROFILE": "D:/Alice"}).directory("D:/Alice")
    candidate = Candidate("process", "D:/Alice2/.tool/tool.exe", "kernel")
    assert _by_provenance(machine, candidate, catalog(target="~/.tool/*.exe"))[0] is None


def _go_image(*, flags=2, section_flags=0xC0000040):
    module = b"a" * 16 + b"path\texample.org/tool/cmd/tool\nmod\texample.org/tool\tv1.2.3\th1:test\n" + b"z" * 16
    version = b"go1.24.0"
    payload = b"\xff Go buildinf:" + bytes((8, flags)) + b"\0" * 16
    payload += bytes((len(version),)) + version + bytes((len(module),)) + module
    image = bytearray(1024)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 60, 128)
    image[128:132] = b"PE\0\0"
    struct.pack_into("<H", image, 134, 1)
    struct.pack_into("<H", image, 148, 240)
    struct.pack_into("<H", image, 152, 0x20B)
    struct.pack_into("<IIII", image, 400, len(payload), 0x1000, 512, 512)
    struct.pack_into("<I", image, 428, section_flags)
    image[512:512 + len(payload)] = payload
    return bytes(image)


def test_go_inline_metadata_is_read_without_executing_helpers(monkeypatch):
    machine = Machine({"USERPROFILE": "D:/Alice", "GOBIN": "F:/GoBin"}).directory("D:/Alice")
    machine.directory("F:/GoBin")
    machine.dirs["F:/GoBin"].append(Entry("F:/GoBin/tool.EXE", False, False, 1024))
    machine.files["F:/GoBin/tool.EXE"] = _go_image()
    monkeypatch.setattr(machine.providers, "applications", lambda gate: Refused("unavailable"))
    packages = machine.providers.packages(machine)
    assert packages.ok
    assert Package("go", "example.org/tool", "v1.2.3", "F:/GoBin/tool.EXE") in packages.value


def test_go_magic_requires_a_pe_data_section_and_alignment():
    assert go_module(_go_image()[512:]) is None
    assert go_module(_go_image(section_flags=0x60000020)) is None
    shifted = bytearray(_go_image())
    shifted[513:] = shifted[512:-1]
    shifted[512] = 0
    assert go_module(bytes(shifted)) is None


def test_go_old_formats_and_truncated_varints_are_explicit():
    with pytest.raises(UnsupportedBuildInfo):
        go_module(_go_image(flags=0))
    malformed = bytearray(_go_image())
    malformed[544:554] = b"\xff" * 10
    with pytest.raises(ValueError, match="string length"):
        go_module(bytes(malformed))


@pytest.mark.skipif(os.name != "nt", reason="native Windows registry read")
def test_native_profilelist_and_current_known_folders():
    gate = SimpleNamespace(env=dict(os.environ), root="/", _live=True, ledger=Ledger())
    root, profiles = windows_locations._registry_data(gate)
    current = absolute(os.environ["USERPROFILE"])
    assert root and absolute(root) == root
    assert any(home.casefold() == current.casefold() for home in profiles)
    for values in profiles.values():
        assert all(isinstance(value, str) for value in values.values())
