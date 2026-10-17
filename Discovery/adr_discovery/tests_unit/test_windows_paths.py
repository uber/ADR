"""Windows path semantics without depending on the test host's path syntax."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from adr_discovery.contracts import paths
from adr_discovery.contracts.records import Candidate, Declaration, Kind, Observation
from adr_discovery.coverage.ledger import Ledger
from adr_discovery.enumerator.markers import is_loose_executable, marker_kind
from adr_discovery.enumerator.roots import in_scope
from adr_discovery.enumerator.sources.binaries import _roots, from_binaries
from adr_discovery.extractor.registries import (
    Install,
    Listing,
    Marketplace,
    Registries,
    Toggle,
    home_relative,
    plugin_roots,
)
from adr_discovery.extractor.surfaces import surface_for
from adr_discovery.pipeline import _container, _root_of, declaration_identity
from adr_discovery.redact.rules import is_personal
from adr_discovery.resolver import resolve
from adr_discovery.world.gate import Entry, Ok, Refused
from adr_discovery.world.platform.base import Application
from adr_discovery.world.platform.windows import WindowsProviders


@pytest.mark.parametrize("left,right", [
    (r"C:\Users\Alice\Tool", "c:/users/alice/tool"),
    (r"\\server\Share\Tool", "//SERVER/share/tool"),
    (r"D:\Apps\Tool\..\Agent", "d:/apps/agent"),
])
def test_windows_keys_match_without_changing_display(left, right):
    assert paths.key(left) == paths.key(right)
    assert paths.logical(left) == left.replace("\\", "/")
    assert Candidate("binary", left, "test").path == paths.logical(left)


def test_posix_paths_and_non_paths_keep_case_and_backslashes():
    assert paths.key("/opt/Agent") != paths.key("/opt/agent")
    assert paths.logical(r"/opt/a\b") == r"/opt/a\b"
    for value in ("tcp://host:123", "@scope/Agent", "C:relative", "https://Host/Tool"):
        assert paths.key(value) == value


def test_containment_obeys_drive_share_and_component_boundaries():
    assert paths.contains(r"C:\Apps\Tool", "c:/apps/tool/bin/agent.exe", proper=True)
    assert paths.contains("C:/", r"c:\Apps")
    assert not paths.contains(r"C:\Apps\Tool", "C:/Apps/Toolbox")
    assert not paths.contains(r"C:\Apps\Tool", "D:/Apps/Tool/bin")
    assert not paths.contains(r"\\host\share", r"\\host\share2\x")
    assert not paths.contains("C:/Apps/Tool", "c:/apps/tool", proper=True)
    assert paths.parent(r"D:\Agent\bin.exe") == "D:/Agent"
    assert _root_of(r"D:\Agent\bin.exe") == "D:/Agent"
    assert _root_of("/agent") == ""  # existing POSIX identity contract
    assert _container(["C:/Apps", "C:/Apps/Tool"], r"c:\apps\tool\skills\x") == "C:/Apps/Tool"


def test_windows_privacy_and_markers_are_case_insensitive():
    assert is_personal(r"C:\Users\Alice\DOCUMENTS\notes.txt")
    assert not in_scope(r"C:\Tool\.GIT\OBJECTS\blob")
    assert marker_kind("SETTINGS.JSON", r"C:\Tools\SETTINGS.JSON") == "marker_file"
    assert marker_kind("AGENTS.md", r"C:\Tools\AGENTS.md") == "instruction_file"
    assert surface_for(r"C:\Tools\SKILLS") is not None
    assert marker_kind("skill.md", "/opt/skill.md") is None


def test_path_entries_keep_drive_colons_and_windows_launcher_extensions():
    entries = (
        Entry(r"D:\Tool Bin\agent.CMD", False, False, 10),
        Entry(r"D:\Tool Bin\AGENT.cmd", False, False, 10),
        Entry(r"D:\Tool Bin\helper.BAT", False, False, 10),
        Entry(r"D:\Tool Bin\readme.txt", False, False, 10),
    )
    gate = SimpleNamespace(
        env={"PATH": r"D:\Tool Bin;\\server\share\bin"}, ledger=Ledger(),
        list_dir=lambda path: Ok(entries) if path == r"D:\Tool Bin" else Refused("absent"),
    )
    roots = _roots(gate, ())
    assert r"D:\Tool Bin" in roots and r"\\server\share\bin" in roots
    assert "D" not in roots
    assert [c.detail["name"] for c in from_binaries(gate, ())] == ["agent.CMD", "helper.BAT"]
    assert is_loose_executable(entries[0], "agent.CMD")
    assert not is_loose_executable(entries[-1], "readme.txt")
    gate.env["PATH"] = r"D:\Tool Bin"
    assert r"D:\Tool Bin" in _roots(gate, ())
    gate.env["PATH"] = "/opt/one:/opt/two"
    assert _roots(gate, ())[-2:] == ["/opt/one", "/opt/two"]


def test_registry_paths_share_enablement_and_installed_precedence():
    path = r"C:\Users\Alice\.claude\plugins\cache\team\tool\1"
    first = Install("claude", "tool", "team", path, scope="project", project=r"D:\Work\Project")
    second = replace(first, path=path.lower().replace("\\", "/"), scope="user", project=None)
    found = Registries(
        marketplaces=(Marketplace("claude", "team", location=path),),
        listings=(Listing("claude", "team", "tool", path.lower()),),
        installs=(first, second),
        toggles=(Toggle("claude", "tool@team", "project", "d:/work/project", False),
                 Toggle("claude", "tool@team", "user", None, True)),
        cached=(replace(first, path=path.upper()),),
    )
    assert found.enabled(first) is False
    assert found.enabled(second) is True
    ((display, provenance, installed),) = plugin_roots(found)
    assert display == path.replace("\\", "/")
    assert installed and provenance.state == "installed"
    assert provenance.enabled and provenance.install_scope == "user"
    assert home_relative(path, "c:/users/alice") == "~/.claude/plugins/cache/team/tool/1"
    assert home_relative("C:/Users/Alice2/tool", "c:/users/alice") == "C:/Users/Alice2/tool"
    assert home_relative(r"\\host\share\Tool", "//HOST/share") == "~/Tool"


def test_paths_merge_one_install_but_do_not_merge_other_drives():
    first = Observation(Kind.APP, r"C:\Apps\Agent", path=r"C:\Apps\Agent", owner="unknown")
    second = replace(first, identity="c:/apps/agent", path="c:/apps/agent")
    other = replace(first, identity="D:/Apps/Agent", path="D:/Apps/Agent")
    assert len(resolve((first, second))) == 1
    assert resolve((first,))[0].asset_id == resolve((second,))[0].asset_id
    assert len(resolve((first, other))) == 2
    child = replace(first, identity="child", path="c:/apps/agent/bin/agent.exe")
    assert len(resolve((first, child))) == 1


def test_declaration_identity_is_stable_across_windows_path_spellings():
    first = Declaration(Kind.SKILL, "tool", r"C:\Tools\Agent\SKILL.md")
    second = replace(first, path="c:/tools/agent/skill.md")
    assert declaration_identity(first) == declaration_identity(second)
    assert declaration_identity(replace(first, path="/opt/Agent/SKILL.md")) != declaration_identity(
        replace(first, path="/opt/agent/SKILL.md")
    )


def test_package_owner_selects_most_specific_install_with_either_separator(monkeypatch):
    providers = WindowsProviders()
    apps = (Application("parent", "Parent", "1", path="C:/Apps"),
            Application("child", "Child", "2", path=r"C:\Apps\Agent"))
    monkeypatch.setattr(providers, "applications", lambda gate: Ok(apps))
    owner = providers.package_owner(None, "c:/apps/agent/bin/agent.exe")
    assert owner.ok and owner.value.name == "child"
    assert not providers.package_owner(None, "C:/Appstore/agent.exe").ok
