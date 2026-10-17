"""Native Windows output/ACL regression tests, independent of the inventory Gate."""

from __future__ import annotations

import ctypes
import os
import re
import struct
import subprocess
from contextlib import contextmanager
from ctypes import wintypes

import pytest

from adr_discovery.cli import _write_private
from adr_discovery.world import private_output
from adr_discovery.world.private_output import private_directory
from adr_discovery.world.store import ArchiveStore

pytestmark = pytest.mark.skipif(os.name != "nt", reason="native Windows handles and DACLs")


def _sddl(path):
    """Inspect the persisted ACL independently through the named-object API."""
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi.GetNamedSecurityInfoW.argtypes = [wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD,
                                            ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.LPVOID),
                                            ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.LPVOID),
                                            ctypes.POINTER(wintypes.LPVOID)]
    advapi.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [wintypes.LPVOID, wintypes.DWORD,
                                                                           wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR),
                                                                           ctypes.POINTER(wintypes.DWORD)]
    advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [wintypes.LPVOID]
    kernel.LocalFree.restype = wintypes.LPVOID
    descriptor, text = wintypes.LPVOID(), wintypes.LPWSTR()
    code = advapi.GetNamedSecurityInfoW(str(path), 1, 5, None, None, None, None, ctypes.byref(descriptor))
    if code:
        raise ctypes.WinError(code)
    try:
        if not advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, 1, 5, ctypes.byref(text), None):
            raise ctypes.WinError(ctypes.get_last_error())
        return text.value
    finally:
        if text:
            kernel.LocalFree(ctypes.cast(text, wintypes.LPVOID))
        kernel.LocalFree(descriptor)


def _assert_private(path, *, directory=False):
    from adr_discovery.world._win_output import _API

    sid = _API().sid
    descriptor = _sddl(path)
    owner = descriptor.removeprefix("O:").split("D:", 1)[0]
    assert _full_sid(owner) == sid
    dacl = descriptor.split("D:", 1)[1]
    assert "P" in dacl.split("(", 1)[0]
    (ace,) = re.findall(r"\(([^)]*)\)", dacl)
    fields = ace.split(";")
    assert fields[:-1] == ["A", "OICI" if directory else "", "FA", "", ""]
    assert _full_sid(fields[-1]) == sid


def _full_sid(value):
    # Windows renders well-known SIDs with aliases, including LA for the
    # local Administrator account used by GitHub's hosted runner.
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.LPVOID)]
    advapi.ConvertStringSidToSidW.restype = wintypes.BOOL
    advapi.ConvertSidToStringSidW.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)]
    advapi.ConvertSidToStringSidW.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [wintypes.LPVOID]
    kernel.LocalFree.restype = wintypes.LPVOID
    native, text = wintypes.LPVOID(), wintypes.LPWSTR()
    if not advapi.ConvertStringSidToSidW(value, ctypes.byref(native)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if not advapi.ConvertSidToStringSidW(native, ctypes.byref(text)):
            raise ctypes.WinError(ctypes.get_last_error())
        return text.value
    finally:
        if text:
            kernel.LocalFree(ctypes.cast(text, wintypes.LPVOID))
        kernel.LocalFree(native)


def test_snapshot_has_owner_only_acl_before_any_payload_write(tmp_path, monkeypatch):
    output = tmp_path / "输出 with spaces"
    original = private_output.os.fdopen
    observed = []

    def inspect_before_write(fd, *args, **kwargs):
        _assert_private(output, directory=True)
        _assert_private(output / "snapshot.json")
        assert (output / "snapshot.json").stat().st_size == 0
        observed.append(True)
        return original(fd, *args, **kwargs)

    monkeypatch.setattr(private_output.os, "fdopen", inspect_before_write)
    _write_private(str(output), "snapshot.json", "private payload")
    assert observed == [True]
    assert (output / "snapshot.json").read_text() == "private payload"


def test_existing_directory_inherited_or_broad_acl_is_restricted(tmp_path):
    output = tmp_path / "existing output"
    with private_directory(str(output)):
        pass
    subprocess.run(["icacls", str(output), "/grant", "*S-1-1-0:(OI)(CI)F"], check=True, capture_output=True)
    _write_private(str(output), "snapshot.json", "private payload")
    _assert_private(output, directory=True)
    _assert_private(output / "snapshot.json")


def test_acl_failure_refuses_output_before_writing(tmp_path, monkeypatch):
    from adr_discovery.world._win_output import _API

    def refused(_self, _handle, _directory):
        raise PermissionError("DACL cannot be secured")

    monkeypatch.setattr(_API, "protect", refused)
    output = tmp_path / "out"
    with pytest.raises(PermissionError, match="DACL cannot"):
        _write_private(str(output), "snapshot.json", "private payload")
    assert not (output / "snapshot.json").exists()


def test_output_ancestors_cannot_be_renamed_while_in_use(tmp_path):
    parent = tmp_path / "parent"
    output = parent / "out"
    with private_directory(str(output)):
        with pytest.raises(OSError):
            os.rename(output, parent / "moved")
        with pytest.raises(OSError):
            os.rename(parent, tmp_path / "moved-parent")


@pytest.mark.parametrize("link_is_parent", [False, True])
def test_junction_output_and_junction_ancestor_are_refused(tmp_path, link_is_parent):
    target, junction = tmp_path / "target", tmp_path / "junction"
    target.mkdir()
    made = subprocess.run(["cmd", "/d", "/c", "mklink", "/J", str(junction), str(target)], capture_output=True)
    assert made.returncode == 0, made.stderr
    try:
        output = junction / "out" if link_is_parent else junction
        with pytest.raises(OSError, match="reparse"):
            _write_private(str(output), "snapshot.json", "private payload")
        assert list(target.iterdir()) == []
    finally:
        os.rmdir(junction)


@contextmanager
def _in_place_junction(path, target):
    """Retain a writable handle before output protection, then mutate the object."""
    from adr_discovery.world._win_output import _API

    api = _API()
    api.kernel.DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,
                                           wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                                           wintypes.LPVOID]
    api.kernel.DeviceIoControl.restype = wintypes.BOOL
    handle = api.open(str(path), 0x40000000)
    installed = False

    def control(code, data):
        buffer, returned = ctypes.create_string_buffer(data), wintypes.DWORD()
        if not api.kernel.DeviceIoControl(handle, code, buffer, len(data), None, 0, ctypes.byref(returned), None):
            raise ctypes.WinError(ctypes.get_last_error())

    def install():
        nonlocal installed
        substitute = ("\\??\\" + str(target)).encode("utf-16-le")
        display = str(target).encode("utf-16-le")
        paths = substitute + b"\0\0" + display + b"\0\0"
        data = struct.pack("<IHHHHHH", 0xA0000003, 8 + len(paths), 0,
                           0, len(substitute), len(substitute) + 2, len(display)) + paths
        control(0x900A4, data)  # FSCTL_SET_REPARSE_POINT, mount-point tag
        installed = True

    try:
        yield install
    finally:
        try:
            if installed:
                control(0x900AC, struct.pack("<IHH", 0xA0000003, 0, 0))
        finally:
            api.kernel.CloseHandle(handle)


@pytest.mark.parametrize("when", ["before_open", "during_open"])
def test_in_place_junction_cannot_redirect_snapshot_payload(tmp_path, monkeypatch, when):
    output, outside = tmp_path / "output", tmp_path / "outside"
    output.mkdir()
    outside.mkdir()
    canary = outside / "canary.txt"
    canary.write_bytes(b"untouched")
    injected = []
    with _in_place_junction(output, outside) as install, private_directory(str(output)) as directory:
        if when == "before_open":
            install()
        else:
            original = directory.api.relative

            def mutate_between_validation_and_open(root, name, access, **options):
                install()
                injected.append(True)
                return original(root, name, access, **options)

            monkeypatch.setattr(directory.api, "relative", mutate_between_validation_and_open)
        with pytest.raises(OSError):
            private_output.write_bytes(directory, "snapshot.json", b"private payload")
        if when == "during_open":
            assert injected == [True], "the native junction mutation must have succeeded"
        assert canary.read_bytes() == b"untouched"
        assert sorted(path.name for path in outside.iterdir()) == ["canary.txt"]
    assert list(output.iterdir()) == []


def test_in_place_junction_cannot_redirect_reads_or_cleanup(tmp_path):
    output, outside = tmp_path / "output", tmp_path / "outside"
    output.mkdir()
    outside.mkdir()
    canary = outside / "archive.zip"
    canary.write_bytes(b"untouched")
    with _in_place_junction(output, outside) as install, private_directory(str(output)) as directory:
        install()
        with pytest.raises(OSError):
            directory.read("archive.zip")
        # Cleanup also refuses a directory whose object became a junction.
        try:
            directory.unlink("archive.zip")
        except OSError:
            pass  # Refusal is safe; deleting the outside canary is not.
        assert canary.read_bytes() == b"untouched"


def test_publication_uses_the_directory_handle_after_in_place_junction(tmp_path):
    from adr_discovery.world._win_output import _API

    output, outside, holding = (tmp_path / name for name in ("output", "outside", "holding"))
    output.mkdir()
    outside.mkdir()
    holding.mkdir()
    api = _API()
    with _in_place_junction(output, outside) as install, private_directory(str(output)) as directory:
        private_output.write_bytes(directory, "temporary", b"private payload")
        source = api.relative(directory.handles[-1], "temporary", 0x10000)
        holding_handle = api.open(str(holding), 0xA1)
        try:
            # Empty the output directory through the open source handle, so
            # it can become a junction while that source remains pinned.
            api.rename(source, holding_handle, "held", replace=False)
            install()
            try:
                api.rename(source, directory.handles[-1], "archive.zip", replace=False)
            except OSError:
                pass  # Native refusal is also a valid no-redirect outcome.
            assert list(outside.iterdir()) == []
        finally:
            api.kernel.CloseHandle(holding_handle)
            api.kernel.CloseHandle(source)


def test_file_acl_verification_failure_deletes_the_created_handle(tmp_path, monkeypatch):
    from adr_discovery.world._win_output import _API

    original = _API.assert_private

    def refuse_file(self, handle, directory):
        if not directory:
            raise PermissionError("file ACL verification failed")
        original(self, handle, directory)

    monkeypatch.setattr(_API, "assert_private", refuse_file)
    output = tmp_path / "output"
    with pytest.raises(PermissionError, match="file ACL"):
        _write_private(str(output), "snapshot.json", "private payload")
    assert list(output.iterdir()) == []


def test_archive_publication_does_not_require_hard_links_and_never_overwrites(tmp_path, monkeypatch):
    def no_hardlinks(*_args, **_kwargs):
        raise OSError("hard links unsupported")

    monkeypatch.setattr(os, "link", no_hardlinks)
    store = ArchiveStore(str(tmp_path / "archives"))
    assert store.put_once("archive.zip", b"first\r\n\x1a\0")
    assert not store.put_once("archive.zip", b"second")
    assert store.read("archive.zip") == b"first\r\n\x1a\0"
    store.replace("index.jsonl", b"first index")
    store.replace("index.jsonl", b"second index")
    assert store.read("index.jsonl") == b"second index"
    _assert_private(store.directory, directory=True)
    _assert_private(store.path_of("archive.zip"))
    _assert_private(store.path_of("index.jsonl"))
    assert sorted(path.name for path in (tmp_path / "archives").iterdir()) == ["archive.zip", "index.jsonl"]


def test_relative_names_and_publication_preserve_utf16_surrogate_pairs(tmp_path):
    store = ArchiveStore(str(tmp_path / "输出😀"))
    assert store.put_once("归档😀.zip", b"archive bytes")
    assert store.read("归档😀.zip") == b"archive bytes"
    store.replace("索引😀.jsonl", b"first")
    store.replace("索引😀.jsonl", b"second")
    assert store.read("索引😀.jsonl") == b"second"
    _assert_private(store.path_of("归档😀.zip"))


def test_index_held_without_delete_sharing_keeps_old_data_and_cleans_temp(tmp_path):
    from adr_discovery.world._win_output import _API

    store = ArchiveStore(str(tmp_path / "archives"))
    store.replace("index.jsonl", b"original index")
    api = _API()
    handle = api.open(store.path_of("index.jsonl"), 0x80000000)
    try:
        with pytest.raises(PermissionError):
            store.replace("index.jsonl", b"replacement index")
    finally:
        api.kernel.CloseHandle(handle)
    assert store.read("index.jsonl") == b"original index"
    assert [path.name for path in (tmp_path / "archives").iterdir()] == ["index.jsonl"]
