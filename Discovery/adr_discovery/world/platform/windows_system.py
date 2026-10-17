"""Trusted Windows helper locations, obtained from the OS rather than PATH."""

from __future__ import annotations

import ctypes
import ntpath
import os
from ctypes import wintypes


def _directories() -> tuple[str, str, bool]:
    if os.name != "nt":
        raise OSError("Windows system directories are unavailable on this platform")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)

    def directory(name: str) -> str:
        query = getattr(kernel, name)
        query.argtypes = [wintypes.LPWSTR, wintypes.UINT]
        query.restype = wintypes.UINT
        buffer = ctypes.create_unicode_buffer(32768)
        length = query(buffer, len(buffer))
        if not length:
            raise ctypes.WinError(ctypes.get_last_error())
        if length >= len(buffer):
            raise OSError("Windows system directory exceeds the path limit")
        path = buffer.value
        # GetSystemWindowsDirectoryW can return just a drive for a root install.
        drive, tail = ntpath.splitdrive(path)
        if drive and not tail:
            path += "\\"
        if not ntpath.isabs(path):
            raise OSError("Windows returned a non-absolute system directory")
        return path

    windows = directory("GetSystemWindowsDirectoryW")
    system = directory("GetSystemDirectoryW")
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.IsWow64Process.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
    kernel.IsWow64Process.restype = wintypes.BOOL
    wow64 = wintypes.BOOL()
    if not kernel.IsWow64Process(kernel.GetCurrentProcess(), ctypes.byref(wow64)):
        raise ctypes.WinError(ctypes.get_last_error())
    return windows, system, bool(wow64.value)


def powershell_path() -> str:
    windows, system, wow64 = _directories()
    # A 32-bit scanner must query the native registry view. Sysnative is an
    # OS alias available only to WOW64 callers; do not put it in the child PATH.
    native = ntpath.join(windows, "Sysnative") if wow64 else system
    return ntpath.join(native, "WindowsPowerShell", "v1.0", "powershell.exe")


def helper_environment() -> dict[str, str]:
    windows, system, _ = _directories()
    powershell = ntpath.join(system, "WindowsPowerShell", "v1.0")
    return {
        "SystemRoot": windows,
        "WINDIR": windows,
        "PATH": ";".join((system, ntpath.join(system, "Wbem"), powershell)),
        "PSModulePath": ntpath.join(powershell, "Modules"),
        "COMSPEC": ntpath.join(system, "cmd.exe"),
    }
