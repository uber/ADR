"""Windows-only private output, implemented with the standard-library FFI.

Directory handles stay open without FILE_SHARE_DELETE. Descendants are opened
relative to those handles, so an in-place junction cannot redirect output.
New files receive a protected DACL before any payload bytes are written.
"""

from __future__ import annotations

import ctypes
import errno
import os
from ctypes import wintypes

from .private_output import plain_name

_READ_CONTROL = 0x00020000
_WRITE_DAC = 0x00040000
_WRITE_OWNER = 0x00080000
_FILE_READ_ATTRIBUTES = 0x80
_FILE_LIST_DIRECTORY = 0x1
_FILE_TRAVERSE = 0x20
_DIRECTORY = 0x10
_REPARSE_POINT = 0x400
_OWNER_INFORMATION = 0x1
_DACL_INFORMATION = 0x4
_PROTECTED_DACL_INFORMATION = 0x80000000
_FILE_ALL_ACCESS = 0x001F01FF
_DELETE = 0x00010000
_SYNCHRONIZE = 0x00100000


class _UnicodeString(ctypes.Structure):
    _fields_ = [("length", wintypes.USHORT), ("maximum", wintypes.USHORT), ("buffer", wintypes.LPWSTR)]


class _ObjectAttributes(ctypes.Structure):
    _fields_ = [("length", wintypes.ULONG), ("root", wintypes.HANDLE),
                ("name", ctypes.POINTER(_UnicodeString)), ("attributes", wintypes.ULONG),
                ("security", wintypes.LPVOID), ("quality", wintypes.LPVOID)]


class _IoStatusValue(ctypes.Union):
    _fields_ = [("status", wintypes.LONG), ("pointer", wintypes.LPVOID)]


class _IoStatusBlock(ctypes.Structure):
    _fields_ = [("value", _IoStatusValue), ("information", ctypes.c_size_t)]


class _RenameInformation(ctypes.Structure):
    _fields_ = [("replace", wintypes.DWORD), ("root", wintypes.HANDLE),
                ("length", wintypes.DWORD), ("name", wintypes.WCHAR * 1)]


class _FileInformation(ctypes.Structure):
    _fields_ = [("attributes", wintypes.DWORD), ("created", wintypes.FILETIME),
                ("accessed", wintypes.FILETIME), ("written", wintypes.FILETIME),
                ("volume", wintypes.DWORD), ("size_high", wintypes.DWORD),
                ("size_low", wintypes.DWORD), ("links", wintypes.DWORD),
                ("index_high", wintypes.DWORD), ("index_low", wintypes.DWORD)]


class _AclSize(ctypes.Structure):
    _fields_ = [("count", wintypes.DWORD), ("used", wintypes.DWORD), ("free", wintypes.DWORD)]


class _AllowedAce(ctypes.Structure):
    _fields_ = [("kind", wintypes.BYTE), ("flags", wintypes.BYTE), ("size", wintypes.WORD),
                ("mask", wintypes.DWORD), ("sid_start", wintypes.DWORD)]


class _API:
    def __init__(self) -> None:
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        self.ntdll = ctypes.WinDLL("ntdll")
        signatures = (
            (self.kernel, "GetCurrentProcess", [], wintypes.HANDLE),
            (self.kernel, "CloseHandle", [wintypes.HANDLE], wintypes.BOOL),
            (self.kernel, "LocalFree", [wintypes.LPVOID], wintypes.LPVOID),
            (self.kernel, "CreateFileW", [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                         wintypes.LPVOID, wintypes.DWORD,
                                         wintypes.DWORD, wintypes.HANDLE], wintypes.HANDLE),
            (self.kernel, "GetFileInformationByHandle", [wintypes.HANDLE, ctypes.POINTER(_FileInformation)], wintypes.BOOL),
            (self.kernel, "SetFileInformationByHandle", [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID,
                                                        wintypes.DWORD], wintypes.BOOL),
            (self.ntdll, "NtCreateFile", [ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD,
                                         ctypes.POINTER(_ObjectAttributes), ctypes.POINTER(_IoStatusBlock),
                                         wintypes.LPVOID, wintypes.ULONG, wintypes.ULONG, wintypes.ULONG,
                                         wintypes.ULONG, wintypes.LPVOID, wintypes.ULONG], wintypes.LONG),
            (self.ntdll, "NtSetInformationFile", [wintypes.HANDLE, ctypes.POINTER(_IoStatusBlock),
                                                 wintypes.LPVOID, wintypes.ULONG, ctypes.c_int], wintypes.LONG),
            (self.ntdll, "RtlNtStatusToDosError", [wintypes.LONG], wintypes.ULONG),
            (self.advapi, "OpenProcessToken", [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)], wintypes.BOOL),
            (self.advapi, "GetTokenInformation", [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID,
                                                 wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL),
            (self.advapi, "ConvertSidToStringSidW", [wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)], wintypes.BOOL),
            (self.advapi, "ConvertStringSecurityDescriptorToSecurityDescriptorW",
             [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL),
            (self.advapi, "GetSecurityDescriptorDacl", [wintypes.LPVOID, ctypes.POINTER(wintypes.BOOL),
                                                       ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.BOOL)], wintypes.BOOL),
            (self.advapi, "GetSecurityDescriptorOwner", [wintypes.LPVOID, ctypes.POINTER(wintypes.LPVOID),
                                                        ctypes.POINTER(wintypes.BOOL)], wintypes.BOOL),
            (self.advapi, "SetSecurityInfo", [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD, wintypes.LPVOID,
                                            wintypes.LPVOID, wintypes.LPVOID, wintypes.LPVOID], wintypes.DWORD),
            (self.advapi, "GetSecurityInfo", [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD,
                                            ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.LPVOID),
                                            ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.LPVOID),
                                            ctypes.POINTER(wintypes.LPVOID)], wintypes.DWORD),
            (self.advapi, "GetSecurityDescriptorControl", [wintypes.LPVOID, ctypes.POINTER(wintypes.WORD),
                                                          ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL),
            (self.advapi, "GetAclInformation", [wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, ctypes.c_int], wintypes.BOOL),
            (self.advapi, "GetAce", [wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID)], wintypes.BOOL),
        )
        for library, name, arguments, result in signatures:
            function = getattr(library, name)
            function.argtypes, function.restype = arguments, result
        self.sid = self._user_sid()

    @staticmethod
    def error(path: str = "", code: int | None = None) -> OSError:
        code = ctypes.get_last_error() if code is None else code
        if code in (80, 183):
            return FileExistsError(errno.EEXIST, "output already exists", path)
        if code in (2, 3):
            return FileNotFoundError(errno.ENOENT, "output does not exist", path)
        return ctypes.WinError(code)

    def _sid_text(self, sid) -> str:
        text = wintypes.LPWSTR()
        if not self.advapi.ConvertSidToStringSidW(sid, ctypes.byref(text)):
            raise self.error()
        try:
            return text.value
        finally:
            self.kernel.LocalFree(ctypes.cast(text, wintypes.LPVOID))

    def _user_sid(self) -> str:
        token = wintypes.HANDLE()
        if not self.advapi.OpenProcessToken(self.kernel.GetCurrentProcess(), 0x8, ctypes.byref(token)):
            raise self.error()
        try:
            size = wintypes.DWORD()
            self.advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
            if not size.value:
                raise self.error()
            buffer = ctypes.create_string_buffer(size.value)
            if not self.advapi.GetTokenInformation(token, 1, buffer, size, ctypes.byref(size)):
                raise self.error()
            return self._sid_text(ctypes.cast(buffer, ctypes.POINTER(wintypes.LPVOID)).contents.value)
        finally:
            self.kernel.CloseHandle(token)

    def security(self, directory: bool):
        descriptor = wintypes.LPVOID()
        flags = "OICI" if directory else ""
        sddl = f"O:{self.sid}D:P(A;{flags};FA;;;{self.sid})"
        if not self.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None):
            raise self.error()
        return descriptor

    def information(self, handle) -> _FileInformation:
        info = _FileInformation()
        if not self.kernel.GetFileInformationByHandle(handle, ctypes.byref(info)):
            raise self.error()
        if info.attributes & _REPARSE_POINT:
            raise OSError("output paths must not contain reparse points")
        return info

    def protect(self, handle, directory: bool) -> None:
        descriptor = self.security(directory)
        try:
            owner, acl = wintypes.LPVOID(), wintypes.LPVOID()
            present, defaulted = wintypes.BOOL(), wintypes.BOOL()
            if not self.advapi.GetSecurityDescriptorOwner(descriptor, ctypes.byref(owner), ctypes.byref(defaulted)):
                raise self.error()
            if not self.advapi.GetSecurityDescriptorDacl(descriptor, ctypes.byref(present), ctypes.byref(acl), ctypes.byref(defaulted)):
                raise self.error()
            error = self.advapi.SetSecurityInfo(handle, 1, _OWNER_INFORMATION | _DACL_INFORMATION | _PROTECTED_DACL_INFORMATION,
                                              owner, None, acl, None)
            if error:
                raise ctypes.WinError(error)
            self.assert_private(handle, directory)
        finally:
            self.kernel.LocalFree(descriptor)

    def assert_private(self, handle, directory: bool) -> None:
        owner, acl, descriptor = wintypes.LPVOID(), wintypes.LPVOID(), wintypes.LPVOID()
        error = self.advapi.GetSecurityInfo(handle, 1, _OWNER_INFORMATION | _DACL_INFORMATION,
                                          ctypes.byref(owner), None, ctypes.byref(acl), None, ctypes.byref(descriptor))
        if error:
            raise ctypes.WinError(error)
        try:
            control, revision = wintypes.WORD(), wintypes.DWORD()
            if not self.advapi.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision)):
                raise self.error()
            if not acl or not control.value & 0x1000 or self._sid_text(owner) != self.sid:
                raise PermissionError("output does not have a protected owner-only DACL")
            size = _AclSize()
            if not self.advapi.GetAclInformation(acl, ctypes.byref(size), ctypes.sizeof(size), 2):
                raise self.error()
            if size.count != 1:
                raise PermissionError("output ACL grants access to additional trustees")
            pointer = wintypes.LPVOID()
            if not self.advapi.GetAce(acl, 0, ctypes.byref(pointer)):
                raise self.error()
            ace = ctypes.cast(pointer, ctypes.POINTER(_AllowedAce)).contents
            sid = pointer.value + _AllowedAce.sid_start.offset
            if (ace.kind != 0 or ace.flags != (3 if directory else 0)
                    or ace.mask != _FILE_ALL_ACCESS or self._sid_text(sid) != self.sid):
                raise PermissionError("output ACL is not an exclusive full-access grant to the current user")
        finally:
            self.kernel.LocalFree(descriptor)

    def open(self, path: str, access: int):
        """Open an existing root anchor. Mutations use relative handles only."""
        handle = self.kernel.CreateFileW(path, access, 3, None, 3, 0x00200000 | 0x02000000, None)
        if handle == wintypes.HANDLE(-1).value:
            raise self.error(path)
        return handle

    def relative(self, root, name: str, access: int, *, create: bool = False, directory: bool = False):
        """Open one component beneath a pinned directory, without a pathname retry.

        Win32 CreateFile has no RootDirectory argument. This small NtCreateFile
        adapter is limited to a plain child name and synchronous, no-follow IO.
        """
        plain_name(name)
        encoded = name.encode("utf-16-le", errors="surrogatepass")
        if len(encoded) > 65532:
            raise ValueError("output name is too long")
        buffer = ctypes.create_string_buffer(encoded + b"\0\0")
        unicode_name = _UnicodeString(len(encoded), len(encoded) + 2, ctypes.cast(buffer, wintypes.LPWSTR))
        descriptor = self.security(directory) if create else None
        attributes = _ObjectAttributes(ctypes.sizeof(_ObjectAttributes), root, ctypes.pointer(unicode_name),
                                       0x40 | 0x1000, descriptor, None)  # CASE_INSENSITIVE | DONT_REPARSE
        handle, status = wintypes.HANDLE(), _IoStatusBlock()
        try:
            result = self.ntdll.NtCreateFile(
                ctypes.byref(handle), access | _SYNCHRONIZE, ctypes.byref(attributes), ctypes.byref(status),
                None, _DIRECTORY if directory else 0x80, 3, 2 if create else 1,
                0x00200000 | 0x20 | (0x1 if directory else 0x40), None, 0,
            )  # OPEN_REPARSE_POINT | SYNCHRONOUS_IO_NONALERT | DIRECTORY/NON_DIRECTORY
            if result < 0:
                raise self.error(name, self.ntdll.RtlNtStatusToDosError(result))
            return handle.value
        finally:
            if descriptor:
                self.kernel.LocalFree(descriptor)

    def delete(self, handle) -> None:
        remove = ctypes.c_ubyte(1)  # FILE_DISPOSITION_INFO.DeleteFile
        if not self.kernel.SetFileInformationByHandle(handle, 4, ctypes.byref(remove), ctypes.sizeof(remove)):
            raise self.error()

    def rename(self, handle, root, name: str, *, replace: bool) -> None:
        plain_name(name)
        encoded = name.encode("utf-16-le", errors="surrogatepass")
        buffer = ctypes.create_string_buffer(ctypes.sizeof(_RenameInformation) + len(encoded))
        info = _RenameInformation.from_buffer(buffer)
        info.replace, info.root, info.length = int(replace), root, len(encoded)
        ctypes.memmove(ctypes.addressof(buffer) + _RenameInformation.name.offset, encoded, len(encoded))
        # The Win32 wrapper rejects this relative RootDirectory form on
        # supported Windows builds. Keep both endpoints native and anchored.
        status = _IoStatusBlock()
        result = self.ntdll.NtSetInformationFile(handle, ctypes.byref(status), buffer, len(buffer), 10)
        if result < 0:
            raise self.error(name, self.ntdll.RtlNtStatusToDosError(result))


class WindowsDirectory:
    def __init__(self, path: str) -> None:
        self.path = path
        self.api = _API()
        self.handles: list = []

    def open(self) -> None:
        parts, path = [], self.path
        while True:
            parts.append(path)
            parent = os.path.dirname(path)
            if parent == path:
                break
            path = parent
        try:
            for path in reversed(parts):
                # Parents are pinned before a child is created or opened.
                # Attribute-only handles do not participate in share-access
                # checks. Directory read access makes the no-delete share
                # policy effective for the entire pinned ancestor chain.
                access = _FILE_READ_ATTRIBUTES | _FILE_LIST_DIRECTORY | _FILE_TRAVERSE
                if path == self.path:
                    access |= _READ_CONTROL | _WRITE_DAC | _WRITE_OWNER
                if not self.handles:
                    # Only the volume/share anchor is opened by absolute path.
                    handle = self.api.open(path, access)
                else:
                    parent = self._directory()
                    name = os.path.basename(path)
                    try:
                        handle = self.api.relative(parent, name, access, directory=True)
                    except FileNotFoundError:
                        try:
                            handle = self.api.relative(parent, name, access, create=True, directory=True)
                        except FileExistsError:
                            handle = self.api.relative(parent, name, access, directory=True)
                self.handles.append(handle)
                if not self.api.information(handle).attributes & _DIRECTORY:
                    raise NotADirectoryError(path)
                if path == self.path:
                    self.api.protect(handle, True)
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        while self.handles:
            self.api.kernel.CloseHandle(self.handles.pop())

    def _path(self, name: str) -> str:
        plain_name(name)
        return os.path.join(self.path, name)

    def _directory(self):
        for handle in self.handles:
            self.api.information(handle)
        return self.handles[-1]

    def create(self, name: str) -> int:
        import msvcrt

        root = self._directory()
        # Native GENERIC_WRITE does not include the attribute read needed for
        # the same-handle validation below.
        handle = self.api.relative(root, name, 0x40000000 | _FILE_READ_ATTRIBUTES | _READ_CONTROL | _DELETE, create=True)
        try:
            self._directory()
            self.api.information(handle)
            self.api.assert_private(handle, False)
            fd = msvcrt.open_osfhandle(handle, os.O_WRONLY | os.O_BINARY)
        except BaseException:
            try:
                self.api.delete(handle)
            finally:
                self.api.kernel.CloseHandle(handle)
            raise
        return fd  # ownership of the native handle transfers to the CRT fd

    def read(self, name: str) -> bytes | None:
        import msvcrt

        try:
            handle = self.api.relative(self._directory(), name, 0x80000000 | _READ_CONTROL | _WRITE_DAC | _WRITE_OWNER)
        except FileNotFoundError:
            return None
        try:
            self._directory()
            if self.api.information(handle).attributes & _DIRECTORY:
                raise IsADirectoryError(self._path(name))
            self.api.protect(handle, False)
            fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
        except BaseException:
            self.api.kernel.CloseHandle(handle)
            raise
        with os.fdopen(fd, "rb") as source:
            return source.read()

    def unlink(self, name: str) -> None:
        try:
            handle = self.api.relative(self._directory(), name, _DELETE)
        except FileNotFoundError:
            return
        try:
            self._directory()
            self.api.delete(handle)
        finally:
            self.api.kernel.CloseHandle(handle)

    def publish(self, temporary: str, name: str, *, replace: bool) -> None:
        root = self._directory()
        handle = self.api.relative(root, temporary, _DELETE | _FILE_READ_ATTRIBUTES)
        try:
            self._directory()
            self.api.information(handle)
            # Both source and destination are anchored to existing handles;
            # no absolute pathname is re-opened during atomic publication.
            self.api.rename(handle, root, name, replace=replace)
            self._directory()
        finally:
            self.api.kernel.CloseHandle(handle)
