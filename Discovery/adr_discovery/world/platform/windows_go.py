"""Read the inline Go build-info format from a bounded PE image.

Format reference: https://go.dev/src/debug/buildinfo/buildinfo.go
No discovered executable or user-managed Go toolchain is executed.
"""

from __future__ import annotations

import re
import struct


class UnsupportedBuildInfo(ValueError):
    pass


def _string(data: bytes, offset: int) -> tuple[bytes, int]:
    size = 0
    for index in range(10):
        if offset + index >= len(data):
            raise ValueError("truncated string length")
        byte = data[offset + index]
        size |= (byte & 127) << (index * 7)
        if byte < 128:
            start = offset + index + 1
            if size > 1 << 20 or start + size > len(data):
                raise ValueError("build-info string outside bounded data")
            return data[start:start + size], start + size
    raise ValueError("invalid string length")


def go_module(data: bytes) -> tuple[str, str] | None:
    """Return the main module only after validating its PE section and record."""
    if len(data) < 64 or data[:2] != b"MZ":
        return None
    pe = struct.unpack_from("<I", data, 60)[0]
    if pe < 64 or pe + 24 > len(data) or data[pe:pe + 4] != b"PE\0\0":
        return None
    count = struct.unpack_from("<H", data, pe + 6)[0]
    optional = struct.unpack_from("<H", data, pe + 20)[0]
    section = pe + 24 + optional
    if not 0 < count <= 96 or optional < 2 or section + count * 40 > len(data):
        return None
    if struct.unpack_from("<H", data, pe + 24)[0] not in (0x10B, 0x20B):
        return None
    for index in range(count):
        header = section + index * 40
        virtual_size, address, raw_size, raw = struct.unpack_from("<IIII", data, header + 8)
        flags = struct.unpack_from("<I", data, header + 36)[0]
        # Match Go's initialized, readable, writable data-section selection.
        if not address or not raw_size or flags & ~0x00600000 != 0xC0000040:
            continue
        if raw < section + count * 40 or raw >= len(data):
            raise ValueError("Go data section outside read budget")
        chunk = data[raw:min(raw + raw_size, len(data))]
        magic = b"\xff Go buildinf:"
        offset = chunk.find(magic)
        while offset >= 0 and ((address + offset) % 16 or offset >= virtual_size):
            offset = chunk.find(magic, offset + 1)
        if offset < 0:
            if raw + raw_size > len(data):
                raise ValueError("Go data section exceeds read budget")
            return None
        if offset + 32 > len(chunk):
            raise ValueError("truncated Go header")
        if chunk[offset + 15] != 2:
            raise UnsupportedBuildInfo("only Go 1.18+ inline little-endian build info is supported")
        version, cursor = _string(chunk, offset + 32)
        module, _ = _string(chunk, cursor)
        if not re.fullmatch(rb"go1\.[0-9]+[^\x00\r\n\t ]*", version):
            raise ValueError("invalid Go version")
        if len(module) < 33 or module[-17:-16] != b"\n":
            raise ValueError("invalid module framing")
        lines = module[16:-16].decode("utf-8").splitlines()
        mains = [line.split("\t") for line in lines if line.startswith("mod\t")]
        paths = [line for line in lines if line.startswith("path\t")]
        if len(mains) != 1 or len(paths) != 1 or len(mains[0]) not in (3, 4):
            raise ValueError("invalid main module record")
        _, name, release, *_ = mains[0]
        if not name or any(char.isspace() or ord(char) < 32 for char in name):
            raise ValueError("invalid module name")
        if not release or any(char.isspace() or ord(char) < 32 for char in release):
            raise ValueError("invalid module version")
        return name, release
    return None
