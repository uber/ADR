"""Explicit, strict text encodings; diagnostics never include source bytes."""

from __future__ import annotations


def decode_text(data: bytes, *, allow_utf16: bool = False) -> str:
    encoding = "utf-8-sig"
    if data.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        raise ValueError("UTF-32 is not supported")
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        if not allow_utf16:
            raise ValueError("UTF-16 is not supported for this format")
        encoding = "utf-16"
    try:
        return data.decode(encoding, errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError(f"invalid {encoding} encoding at byte {exc.start}") from None
