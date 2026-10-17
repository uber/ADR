"""Private output files, with atomic publication and platform-specific access control.

POSIX uses a pinned directory fd and modes. Windows uses native handles and a
protected DACL; chmod is not an access-control implementation on Windows.
"""

from __future__ import annotations

import os
import secrets
from contextlib import contextmanager


def plain_name(name: str) -> None:
    """Keep callers inside the directory, including Windows device/stream names."""
    reserved = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
                *(f"LPT{i}" for i in range(1, 10))}
    if (not name or name in (".", "..") or any(c in name for c in "/\\:\0")
            or name.rstrip(" .") != name or name.split(".", 1)[0].upper() in reserved):
        raise ValueError(f"not a plain output file name: {name!r}")


class _PosixDirectory:
    def __init__(self, path: str) -> None:
        self.path = path
        self.fd = -1

    def open(self) -> None:
        os.makedirs(self.path, mode=0o700, exist_ok=True)
        self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            before = os.fstat(self.fd)
            current = os.stat(self.path, follow_symlinks=False)
            if (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino):
                raise OSError("output directory changed during validation")
            os.fchmod(self.fd, 0o700)
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def create(self, name: str) -> int:
        plain_name(name)
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
        try:
            os.fchmod(fd, 0o600)
        except BaseException:
            os.close(fd)
            self.unlink(name)
            raise
        return fd

    def read(self, name: str) -> bytes | None:
        plain_name(name)
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.fd)
        except FileNotFoundError:
            return None
        with os.fdopen(fd, "rb") as source:
            return source.read()

    def unlink(self, name: str) -> None:
        plain_name(name)
        try:
            os.unlink(name, dir_fd=self.fd)
        except FileNotFoundError:
            pass

    def publish(self, temporary: str, name: str, *, replace: bool) -> None:
        plain_name(temporary)
        plain_name(name)
        if replace:
            os.replace(temporary, name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
        else:
            os.link(temporary, name, src_dir_fd=self.fd, dst_dir_fd=self.fd, follow_symlinks=False)


@contextmanager
def private_directory(path: str):
    """Hold the validated directory until every operation inside it finishes."""
    absolute = os.path.abspath(path)
    if os.name == "nt":
        from ._win_output import WindowsDirectory

        directory = WindowsDirectory(absolute)
    else:
        directory = _PosixDirectory(absolute)
    directory.open()
    try:
        yield directory
    finally:
        directory.close()


def write_bytes(directory, name: str, data: bytes) -> None:
    """Create exclusively, removing our partial file if writing fails."""
    fd = directory.create(name)
    try:
        with os.fdopen(fd, "wb") as target:
            fd = -1
            target.write(data)
            target.flush()
            os.fsync(target.fileno())
    except BaseException:
        if fd >= 0:
            os.close(fd)
        directory.unlink(name)
        raise


def write_temporary(directory, data: bytes) -> str:
    """A private file in the publication directory, hence on the same volume."""
    for _ in range(10):
        name = ".partial-" + secrets.token_hex(16)
        try:
            write_bytes(directory, name, data)
        except FileExistsError:
            continue
        return name
    raise FileExistsError("could not allocate a unique output temporary file")


def write_private(output_dir: str, filename: str, text: str) -> str:
    plain_name(filename)
    with private_directory(output_dir) as directory:
        write_bytes(directory, filename, text.encode("utf-8"))
    return os.path.join(output_dir, filename)
