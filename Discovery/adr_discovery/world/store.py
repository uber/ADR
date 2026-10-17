"""Private local skill archives, separate from the read-only inventory gate.

POSIX stores use mode 0700/0600. Windows stores use a protected DACL granting
access only to the current user. Publication never exposes a partial zip.
"""

from __future__ import annotations

import os

from .private_output import plain_name, private_directory, write_temporary


class ArchiveStore:
    """A content-addressed directory: a name, once written, is never rewritten."""

    INDEX = "index.jsonl"

    def __init__(self, directory: str) -> None:
        self.directory = os.path.abspath(directory)

    def open(self) -> None:
        with private_directory(self.directory):
            pass

    def path_of(self, name: str) -> str:
        plain_name(name)
        return os.path.join(self.directory, name)

    def has(self, name: str) -> bool:
        return self.read(name) is not None

    def read(self, name: str) -> bytes | None:
        with private_directory(self.directory) as directory:
            return directory.read(name)

    def put_once(self, name: str, data: bytes) -> bool:
        """Atomically publish a complete file without replacing any existing name.

        Windows rename has the required no-overwrite behavior and works on
        filesystems without hard links. POSIX uses link from a private temp.
        """
        plain_name(name)
        with private_directory(self.directory) as directory:
            temporary = write_temporary(directory, data)
            try:
                directory.publish(temporary, name, replace=False)
            except FileExistsError:
                return False
            finally:
                directory.unlink(temporary)
        return True

    def replace(self, name: str, data: bytes) -> None:
        """Atomically replace the mutable index; failed publication leaves no temp."""
        plain_name(name)
        with private_directory(self.directory) as directory:
            temporary = write_temporary(directory, data)
            try:
                directory.publish(temporary, name, replace=True)
            finally:
                directory.unlink(temporary)
