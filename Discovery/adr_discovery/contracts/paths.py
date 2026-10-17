"""Pure path operations for records, independent of the collector's host OS.

Drive-qualified and UNC paths use Windows comparisons. POSIX paths keep
their spelling and case; URLs and registry identifiers are not file paths.
Native file access and resolution remain the responsibility of world/.
"""

from __future__ import annotations

import ntpath
import posixpath


def is_windows(path: str) -> bool:
    return (
        len(path) >= 3 and path[0].isalpha() and path[1] == ":" and path[2] in "/\\"
    ) or path.startswith(("\\\\", "//"))


def logical(path: str) -> str:
    """Use forward separators for Windows records, preserving display case."""
    return path.replace("\\", "/") if is_windows(path) else path


def key(path: str) -> str:
    """Comparison key, without consulting the local filesystem."""
    return ntpath.normcase(ntpath.normpath(path)).replace("\\", "/") if is_windows(path) else path


def basename(path: str) -> str:
    return logical(path).rstrip("/").rsplit("/", 1)[-1]


def parent(path: str) -> str:
    value = logical(path)
    if is_windows(value):
        return ntpath.dirname(value).replace("\\", "/")
    return posixpath.dirname(value)


def is_absolute(path: str) -> bool:
    return is_windows(path) or path.startswith("/")


def contains(root: str, path: str, *, proper: bool = False) -> bool:
    if not root or not path:
        return False
    root_key, path_key = key(root).rstrip("/"), key(path).rstrip("/")
    return (not proper and root_key == path_key) or path_key.startswith(root_key + "/")


def relative_to(path: str, root: str) -> str | None:
    if not contains(root, path):
        return None
    if is_windows(root):
        return ntpath.relpath(path, root).replace("\\", "/")
    return posixpath.relpath(path, root)


def join(root: str, relative: str) -> str:
    """Join a path using the root's syntax; an absolute child stays absolute."""
    if is_windows(root):
        return logical(ntpath.join(root, relative))
    return posixpath.join(root, relative)
