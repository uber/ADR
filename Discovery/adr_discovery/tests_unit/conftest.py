"""Fixture worlds.

A fixture directory and a live machine are interchangeable below M1, so
every case here builds a world on disk and drives the real pipeline over
it. Nothing is mocked; the gate reads these trees exactly as it reads `/`.
"""

from __future__ import annotations

import json
import os

import pytest

from adr_discovery.catalog.load import loads as load_catalog
from adr_discovery.coverage.ledger import Ledger
from adr_discovery.world.budget import Budget
from adr_discovery.world.gate import Gate
from adr_discovery.world.platform.base import FixtureProviders

PACKAGE = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


class World:
    """A machine on disk, plus the non-filesystem surfaces beside it."""

    def __init__(self, root: str) -> None:
        self.root = root
        self._restore: list[str] = []

    def cleanup(self) -> None:
        for path in self._restore:
            try:
                os.chmod(path, 0o755)
            except OSError:
                pass

    def file(self, path: str, body: str = "") -> "World":
        full = self.root + path
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as fh:
            fh.write(body)
        return self

    def json(self, path: str, document) -> "World":
        return self.file(path, json.dumps(document))

    def binary(self, path: str, body: str) -> "World":
        """Exact bytes, plus the executable bit.

        `exe` writes a shell wrapper of its own devising, which is fine for
        version probes and useless for a case that asserts on a hash.
        """
        self.file(path, body)
        os.chmod(self.root + path, 0o755)
        return self

    def exe(self, path: str, prints: str) -> "World":
        self.file(path, f"#!/bin/sh\necho {prints!r}\n")
        os.chmod(self.root + path, 0o755)
        return self

    def dir(self, path: str) -> "World":
        os.makedirs(self.root + path, exist_ok=True)
        return self

    def unreadable(self, path: str) -> "World":
        """Make a directory unreadable, and restore it at teardown.

        Without the restore, pytest cannot clean its own tmp tree and every
        later run inherits the mess.
        """
        os.chmod(self.root + path, 0o000)
        self._restore.append(self.root + path)
        return self

    def symlink(self, path: str, target: str, outside: bool = False) -> "World":
        """`target` is a path *inside* this world unless `outside` is set.

        The distinction matters: a link out of the world is refused for
        containment before the deny-list is ever consulted, so a case about
        the deny-list has to stay inside.
        """
        full = self.root + path
        os.makedirs(os.path.dirname(full), exist_ok=True)
        os.symlink(target if outside else self.root + target, full)
        return self

    def surface(self, name: str, rows) -> "World":
        """processes | sockets | packages | applications | dns | execjournal"""
        return self.json(f"/{name}.json", rows)

    def gate(self, **kwargs) -> Gate:
        kwargs.setdefault("ledger", Ledger())
        kwargs.setdefault("budget", Budget(max_entries=50_000))
        kwargs.setdefault("providers", FixtureProviders())
        kwargs.setdefault("env", {"PATH": "/usr/bin:/bin"})
        return Gate(self.root, **kwargs)


@pytest.fixture
def world(tmp_path):
    built = World(str(tmp_path))
    try:
        yield built
    finally:
        built.cleanup()


@pytest.fixture(scope="session")
def catalog():
    with open(os.path.join(PACKAGE, "catalog", "catalog.json"), encoding="utf-8") as fh:
        return load_catalog(fh.read())
