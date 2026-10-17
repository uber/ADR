"""Read Windows language-package manifests without running user toolchains."""

from __future__ import annotations

import json

from .base import LanguagePackages, Package
from .windows_go import UnsupportedBuildInfo, go_module
from .windows_locations import _env, _unique, absolute


class WindowsLanguagePackages(LanguagePackages):
    """Reuse manifest readers with Windows storage roots, including overrides."""

    def collect(self, gate, profiles) -> list[Package]:
        env = _env(gate)
        homes = tuple(profile.home for profile in profiles)
        node = [profile.roaming + "/npm/node_modules" for profile in profiles]
        node.extend(home + "/node_modules" for home in homes)
        pipx = [profile.local + "/pipx/pipx/venvs" for profile in profiles]
        pipx.extend(home + suffix for home in homes for suffix in ("/pipx/venvs", "/.local/pipx/venvs"))
        uv = [profile.roaming + "/uv/data/tools" for profile in profiles]
        # Environment overrides describe the caller's installations, not each
        # discovered user's. Query each override once as a separate root.
        for key, suffix, roots in (("NPM_CONFIG_PREFIX", "/node_modules", node),
                                   ("PIPX_HOME", "/venvs", pipx), ("UV_TOOL_DIR", "", uv)):
            value = absolute(env.get(key, ""))
            if value:
                roots.insert(0, value + suffix)
        self.NODE_ROOTS = _unique(node)
        found = self._npm(gate, homes)
        found.extend(self._venvs(gate, homes, _unique(pipx), "pipx"))
        found.extend(self._venvs(gate, homes, _unique(uv), "uv"))
        found.extend(self._cargo(gate, homes))
        found.extend(self._python(gate, profiles))
        found.extend(self._go(gate, homes))
        return list(dict.fromkeys(found))

    def _go(self, gate, homes) -> list[Package]:
        env = _env(gate)
        roots = [home + "/go/bin" for home in homes]
        roots.extend(path + "/bin" for item in env.get("GOPATH", "").split(";")
                     if (path := absolute(item)))
        roots.append(absolute(env.get("GOBIN", "")))
        found = []
        for root in _unique(roots):
            listing = gate.list_dir(root)
            if not listing.ok:
                continue
            for entry in listing.value:
                if entry.is_dir or not entry.path.casefold().endswith(".exe"):
                    continue
                raw = gate.read_bytes(entry.path, limit=8 << 20)
                if not raw.ok:
                    continue
                try:
                    module = go_module(raw.value)
                except UnsupportedBuildInfo:
                    gate.ledger.unavailable("go_packages", "legacy/unknown Go build-info encoding")
                    continue
                except ValueError as exc:
                    gate.ledger.probe("go_packages", "degraded", str(exc))
                    continue
                if module:
                    found.append(Package("go", module[0], module[1], entry.path))
        return found

    def _python(self, gate, profiles) -> list[Package]:
        """Only bounded, known Python install roots; never search user documents."""
        out = []
        for profile in profiles:
            for root, suffix in ((profile.roaming + "/Python", "/site-packages"),
                                 (profile.local + "/Programs/Python", "/Lib/site-packages")):
                versions = gate.list_dir(root)
                if not versions.ok:
                    continue
                for version in versions.value:
                    if not version.is_dir:
                        continue
                    packages = gate.list_dir(version.path + suffix)
                    if not packages.ok:
                        continue
                    for package in packages.value:
                        if not package.is_dir or not package.path.casefold().endswith(".dist-info"):
                            continue
                        raw = gate.read_text(package.path + "/METADATA", limit=1 << 20)
                        if not raw.ok:
                            continue
                        fields = {}
                        for line in raw.value.splitlines():
                            if not line:
                                break
                            key, sep, value = line.partition(":")
                            if sep and key in {"Name", "Version"}:
                                fields.setdefault(key, value.strip())
                        if fields.get("Name"):
                            out.append(Package("pip", fields["Name"], fields.get("Version"),
                                               package.path))
        return out

    def _cargo(self, gate, homes) -> list[Package]:
        roots = [home + "/.cargo" for home in homes]
        override = absolute(_env(gate).get("CARGO_HOME", ""))
        if override:
            roots.insert(0, override)
        out = []
        for root in _unique(roots):
            raw = gate.read_text(root + "/.crates2.json", limit=4 << 20)
            if not raw.ok:
                continue
            try:
                document = json.loads(raw.value)
                installs = document.get("installs") if isinstance(document, dict) else None
                if not isinstance(installs, dict):
                    raise ValueError("expected installs mapping")
            except ValueError:
                gate.ledger.probe("cargo", "degraded", root + "/.crates2.json")
                continue
            for key in installs:
                parts = key.split()
                if parts:
                    out.append(Package("cargo", parts[0], parts[1] if len(parts) > 1 else None,
                                       root + "/bin"))
        return out
