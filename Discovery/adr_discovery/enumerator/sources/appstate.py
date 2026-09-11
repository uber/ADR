"""Application state -- per profile, rather than per default.

Extensions and per-tool state live under directories a host application
maintains. The rule that matters here is *every* browser profile: a large
share of real shadow AI sits on a second profile, and a scan that reads
Default only reports a clean machine.
"""

from __future__ import annotations

import json

from ...contracts.records import Candidate, Priority
from ..markers import (
    BROWSER_PROFILE_ROOTS,
    CONFIG_FILE_TEMPLATES,
    EDITOR_EXTENSION_ROOTS,
    FIREFOX_PROFILE_ROOTS,
    STATE_ROOTS,
)


def _expand(gate, template: str, homes: tuple[str, ...]) -> list[str]:
    if not template.startswith("~"):
        return [template]
    return [home + template[1:] for home in homes]


def from_app_state(gate, homes: tuple[str, ...]) -> tuple[Candidate, ...]:
    out: list[Candidate] = []

    for template in CONFIG_FILE_TEMPLATES:
        for path in _expand(gate, template, homes):
            if gate.stat(path).ok:
                kind = "shell_profile" if path.endswith(("/.bashrc", "/.zshrc")) else "marker_file"
                out.append(Candidate(kind=kind, path=path, source="app_state:config",
                                     priority=Priority.HOME, detail={"marker": path.rsplit("/", 1)[-1]}))

    for template in STATE_ROOTS:
        for path in _expand(gate, template, homes):
            listing = gate.list_dir(path)
            if not listing.ok:
                continue
            out.append(
                Candidate(kind="state_dir", path=path, source="app_state",
                          priority=Priority.HOME, detail={"entries": len(listing.value)})
            )

    for template in BROWSER_PROFILE_ROOTS:
        for browser_root in _expand(gate, template, homes):
            profiles = gate.list_dir(browser_root)
            if not profiles.ok:
                continue
            for profile in profiles.value:
                if not profile.is_dir:
                    continue
                name = profile.path.rsplit("/", 1)[-1]
                if name != "Default" and not name.startswith("Profile "):
                    continue
                ext_root = profile.path + "/Extensions"
                extensions = gate.list_dir(ext_root)
                if not extensions.ok:
                    continue
                for ext in extensions.value:
                    if not ext.is_dir:
                        continue
                    out.append(
                        Candidate(
                            kind="extension",
                            path=ext.path,
                            source="app_state:browser",
                            priority=Priority.HOME,
                            detail={"extension_id": ext.path.rsplit("/", 1)[-1],
                                    "profile": name, "browser": browser_root},
                        )
                    )

    for template in EDITOR_EXTENSION_ROOTS:
        for root in _expand(gate, template, homes):
            extensions = gate.list_dir(root)
            if not extensions.ok:
                continue
            for ext in extensions.value:
                if not ext.is_dir:
                    continue
                ident, version = _editor_identity(gate, ext.path)
                out.append(Candidate(
                    kind="extension", path=ext.path, source="app_state:editor",
                    priority=Priority.HOME,
                    detail={"extension_id": ident, "version": version, "editor": root},
                ))

    for template in FIREFOX_PROFILE_ROOTS:
        for root in _expand(gate, template, homes):
            profiles = gate.list_dir(root)
            if not profiles.ok:
                continue
            for profile in profiles.value:
                if not profile.is_dir:
                    continue
                extensions = gate.list_dir(profile.path + "/extensions")
                if not extensions.ok:
                    continue
                for ext in extensions.value:
                    if ext.is_dir or ext.path.endswith(".xpi"):
                        ident = ext.path.rsplit("/", 1)[-1].removesuffix(".xpi")
                        out.append(Candidate(
                            kind="extension", path=ext.path, source="app_state:firefox",
                            priority=Priority.HOME,
                            detail={"extension_id": ident, "profile": profile.path,
                                    "browser": "firefox"},
                        ))
    return tuple(out)


def _editor_identity(gate, path: str) -> tuple[str, str | None]:
    raw = gate.read_text(path + "/package.json", limit=1 << 20)
    if raw.ok:
        try:
            manifest = json.loads(raw.value)
            publisher, name = manifest.get("publisher"), manifest.get("name")
            if publisher and name:
                version = manifest.get("version")
                return f"{publisher}.{name}", str(version) if version else None
        except (ValueError, TypeError):
            gate.ledger.probe("extension_manifest", "degraded", path)
    return path.rsplit("/", 1)[-1], None
