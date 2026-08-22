"""Agents that live somewhere other than this operating system's own tree.

A developer laptop can be reported as agent-free while the whole toolchain runs
one filesystem boundary away: inside a devcontainer, inside WSL, or on a remote
host the editor is attached to. Those are still agents with access to the
repository, and an inventory that cannot say so is misleading rather than empty.
"""

import json
import posixpath
from typing import Any, Dict, List, Optional

from ..base_probe import BaseProbe, Observation
from ..env import DiscoveryEnv

PROJECT_ROOTS = ("~/dev", "~/src", "~/workspace", "~/code")

#: Keys in a devcontainer definition that can install a tool.
INSTALL_KEYS = ("postCreateCommand", "postStartCommand", "onCreateCommand", "updateContentCommand")


class LocationProbe(BaseProbe):
    name = "location"

    def collect(self, env: DiscoveryEnv) -> List[Observation]:
        out: List[Observation] = []
        for root in PROJECT_ROOTS:
            for logical, _ in env.walk(env.expand(root), max_depth=3):
                base = posixpath.basename(logical)
                if base == "devcontainer.json":
                    out.extend(self._devcontainer(env, logical))
                elif base.endswith(".code-workspace"):
                    out.extend(self._remote_workspace(env, logical))
        return out

    # -- containers -------------------------------------------------------

    def _devcontainer(self, env: DiscoveryEnv, logical: str) -> List[Observation]:
        data = self._read_jsonc(env, logical)
        if not isinstance(data, dict):
            return []
        text = " ".join(str(data.get(key, "")) for key in INSTALL_KEYS)
        text += " " + " ".join(str(k) for k in (data.get("features") or {}))
        text += " " + str(data.get("image", ""))
        extensions = self._extensions(data)
        out = []
        for entry in self.catalog.entries:
            if not self._mentions(entry, text, extensions):
                continue
            out.append(Observation(
                probe=self.name, channel="config", kind=entry.get("kind", "cli_agent"),
                name=entry["name"], path=logical, matched_on="devcontainer",
                catalog_id=entry["id"], vendor=entry.get("vendor"),
                install_method="container", owner=env.user,
                identity_hint="location:%s:%s" % (entry["id"], logical),
                extra={"flags": ["container_declared"], "location": "devcontainer",
                       "project": posixpath.dirname(posixpath.dirname(logical))},
                confidence=0.5,
            ))
        return out

    def _extensions(self, data: Dict[str, Any]) -> List[str]:
        customizations = data.get("customizations") or {}
        vscode = customizations.get("vscode") or {}
        return [str(item).lower() for item in (vscode.get("extensions") or [])]

    def _mentions(self, entry: Dict[str, Any], text: str, extensions: List[str]) -> bool:
        lowered = text.lower()
        for package in entry.get("npm_packages", []) + entry.get("pypi_packages", []):
            if package.lower() in lowered:
                return True
        for extension_id in entry.get("extension_ids", []):
            if extension_id.lower() in extensions:
                return True
        for binary in entry.get("binaries", []):
            if (" %s " % binary) in (" %s " % lowered):
                return True
        return False

    # -- remote hosts -----------------------------------------------------

    def _remote_workspace(self, env: DiscoveryEnv, logical: str) -> List[Observation]:
        """An editor workspace attached to another machine.

        The agent runs there, not here. Reporting it as a local install would
        overstate this endpoint; dropping it would lose the fact entirely.
        """
        data = self._read_jsonc(env, logical)
        if not isinstance(data, dict):
            return []
        authority = str(data.get("remoteAuthority", ""))
        if not authority:
            return []
        host = authority.split("+", 1)[-1]
        extensions = self._extensions(data)
        out = []
        for entry in self.catalog.entries:
            if not self._mentions(entry, str(data.get("settings", "")), extensions):
                continue
            out.append(Observation(
                probe=self.name, channel="config", kind=entry.get("kind", "cli_agent"),
                name=entry["name"], path=logical, matched_on="remote_workspace",
                catalog_id=entry["id"], vendor=entry.get("vendor"),
                install_method="remote", owner=env.user,
                identity_hint="location:%s:%s" % (entry["id"], host),
                extra={"flags": ["remote"], "location": "remote:%s" % host, "host": host},
                confidence=0.5,
            ))
        return out

    def _read_jsonc(self, env: DiscoveryEnv, logical: str) -> Optional[Any]:
        """Devcontainer and workspace files are JSON with comments in practice."""
        result = env.read(logical)
        if not result:
            self.error(env, logical, result.error or "unreadable")
            return None
        try:
            return json.loads(strip_jsonc(result.text))
        except ValueError as exc:
            self.error(env, logical, "malformed json: %s" % exc)
            return None


def strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas, outside of strings."""
    out = []
    in_string = False
    escaped = False
    index = 0
    while index < len(text):
        char = text[index]
        if in_string:
            out.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            out.append(char)
            index += 1
            continue
        if text.startswith("//", index):
            index = text.find("\n", index)
            if index == -1:
                break
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index)
            index = len(text) if end == -1 else end + 2
            continue
        out.append(char)
        index += 1
    cleaned = "".join(out)
    # trailing commas before a closing brace or bracket
    result = []
    for position, char in enumerate(cleaned):
        if char == ",":
            rest = cleaned[position + 1:].lstrip()
            if rest[:1] in ("}", "]"):
                continue
        result.append(char)
    return "".join(result)
