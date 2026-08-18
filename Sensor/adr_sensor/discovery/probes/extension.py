"""IDE and browser extensions - where a large share of real shadow AI lives,
and the blind spot in most endpoint inventories."""

import posixpath
from typing import List

from ..base_probe import BaseProbe, Observation
from ..env import DiscoveryEnv

IDE_EXTENSION_DIRS = (("~/.vscode/extensions", "vscode"), ("~/.cursor/extensions", "cursor"))

CHROME_PROFILE_DIRS = {
    "darwin": "~/Library/Application Support/Google/Chrome/Default/Extensions",
    "windows": "%LOCALAPPDATA%/Google/Chrome/User Data/Default/Extensions",
    "linux": "~/.config/google-chrome/Default/Extensions",
}


class ExtensionProbe(BaseProbe):
    name = "extension"

    def collect(self, env: DiscoveryEnv) -> List[Observation]:
        out = self._ide(env)
        out.extend(self._browser(env))
        return out

    def _ide(self, env: DiscoveryEnv) -> List[Observation]:
        out: List[Observation] = []
        for directory, host in IDE_EXTENSION_DIRS:
            base = env.expand(directory)
            for name in env.listdir(base):
                folder = posixpath.join(base, name)
                manifest = self.read_json(env, posixpath.join(folder, "package.json"))
                if not isinstance(manifest, dict):
                    continue
                extension_id = "%s.%s" % (manifest.get("publisher", ""), manifest.get("name", ""))
                entry = self.catalog.match("extension_ids", extension_id)
                out.append(Observation(
                    probe=self.name, channel="filesystem", kind="extension",
                    name=((entry or {}).get("name") or manifest.get("displayName")
                          or manifest.get("name") or name),
                    path=folder, matched_on="extension:%s" % extension_id,
                    catalog_id=(entry or {}).get("id"), version=manifest.get("version"),
                    vendor=(entry or {}).get("vendor") or manifest.get("publisher"),
                    realpath=env.realpath(folder), install_root=base,
                    install_method="ide_extension", pkg_identity="ext:%s" % extension_id,
                    owner=env.user,
                    extra={"host_app": host, "extension_id": extension_id,
                           "host_permissions": list(manifest.get("host_permissions") or [])},
                    confidence=0.5,
                ))
        return out

    def _display_name(self, env: DiscoveryEnv, path: str, manifest, extension_id: str) -> str:
        """Resolve a ``__MSG_name__`` placeholder through the extension's locale.

        Chrome extensions localize their own name, so the raw manifest value is
        frequently a placeholder. Reporting it verbatim gives an operator a list
        of ``__MSG_extName__`` rows, which is an inventory nobody can act on.
        """
        name = str(manifest.get("name", extension_id))
        if not name.startswith("__MSG_"):
            return name
        key = name[6:-2] if name.endswith("__") else name[6:]
        locale = str(manifest.get("default_locale") or "en")
        for candidate in (locale, "en", "en_US"):
            messages = self.read_json(env, posixpath.join(path, "_locales", candidate, "messages.json"))
            if isinstance(messages, dict):
                for message_key, record in messages.items():
                    if message_key.lower() == key.lower() and isinstance(record, dict):
                        return str(record.get("message") or name)
        return extension_id

    def _browser(self, env: DiscoveryEnv) -> List[Observation]:
        base = env.expand(CHROME_PROFILE_DIRS.get(env.platform, ""))
        if not base or not env.is_dir(base):
            return []
        out: List[Observation] = []
        for extension_id in env.listdir(base):
            folder = posixpath.join(base, extension_id)
            for version in env.listdir(folder):
                manifest = self.read_json(env, posixpath.join(folder, version, "manifest.json"))
                if not isinstance(manifest, dict):
                    continue
                permissions = (list(manifest.get("host_permissions") or [])
                               + list(manifest.get("permissions") or []))
                path = posixpath.join(folder, version)
                out.append(Observation(
                    probe=self.name, channel="filesystem", kind="extension",
                    name=self._display_name(env, path, manifest, extension_id), path=path,
                    matched_on="chrome:%s" % extension_id,
                    version=str(manifest.get("version") or version),
                    realpath=env.realpath(path), install_root=base,
                    install_method="browser_extension", pkg_identity="chrome:%s" % extension_id,
                    owner=env.user,
                    extra={"host_app": "chrome", "extension_id": extension_id,
                           "host_permissions": permissions},
                    confidence=0.45,
                ))
        return out
