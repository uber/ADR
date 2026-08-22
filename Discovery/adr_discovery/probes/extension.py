"""IDE and browser extensions - where a large share of real shadow AI lives,
and the blind spot in most endpoint inventories."""

import posixpath
from typing import List

from ..base_probe import BaseProbe, Observation
from ..env import DiscoveryEnv

IDE_EXTENSION_DIRS = (("~/.vscode/extensions", "vscode"), ("~/.cursor/extensions", "cursor"))

#: Chromium-family browser roots. Every one of them keeps extensions per
#: profile, and most shadow AI lives on a profile that is not Default.
CHROMIUM_ROOTS = {
    "darwin": [
        ("chrome", "~/Library/Application Support/Google/Chrome"),
        ("edge", "~/Library/Application Support/Microsoft Edge"),
        ("brave", "~/Library/Application Support/BraveSoftware/Brave-Browser"),
        ("arc", "~/Library/Application Support/Arc/User Data"),
        ("vivaldi", "~/Library/Application Support/Vivaldi"),
    ],
    "windows": [
        ("chrome", "%LOCALAPPDATA%/Google/Chrome/User Data"),
        ("edge", "%LOCALAPPDATA%/Microsoft/Edge/User Data"),
        ("brave", "%LOCALAPPDATA%/BraveSoftware/Brave-Browser/User Data"),
    ],
    "linux": [
        ("chrome", "~/.config/google-chrome"),
        ("chromium", "~/.config/chromium"),
        ("brave", "~/.config/BraveSoftware/Brave-Browser"),
    ],
}

FIREFOX_ROOTS = {
    "darwin": "~/Library/Application Support/Firefox/Profiles",
    "windows": "%APPDATA%/Mozilla/Firefox/Profiles",
    "linux": "~/.mozilla/firefox",
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
                    install_method="ide_extension",
                    pkg_identity="ext:%s:%s" % (host, extension_id), owner=env.user,
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
        out: List[Observation] = []
        for browser, root in CHROMIUM_ROOTS.get(env.platform, []):
            base = env.expand(root)
            if not env.is_dir(base):
                continue
            for profile in self._profiles(env, base):
                out.extend(self._chromium_profile(env, browser, profile))
        out.extend(self._firefox(env))
        return out

    def _profiles(self, env: DiscoveryEnv, base: str) -> List[str]:
        """Every profile directory, not just Default."""
        found = []
        for name in env.listdir(base):
            if name == "Default" or name.startswith("Profile "):
                candidate = posixpath.join(base, name, "Extensions")
                if env.is_dir(candidate):
                    found.append(candidate)
        direct = posixpath.join(base, "Extensions")
        if env.is_dir(direct):
            found.append(direct)
        return found

    def _chromium_profile(self, env: DiscoveryEnv, browser: str, base: str) -> List[Observation]:
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
                entry = self.catalog.match("extension_ids", extension_id)
                out.append(Observation(
                    probe=self.name, channel="filesystem", kind="extension",
                    name=self._display_name(env, path, manifest, extension_id), path=path,
                    matched_on="%s:%s" % (browser, extension_id),
                    catalog_id=(entry or {}).get("id"),
                    version=str(manifest.get("version") or version),
                    realpath=env.realpath(path), install_root=base,
                    install_method="browser_extension",
                    pkg_identity="%s:%s:%s" % (browser, base, extension_id), owner=env.user,
                    extra={"host_app": browser, "extension_id": extension_id,
                           "host_permissions": permissions, "profile": base},
                    confidence=0.45,
                ))
        return out

    def _firefox(self, env: DiscoveryEnv) -> List[Observation]:
        """Firefox ships extensions as XPI archives, read without unpacking."""
        import json as json_mod
        import zipfile

        base = env.expand(FIREFOX_ROOTS.get(env.platform, ""))
        if not base or not env.is_dir(base):
            return []
        out: List[Observation] = []
        for profile in env.listdir(base):
            folder = posixpath.join(base, profile, "extensions")
            for name in env.listdir(folder):
                if not name.endswith(".xpi"):
                    continue
                path = posixpath.join(folder, name)
                try:
                    with zipfile.ZipFile(str(env.real(path))) as archive:
                        manifest = json_mod.loads(archive.read("manifest.json").decode("utf-8", "replace"))
                except Exception as exc:
                    self.error(env, path, "unreadable xpi: %s" % exc)
                    continue
                permissions = (list(manifest.get("host_permissions") or [])
                               + list(manifest.get("permissions") or []))
                out.append(Observation(
                    probe=self.name, channel="filesystem", kind="extension",
                    name=str(manifest.get("name", name)), path=path,
                    matched_on="firefox:%s" % name, version=str(manifest.get("version", "")),
                    realpath=env.realpath(path), install_root=folder,
                    install_method="xpi", pkg_identity="firefox:%s" % name, owner=env.user,
                    extra={"host_app": "firefox", "host_permissions": permissions},
                    confidence=0.45,
                ))
        return out
