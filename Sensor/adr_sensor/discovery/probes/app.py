"""Desktop AI applications, from whichever registry the platform maintains."""

import plistlib
import posixpath
from typing import Any, Dict, List, Optional

from ..base_probe import BaseProbe, Observation
from ..env import DiscoveryEnv
from ..paths import install_root, owner_of

MAC_APP_DIRS = ("/Applications", "~/Applications", "/opt/homebrew-cask/Caskroom")
LINUX_DESKTOP_DIRS = ("/usr/share/applications", "~/.local/share/applications")
APPIMAGE_DIRS = ("~/Downloads", "~/Applications", "~/.local/bin", "/opt")


class AppProbe(BaseProbe):
    name = "app"

    def collect(self, env: DiscoveryEnv) -> List[Observation]:
        if env.platform == "darwin":
            return self._macos(env)
        if env.platform == "windows":
            return self._windows(env)
        return self._linux(env)

    # -- macOS ------------------------------------------------------------

    def _macos(self, env: DiscoveryEnv) -> List[Observation]:
        out: List[Observation] = []
        for directory in MAC_APP_DIRS:
            base = env.expand(directory)
            for name in env.listdir(base):
                if not name.endswith(".app"):
                    continue
                bundle = posixpath.join(base, name)
                info = self._plist(env, posixpath.join(bundle, "Contents/Info.plist"))
                if info is None:
                    continue
                out.extend(self._bundle_observations(env, bundle, name, info))
        return out

    def _bundle_observations(self, env, bundle, name, info) -> List[Observation]:
        bundle_id = str(info.get("CFBundleIdentifier", ""))
        entry = self.catalog.match("bundle_ids", bundle_id)
        realpath = env.realpath(bundle)
        signature = self._signature(env, bundle)
        base = Observation(
            probe=self.name, channel="filesystem", kind=(entry or {}).get("kind", "app"),
            name=(entry or {}).get("name") or name[:-4], path=bundle,
            matched_on=("bundle_id:%s" % bundle_id) if entry else "app_bundle",
            catalog_id=(entry or {}).get("id"),
            version=info.get("CFBundleShortVersionString"),
            vendor=(entry or {}).get("vendor"), realpath=realpath,
            install_root=install_root(realpath), install_method="dmg",
            signature=signature, owner=owner_of(bundle, env),
            extra={"bundle_id": bundle_id, "executable": str(info.get("CFBundleExecutable", ""))},
            confidence=0.55,
        )
        out = [base]
        if signature.get("team_id"):
            out.append(Observation(
                probe=self.name, channel="code_signature", kind=base.kind, name=base.name,
                path=bundle, matched_on="team_id:%s" % signature["team_id"],
                catalog_id=base.catalog_id, realpath=realpath, install_root=base.install_root,
                signature=signature, owner=base.owner, confidence=0.5,
            ))
        return out

    def _plist(self, env: DiscoveryEnv, logical: str) -> Optional[Dict[str, Any]]:
        result = env.read(logical)
        if not result:
            return None
        try:
            # Binary plists are the norm on macOS, so this must be the raw bytes.
            return plistlib.loads(result.data)
        except Exception as exc:
            self.error(env, logical, "malformed plist: %s" % exc)
            return None

    def _signature(self, env: DiscoveryEnv, path: str) -> Dict[str, Any]:
        out = env.run(["codesign", "--display", "--verbose", path], timeout=2.0)
        if not out:
            return {"signed": False}
        team = None
        for line in out.splitlines():
            if line.startswith("TeamIdentifier="):
                team = line.split("=", 1)[1].strip()
        return {"signed": bool(team) and team != "not set", "team_id": team}

    # -- Windows ----------------------------------------------------------

    def _windows(self, env: DiscoveryEnv) -> List[Observation]:
        out: List[Observation] = []
        for record in env.registry:
            display = str(record.get("DisplayName", ""))
            entry = self.catalog.match("registry_names", display)
            location = str(record.get("InstallLocation", ""))
            publisher = record.get("Publisher")
            out.append(Observation(
                probe=self.name, channel="package_registry", kind=(entry or {}).get("kind", "app"),
                name=(entry or {}).get("name") or display,
                path=location or str(record.get("key", "")),
                matched_on="registry:%s" % display, catalog_id=(entry or {}).get("id"),
                version=record.get("DisplayVersion"),
                vendor=(entry or {}).get("vendor") or publisher,
                realpath=env.realpath(location) if location else None,
                install_root=install_root(location), install_method="msi",
                pkg_identity="registry:%s" % display, owner=env.user,
                signature={"signed": bool(publisher), "publisher": publisher},
                confidence=0.6,
            ))
        programs = env.expand("%LOCALAPPDATA%/Programs")
        for name in env.listdir(programs):
            entry = self.catalog.match("registry_names", name)
            if not entry:
                continue
            path = posixpath.join(programs, name)
            out.append(Observation(
                probe=self.name, channel="filesystem", kind=entry.get("kind", "app"),
                name=entry["name"], path=path, matched_on="programs_dir:%s" % name,
                catalog_id=entry["id"], vendor=entry.get("vendor"),
                realpath=env.realpath(path), install_root=install_root(path),
                install_method="msi", owner=env.user, confidence=0.5,
            ))
        return out

    # -- Linux ------------------------------------------------------------

    def _linux(self, env: DiscoveryEnv) -> List[Observation]:
        out: List[Observation] = []
        for directory in LINUX_DESKTOP_DIRS:
            base = env.expand(directory)
            for name in env.listdir(base):
                entry = self.catalog.match("desktop_ids", name)
                if not entry:
                    continue
                path = posixpath.join(base, name)
                out.append(Observation(
                    probe=self.name, channel="filesystem", kind=entry.get("kind", "app"),
                    name=entry["name"], path=path, matched_on="desktop:%s" % name,
                    catalog_id=entry["id"], vendor=entry.get("vendor"),
                    realpath=env.realpath(path), install_root=install_root(path),
                    install_method="deb", owner=env.user, confidence=0.5,
                ))
        for base, method in (("/var/lib/flatpak/app", "flatpak"), ("/snap", "snap")):
            for name in env.listdir(base):
                entry = (self.catalog.match("desktop_ids", name + ".desktop")
                         or self.catalog.match("binaries", name))
                if not entry:
                    continue
                path = posixpath.join(base, name)
                out.append(Observation(
                    probe=self.name, channel="package_registry", kind=entry.get("kind", "app"),
                    name=entry["name"], path=path, matched_on="%s:%s" % (method, name),
                    catalog_id=entry["id"], vendor=entry.get("vendor"), realpath=path,
                    install_root=path, install_method=method,
                    pkg_identity="%s:%s" % (method, name), owner=env.user, confidence=0.6,
                ))
        out.extend(self._appimages(env))
        return out

    def _appimages(self, env: DiscoveryEnv) -> List[Observation]:
        """AppImages have no package registry entry, so the filename is the only clue."""
        out: List[Observation] = []
        for directory in APPIMAGE_DIRS:
            base = env.expand(directory)
            for name in env.listdir(base):
                if not name.lower().endswith(".appimage"):
                    continue
                stem = name.split("-")[0].split(".")[0].lower()
                entry = (self.catalog.match("binaries", stem)
                         or self.catalog.match("desktop_ids", stem + ".desktop"))
                if not entry:
                    continue
                path = posixpath.join(base, name)
                out.append(Observation(
                    probe=self.name, channel="filesystem", kind=entry.get("kind", "app"),
                    name=entry["name"], path=path, matched_on="appimage:%s" % name,
                    catalog_id=entry["id"], vendor=entry.get("vendor"), realpath=path,
                    install_root=path, install_method="appimage", owner=env.user, confidence=0.5,
                ))
        return out
