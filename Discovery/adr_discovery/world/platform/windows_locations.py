"""Windows profile and application roots, without assuming a system drive.

Only loaded user hives are read. Unloaded profiles use their own conventional
AppData directories; the caller's APPDATA is never applied to another user.
Filesystem inspection still goes through Gate, including registry-supplied
paths. No user hive is loaded and no document directory is recursively added.
"""

from __future__ import annotations

import ntpath
import os
import re
import stat
from dataclasses import dataclass
from weakref import WeakKeyDictionary

_PROFILE_LIST = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
_SHELL_FOLDERS = r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
_SHARED_PROFILES = frozenset({"public", "default", "default user", "all users"})


@dataclass(frozen=True, slots=True)
class WindowsHome:
    home: str
    roaming: str
    local: str
    documents: str


def absolute(value: str) -> str | None:
    """Accept fully anchored drive/UNC paths, never current-drive relatives."""
    if not value or "\x00" in value:
        return None
    drive, tail = ntpath.splitdrive(value)
    parts = drive.replace("\\", "/").split("/")
    unc = drive.startswith(("\\\\", "//")) and len(parts) == 4 and all(parts[2:])
    if not unc and not re.fullmatch(r"[A-Za-z]:", drive):
        return None
    if not drive or not (tail.startswith(("/", "\\")) or (unc and not tail)):
        return None
    if drive.startswith(("\\\\?", "\\\\.", "//?", "//.")):
        return None
    return ntpath.normpath(value).replace("\\", "/")


def _env(gate) -> dict[str, str]:
    return {key.upper(): value for key, value in gate.env.items()}


def _expand(value: str, env: dict[str, str]) -> str | None:
    value = re.sub(r"%([^%]+)%", lambda match: env.get(match[1].upper(), match[0]), value)
    return None if "%" in value else absolute(value)


def _unique(paths) -> tuple[str, ...]:
    found: dict[str, str] = {}
    for path in paths:
        if path:
            found.setdefault(path.casefold(), path)
    return tuple(found.values())


def _registry_data(gate) -> tuple[str | None, dict[str, dict[str, str]]]:
    """ProfileList plus known-folder overrides for currently loaded hives."""
    if os.name != "nt":
        return None, {}
    live = getattr(gate, "_live", None)
    if live is None:
        gate.ledger.unavailable("profiles", "native profile registry requires Gate's explicit live-mode marker")
        return None, {}
    if not live:
        return None, {}
    import winreg

    env = _env(gate)

    def values(hive, path, names, profile=None):
        out = {}
        try:
            with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                for name in names:
                    try:
                        value, _ = winreg.QueryValueEx(key, name)
                        if isinstance(value, str):
                            out[name] = value
                    except OSError:
                        pass
        except OSError as exc:
            if profile is not None:
                reason = "access denied" if isinstance(exc, PermissionError) else "hive or key unavailable"
                gate.ledger.probe("known_folders", "degraded", f"{profile}: {reason}; using profile defaults")
            return out
        if profile is not None and not all(name in out for name in names):
            gate.ledger.probe("known_folders", "degraded", f"{profile}: incomplete known folders; defaults may apply")
        return out

    names = ("AppData", "Local AppData", "Personal")
    profiles = values(winreg.HKEY_LOCAL_MACHINE, _PROFILE_LIST, ("ProfilesDirectory",))
    root = _expand(profiles.get("ProfilesDirectory", ""), env)
    if root is None:
        gate.ledger.probe("profiles", "degraded", "ProfilesDirectory missing or invalid")
    found = {}
    current = _expand(env.get("USERPROFILE", ""), env)
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _PROFILE_LIST, 0,
                            winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            total = winreg.QueryInfoKey(key)[0]
            count = min(total, 4096)
            if total > count:
                gate.ledger.probe("profiles", "degraded", "ProfileList exceeded 4096 entries")
            for index in range(count):
                sid = winreg.EnumKey(key, index)
                if sid.endswith(".bak") or not sid.startswith(("S-1-5-21-", "S-1-12-1-")):
                    continue
                profile = values(winreg.HKEY_LOCAL_MACHINE, _PROFILE_LIST + "\\" + sid,
                                 ("ProfileImagePath",))
                home = _expand(profile.get("ProfileImagePath", ""), env)
                if home:
                    found[home] = ({} if current and home.casefold() == current.casefold() else
                                   values(winreg.HKEY_USERS, sid + "\\" + _SHELL_FOLDERS, names, home))
                else:
                    gate.ledger.probe("profiles", "degraded", "ProfileImagePath missing or invalid")
    except OSError as exc:
        gate.ledger.probe("profiles", "degraded", f"ProfileList unavailable: {exc}")
    if current:
        # HKCU belongs only to the caller, even when other profiles were found.
        existing = next((key for key in found if key.casefold() == current.casefold()), current)
        found[existing] = values(winreg.HKEY_CURRENT_USER, _SHELL_FOLDERS, names, current)
    return root, found


class WindowsLocations:
    """Provider mixin; its cache shares the scan lifetime when Gate supplies it."""

    HOME_ROOTS: tuple[str, ...] = ()
    DIRECT_HOMES: tuple[str, ...] = ()

    def _locations(self, gate) -> tuple[WindowsHome, ...]:
        token = getattr(gate, "scan_token", None)
        if token is not None:
            cache = getattr(self, "_location_snapshots", None)
            if cache is None:
                cache = self._location_snapshots = WeakKeyDictionary()
            saved = cache.get(gate)
            if saved is not None and saved[0] is token:
                return saved[1]
        result = self._read_locations(gate)
        if token is not None:
            self._location_snapshots[gate] = (token, result)
        return result

    def _read_locations(self, gate) -> tuple[WindowsHome, ...]:
        env = _env(gate)
        current = absolute(env.get("USERPROFILE", ""))
        if not current:
            current = absolute(env.get("HOMEDRIVE", "") + env.get("HOMEPATH", ""))
        if not current:
            current = absolute(env.get("HOME", ""))
        profiles_root, registered = _registry_data(gate)
        candidates = list(registered)
        if current:
            candidates.append(current)
        # ProfilesDirectory is authoritative. An arbitrary USERPROFILE parent
        # might be a drive root containing unrelated data; do not enumerate it.
        roots = (profiles_root,) if profiles_root else ()
        for root in roots:
            listing = gate.list_dir(root)
            if listing.ok:
                candidates.extend(entry.path for entry in listing.value if entry.is_dir
                                  and ntpath.basename(entry.path).casefold() not in _SHARED_PROFILES
                                  and not ntpath.basename(entry.path).startswith("."))
        by_home = {key.casefold(): value for key, value in registered.items()}
        out = []
        for home in _unique(absolute(path) for path in candidates):
            info = gate.stat(home)
            if not info.ok or not stat.S_ISDIR(info.value.mode):
                continue
            defaults = {"APPDATA": home + "/AppData/Roaming", "LOCALAPPDATA": home + "/AppData/Local"}
            caller = current is not None and home.casefold() == current.casefold()
            # OneDrive and other caller-specific variables can appear in
            # known-folder values too. Never use them for another profile.
            machine_keys = {"SYSTEMDRIVE", "SYSTEMROOT", "WINDIR", "PROGRAMDATA", "PROGRAMFILES",
                            "PROGRAMFILES(X86)", "PROGRAMW6432", "ALLUSERSPROFILE"}
            user_env = dict(env) if caller else {key: value for key, value in env.items() if key in machine_keys}
            for key, value in defaults.items():
                user_env.setdefault(key, value)
            drive, tail = ntpath.splitdrive(home)
            user_env.update(USERPROFILE=home, USERNAME=ntpath.basename(home),
                            HOMEDRIVE=drive, HOMEPATH=tail)
            overrides = by_home.get(home.casefold(), {})
            roaming = _expand(overrides.get("AppData", ""), user_env)
            local = _expand(overrides.get("Local AppData", ""), user_env)
            if any(value and _expand(value, user_env) is None for value in overrides.values()):
                gate.ledger.probe("known_folders", "degraded", f"{home}: unresolved known-folder path; defaults may apply")
            if caller:
                roaming = roaming or absolute(env.get("APPDATA", ""))
                local = local or absolute(env.get("LOCALAPPDATA", ""))
            documents = _expand(overrides.get("Personal", ""), user_env) or home + "/Documents"
            out.append(WindowsHome(home, roaming or defaults["APPDATA"],
                                   local or defaults["LOCALAPPDATA"], documents))
        return tuple(out)

    def homes(self, gate) -> tuple[str, ...]:
        return tuple(profile.home for profile in self._locations(gate))

    def system_roots(self, gate) -> tuple[str, ...]:
        env = _env(gate)
        roots = [absolute(env.get(key, "")) for key in
                 ("PROGRAMW6432", "PROGRAMFILES", "PROGRAMFILES(X86)", "PROGRAMDATA")]
        roots.extend(profile.local + "/Programs" for profile in self._locations(gate))
        return _unique(roots)

    def powershell_profile_paths(self, gate) -> tuple[str, ...]:
        """Exact file allowlist for the separate PowerShell profile reader.

        These paths are never sweep roots or ordinary app-state templates.
        """
        return _unique(profile.documents + "/" + directory + "/" + filename
                       for profile in self._locations(gate)
                       for directory in ("WindowsPowerShell", "PowerShell")
                       for filename in ("profile.ps1", "Microsoft.PowerShell_profile.ps1"))

    def source_paths(self, gate, category, templates, homes) -> tuple[str, ...]:
        profiles = {profile.home.casefold(): profile for profile in self._locations(gate)}
        out = []
        for home in homes:
            profile = profiles.get(home.casefold())
            if profile is None:
                profile = WindowsHome(home, home + "/AppData/Roaming", home + "/AppData/Local",
                                      home + "/Documents")
            for template in templates:
                # POSIX app locations do not become current-drive Windows paths.
                if template.startswith("~/Library/") or template.startswith("/"):
                    continue
                replacements = (("~/AppData/Roaming", profile.roaming),
                                ("~/AppData/Local", profile.local),
                                ("~", profile.home))
                for prefix, base in replacements:
                    if template == prefix or template.startswith(prefix + "/"):
                        out.append(base + template[len(prefix):])
                        break
            if category == "state":
                out.extend(profile.roaming + suffix for suffix in ("/Claude", "/Code/User"))
            elif category == "browser":
                out.extend(profile.local + suffix for suffix in (
                    "/Google/Chrome/User Data", "/Chromium/User Data", "/Microsoft/Edge/User Data",
                    "/BraveSoftware/Brave-Browser/User Data",
                ))
            elif category == "firefox":
                out.append(profile.roaming + "/Mozilla/Firefox/Profiles")
            elif category == "models":
                out.extend((profile.home + "/.lmstudio/models", profile.local + "/nomic.ai/GPT4All"))
        env = _env(gate)
        if category == "config":
            program_files = absolute(env.get("PROGRAMW6432", "")) or absolute(env.get("PROGRAMFILES", ""))
            if program_files:
                out.extend(program_files + "/ClaudeCode/" + filename
                           for filename in ("managed-settings.json", "managed-mcp.json"))
        elif category == "models":
            ollama = absolute(env.get("OLLAMA_MODELS", ""))
            hf_home = absolute(env.get("HF_HOME", ""))
            hub = absolute(env.get("HF_HUB_CACHE", "")) or (hf_home + "/hub" if hf_home else None)
            out = [path for path in (ollama, hub) if path] + out
        return _unique(out)
