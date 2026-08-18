"""CLI coding agents: the binaries, the packages that installed them, and the
state directories that prove somebody actually ran them."""

import hashlib
import posixpath
from typing import Any, Dict, List, Optional

from ..base_probe import BaseProbe, Observation
from ..env import DiscoveryEnv
from ..paths import install_method, install_root, owner_of

#: Checked in addition to PATH, because a non-login scan context rarely has the
#: PATH the user actually types into.
EXTRA_BIN_DIRS = ("~/.local/bin", "/usr/local/bin", "/opt/homebrew/bin", "~/bin", "~/.npm-global/bin")

NODE_MODULE_ROOTS = ("/opt/homebrew/lib/node_modules", "/usr/local/lib/node_modules",
                     "~/.npm-global/lib/node_modules")

#: Tier 2 escalation budget: hashing is only worth it for binaries in
#: non-standard locations, and only when the catalog carries hashes at all.
HASH_DIRS = ("~/bin", "~/.local/bin")
MAX_HASH_BYTES = 64_000_000


class CliAgentProbe(BaseProbe):
    name = "cli_agent"

    def collect(self, env: DiscoveryEnv) -> List[Observation]:
        found: List[Observation] = []
        found.extend(self._from_bin_dirs(env))
        found.extend(self._from_node_modules(env))
        found.extend(self._from_state_dirs(env))
        return found

    # -- Stage 0/1: binaries on PATH and in conventional bin dirs ---------

    def _bin_dirs(self, env: DiscoveryEnv) -> List[str]:
        directories = [d for d in env.env_vars.get("PATH", "").split(":") if d]
        directories.extend(env.expand(d) for d in EXTRA_BIN_DIRS)
        for user in [env.user] + list(env.extra_users):
            directories.append("/Users/%s/.local/bin" % user)
            directories.append("/home/%s/.local/bin" % user)
        ordered, seen = [], set()
        for directory in directories:
            if directory not in seen:
                seen.add(directory)
                ordered.append(directory)
        return ordered

    def _from_bin_dirs(self, env: DiscoveryEnv) -> List[Observation]:
        out: List[Observation] = []
        hash_dirs = {env.expand(d) for d in HASH_DIRS}
        for directory in self._bin_dirs(env):
            for name in env.listdir(directory):
                logical = posixpath.join(directory, name)
                entry = self.catalog.match("binaries", name)
                matched_on = "binary:%s" % name
                if entry is None and self.catalog.has_hashes() and directory in hash_dirs:
                    entry, matched_on = self._hash_match(env, logical)
                if entry is None:
                    continue
                out.extend(self._binary_observations(env, entry, logical, matched_on))
        return out

    def _hash_match(self, env: DiscoveryEnv, logical: str):
        """Tier 2: identify a renamed copy by content, not by its filename."""
        result = env.read(logical, limit=MAX_HASH_BYTES)
        if not result:
            return None, ""
        digest = hashlib.sha256(result.data).hexdigest()
        entry = self.catalog.match("sha256", digest)
        return entry, ("sha256:%s" % digest[:12] if entry else "")

    def _binary_observations(self, env, entry, logical, matched_on) -> List[Observation]:
        realpath = env.realpath(logical)
        signature = self._signature(env, realpath)
        base = Observation(
            probe=self.name, channel="filesystem", kind=entry.get("kind", "cli_agent"),
            name=entry["name"], path=logical, matched_on=matched_on,
            catalog_id=entry["id"], version=self._version(env, logical),
            vendor=entry.get("vendor"), realpath=realpath, install_root=install_root(realpath),
            install_method=install_method(realpath), signature=signature,
            owner=owner_of(logical, env), confidence=0.5,
        )
        out = [base]
        if signature.get("team_id"):
            out.append(Observation(
                probe=self.name, channel="code_signature", kind=base.kind, name=base.name,
                path=logical, matched_on="team_id:%s" % signature["team_id"],
                catalog_id=entry["id"], realpath=realpath, install_root=base.install_root,
                signature=signature, owner=base.owner, confidence=0.5,
            ))
        return out

    def _version(self, env: DiscoveryEnv, logical: str) -> Optional[str]:
        out = env.run([logical, "--version"], timeout=2.0)
        if not out:
            return None
        for token in out.strip().split():
            if token and token[0].isdigit():
                return token
        return None

    def _signature(self, env: DiscoveryEnv, realpath: str) -> Dict[str, Any]:
        out = env.run(["codesign", "--display", "--verbose", realpath], timeout=2.0)
        if not out:
            return {"signed": False}
        team = None
        for line in out.splitlines():
            if line.startswith("TeamIdentifier="):
                team = line.split("=", 1)[1].strip()
        return {"signed": bool(team) and team != "not set", "team_id": team}

    # -- Stage 1: package-manager provenance ------------------------------

    def _from_node_modules(self, env: DiscoveryEnv) -> List[Observation]:
        out: List[Observation] = []
        for root in NODE_MODULE_ROOTS:
            base = env.expand(root)
            for name in env.listdir(base):
                if name.startswith("@"):
                    scope = posixpath.join(base, name)
                    packages = [posixpath.join(scope, child) for child in env.listdir(scope)]
                else:
                    packages = [posixpath.join(base, name)]
                for package_dir in packages:
                    observation = self._npm_package(env, package_dir)
                    if observation is not None:
                        out.append(observation)
        return out

    def _npm_package(self, env: DiscoveryEnv, package_dir: str) -> Optional[Observation]:
        manifest = self.read_json(env, posixpath.join(package_dir, "package.json"))
        if not isinstance(manifest, dict):
            return None
        entry = self.catalog.match("npm_packages", manifest.get("name", ""))
        if not entry:
            return None
        bin_field = manifest.get("bin") or {}
        relative = None
        if isinstance(bin_field, dict) and bin_field:
            relative = list(bin_field.values())[0]
        elif isinstance(bin_field, str):
            relative = bin_field
        target = None
        if relative:
            target = env.realpath(posixpath.normpath(posixpath.join(package_dir, relative)))
        return Observation(
            probe=self.name, channel="package_registry", kind=entry.get("kind", "cli_agent"),
            name=entry["name"], path=package_dir, matched_on="npm:%s" % manifest.get("name"),
            catalog_id=entry["id"], version=manifest.get("version"), vendor=entry.get("vendor"),
            realpath=target, install_root=install_root(package_dir), install_method="npm",
            pkg_identity="npm:%s" % manifest.get("name"), owner=owner_of(package_dir, env),
            confidence=0.6,
        )

    # -- Stage 1: state directories, the strongest presence signal --------

    def _from_state_dirs(self, env: DiscoveryEnv) -> List[Observation]:
        out: List[Observation] = []
        for entry in self.catalog.entries:
            for state in entry.get("state_dirs", []) or []:
                for user in [env.user] + list(env.extra_users):
                    logical = self._user_path(env, state, user)
                    if not env.exists(logical):
                        continue
                    out.append(Observation(
                        probe=self.name, channel="filesystem", kind=entry.get("kind", "cli_agent"),
                        name=entry["name"], path=logical, matched_on="state_dir",
                        catalog_id=entry["id"], vendor=entry.get("vendor"),
                        identity_hint="state:%s" % entry["id"], owner=user, confidence=0.45,
                    ))
        return out

    def _user_path(self, env: DiscoveryEnv, template: str, user: str) -> str:
        if not template.startswith("~"):
            return template
        home = "/home/%s" % user if env.platform == "linux" else "/Users/%s" % user
        return template.replace("~", home, 1)
