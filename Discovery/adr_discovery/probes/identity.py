"""Which account an agent is authenticated as, and how.

A corporate machine driving a personal subscription is the core shadow-AI case,
and it is invisible to an inventory that records only that the tool is
installed. The fact of a stored credential is the finding; the credential itself
never leaves the endpoint.
"""

import posixpath
import re
from typing import List, Optional

from ..base_probe import BaseProbe, Observation
from ..env import DiscoveryEnv
from ..net import matches_any

#: (catalog id, credential file). Presence and shape only - never the value.
CREDENTIAL_FILES = (
    ("claude-code", "~/.claude/.credentials.json"),
    ("codex", "~/.codex/auth.json"),
    ("gemini-cli", "~/.gemini/oauth_creds.json"),
    ("cursor", "~/.cursor/credentials.json"),
)

SHELL_RC_FILES = ("~/.zshrc", "~/.bashrc", "~/.bash_profile", "~/.profile", "~/.config/fish/config.fish")

#: Provider key names, mapped to the tool whose spend they pay for.
PROVIDER_KEYS = {
    "ANTHROPIC_API_KEY": ("anthropic", "claude-code"),
    "OPENAI_API_KEY": ("openai", "codex"),
    "GEMINI_API_KEY": ("google", "gemini-cli"),
    "GOOGLE_API_KEY": ("google", "gemini-cli"),
    "XAI_API_KEY": ("xai", "grok-cli"),
}

EXPORT_LINE = re.compile(r"^\s*(?:export\s+|set\s+-x\s+)?([A-Z0-9_]+)\s*[= ]", re.MULTILINE)


class IdentityProbe(BaseProbe):
    name = "identity"

    def collect(self, env: DiscoveryEnv) -> List[Observation]:
        out: List[Observation] = []
        out.extend(self._oauth(env))
        out.extend(self._api_keys(env))
        return out

    def _oauth(self, env: DiscoveryEnv) -> List[Observation]:
        corporate = [domain.lower() for domain in (env.policy.get("corporate_domains") or [])]
        out: List[Observation] = []
        for catalog_id, template in CREDENTIAL_FILES:
            logical = env.expand(template)
            if not env.exists(logical):
                continue
            data = self.read_json(env, logical)
            account = self._account(data)
            personal = self._is_personal(account, corporate)
            entry = self.catalog.get(catalog_id) or {}
            out.append(Observation(
                probe=self.name, channel="config", kind=entry.get("kind", "cli_agent"),
                name=entry.get("name", catalog_id), path=logical, matched_on="credentials",
                catalog_id=catalog_id, vendor=entry.get("vendor"), owner=env.user,
                identity_hint="attr:%s" % catalog_id,
                extra={"auth_method": "oauth",
                       "account_type": "personal" if personal else "enterprise",
                       "risk_factors": ["personal_account"] if personal else []},
                confidence=0.5,
            ))
        return out

    def _account(self, data) -> Optional[str]:
        if not isinstance(data, dict):
            return None
        for key in ("account", "email", "subject"):
            if isinstance(data.get(key), str):
                return data[key]
        for value in data.values():
            if isinstance(value, dict):
                found = self._account(value)
                if found:
                    return found
        return None

    def _is_personal(self, account: Optional[str], corporate: List[str]) -> bool:
        """No corporate domain in the account means it is somebody's own login."""
        if not account or "@" not in account:
            return bool(corporate)
        return not matches_any(account.split("@", 1)[1], corporate)

    def _api_keys(self, env: DiscoveryEnv) -> List[Observation]:
        """A raw key in a shell profile pays for spend nobody can attribute."""
        out: List[Observation] = []
        seen = set()
        for template in SHELL_RC_FILES:
            logical = env.expand(template)
            if not env.exists(logical):
                continue
            result = env.read(logical, limit=200_000)
            if not result:
                continue
            for match in EXPORT_LINE.finditer(result.text):
                name = match.group(1)
                if name not in PROVIDER_KEYS or name in seen:
                    continue
                seen.add(name)
                provider, catalog_id = PROVIDER_KEYS[name]
                entry = self.catalog.get(catalog_id) or {}
                out.append(Observation(
                    probe=self.name, channel="config", kind=entry.get("kind", "cli_agent"),
                    name=entry.get("name", catalog_id), path=logical,
                    matched_on="env_key:%s" % name, catalog_id=catalog_id,
                    vendor=entry.get("vendor"), owner=env.user,
                    identity_hint="attr:%s" % catalog_id,
                    extra={"auth_method": "api_key", "credential_kinds": [provider],
                           "env_names": [name], "risk_factors": ["unattributed_spend"]},
                    confidence=0.45,
                ))
        return out


def _basename(path: str) -> str:
    return posixpath.basename(path)
