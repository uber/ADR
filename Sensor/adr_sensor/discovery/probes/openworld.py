"""Stage 2: deciding something is an AI tool without knowing what it is.

Closed-world fingerprinting only finds tools somebody already catalogued, which
excludes most of the shadow-AI risk by construction. These signals are weak
alone and decent in combination. Anything over the threshold becomes a review
queue item - triage, not an alert - and triage is what grows the catalog.
"""

import json
import posixpath
from typing import Any, Dict, List

from ..base_probe import BaseProbe, Observation
from ..env import DiscoveryEnv
from ..redact import is_denied

#: Hosts only an LLM client talks to. Matched exactly: a wildcard grant such as
#: ``<all_urls>`` is breadth, not intent, and flagging it buries the operator in
#: password managers and ad blockers.
PROVIDER_HOSTS = (
    "api.anthropic.com", "api.openai.com", "generativelanguage.googleapis.com",
    "bedrock-runtime", "api.mistral.ai", "api.cohere.ai", "api.x.ai", "api.deepseek.com",
)

PROVIDER_KEY_NAMES = ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY",
                      "GOOGLE_API_KEY", "MISTRAL_API_KEY", "COHERE_API_KEY")

#: Signal weights. Any single strong signal clears the threshold; the weak ones
#: only matter in combination. The threshold belongs on a PR curve swept over
#: the corpus, not in a code review.
WEIGHTS = {
    "mcp_participation": 0.6,
    "runtime_shape": 0.6,
    "network_intent": 0.55,
    "state_shape": 0.5,
    "credential_affinity": 0.3,
}

THRESHOLD = 0.5

#: Roots scanned for uncatalogued agents. Personal content is excluded by the
#: deny-list before this list is ever consulted.
PROJECT_ROOTS = ("~/dev", "~/src", "~/workspace", "~/code")

#: Tier 2 ceiling for a strings scan of a bundle executable.
MAX_STRINGS_BYTES = 2_000_000


class OpenWorldProbe(BaseProbe):
    """Scores what the catalog rejected. Runs after every other probe."""

    name = "openworld"

    def collect(self, env: DiscoveryEnv) -> List[Observation]:
        return []

    def score_candidates(self, env: DiscoveryEnv,
                         observations: List[Observation]) -> List[Dict[str, Any]]:
        try:
            return self._score(env, observations)
        except Exception as exc:
            env.errors.append({"probe": self.name, "stage": "score",
                               "error_type": exc.__class__.__name__, "message": str(exc)})
            return []

    # -- candidate assembly ----------------------------------------------

    def _score(self, env: DiscoveryEnv, observations: List[Observation]) -> List[Dict[str, Any]]:
        queue: List[Dict[str, Any]] = []
        seen = set()
        for observation in observations:
            if observation.catalog_id or observation.kind == "mcp_server":
                continue
            if observation.path in seen:
                continue
            seen.add(observation.path)
            queue.append(self._entry(observation.name, observation.path, observation.kind,
                                     self._signals_for_observation(env, observation)))
        for path, name in self._directory_candidates(env):
            if path in seen:
                continue
            seen.add(path)
            signals, sessions = self._signals_for_directory(env, path)
            queue.append(self._entry(name, path, "cli_agent", signals, sessions))
        return sorted([item for item in queue if item["score"] >= THRESHOLD],
                      key=lambda item: -item["priority"])

    def _entry(self, name: str, path: str, kind: str, signals: Dict[str, bool],
               sessions: int = 0) -> Dict[str, Any]:
        fired = sorted(key for key, value in signals.items() if value)
        score = round(min(1.0, sum(WEIGHTS[key] for key in fired)), 3)
        # An unknown tool somebody uses daily is a more urgent triage item than
        # an unknown tool nobody has opened. Usage is what orders the queue.
        priority = round(min(2.0, score + min(0.5, sessions / 100.0)), 3)
        return {"name": name, "path": path, "kind": kind,
                "state": "probable_ai_unclassified", "signals": fired,
                "score": score, "sessions": sessions, "priority": priority,
                "threshold": THRESHOLD}

    def _directory_candidates(self, env: DiscoveryEnv):
        for root in PROJECT_ROOTS:
            base = env.expand(root)
            for name in env.listdir(base):
                path = posixpath.join(base, name)
                if env.is_dir(path) and not is_denied(path):
                    yield path, name
        known = set(self.catalog.state_dir_names())
        for name in env.listdir(env.home):
            if not name.startswith("."):
                continue
            path = posixpath.join(env.home, name)
            if "~/" + name in known or not env.is_dir(path) or is_denied(path):
                continue
            yield path, name.lstrip(".")

    # -- the signals ------------------------------------------------------

    def _signals_for_observation(self, env: DiscoveryEnv, observation: Observation) -> Dict[str, bool]:
        signals = {key: False for key in WEIGHTS}
        extra = observation.extra or {}
        if any(self._is_provider_target(item) for item in (extra.get("host_permissions") or [])):
            signals["network_intent"] = True
        if extra.get("serving"):
            signals["runtime_shape"] = True
        if observation.path.endswith(".app") and not signals["network_intent"]:
            signals["network_intent"] = self._executable_mentions_provider(env, observation)
        return signals

    def _signals_for_directory(self, env: DiscoveryEnv, path: str):
        """Signals for a directory, plus how many chat-shaped sessions it holds."""
        signals = {key: False for key in WEIGHTS}
        sessions = 0
        for logical, _ in env.walk(path, max_depth=3):
            base = posixpath.basename(logical)
            if base in (".env", ".envrc"):
                result = env.read(logical, limit=64_000)
                if result and any(name in result.text for name in PROVIDER_KEY_NAMES):
                    signals["credential_affinity"] = True
            elif base in (".mcp.json", "mcp.json"):
                signals["mcp_participation"] = True
            elif base.endswith(".jsonl") and self._looks_like_chat(env, logical):
                signals["state_shape"] = True
                sessions += 1
        return signals, sessions

    def _looks_like_chat(self, env: DiscoveryEnv, logical: str) -> bool:
        """A state file shaped like a conversation, whatever product wrote it."""
        result = env.read(logical, limit=64_000)
        if not result:
            return False
        for line in result.text.splitlines()[:20]:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                return False
            if not isinstance(record, dict):
                return False
            if "role" in record and "content" in record:
                return True
            if isinstance(record.get("messages"), list):
                return True
        return False

    def _executable_mentions_provider(self, env: DiscoveryEnv, observation: Observation) -> bool:
        """Bounded strings scan of the bundle executable only.

        Deliberately not the whole bundle: a changelog that mentions a provider
        is documentation, not intent, and scanning it manufactures false twins.
        """
        executable = (observation.extra or {}).get("executable")
        if not executable:
            return False
        logical = posixpath.join(observation.path, "Contents/MacOS", executable)
        result = env.read(logical, limit=MAX_STRINGS_BYTES)
        if not result:
            return False
        return any(host in result.text for host in PROVIDER_HOSTS)

    def _is_provider_target(self, pattern: Any) -> bool:
        text = str(pattern)
        if "<all_urls>" in text or text in ("*://*/*", "http://*/*", "https://*/*"):
            return False
        return any(host in text for host in PROVIDER_HOSTS)
