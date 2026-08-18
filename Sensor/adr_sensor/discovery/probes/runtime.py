"""Local model runtimes and the weights they hold.

A listening port that answers a model-listing endpoint separates "actively
serving" from "installed once and forgotten", which is the distinction that
actually matters for risk.
"""

import posixpath
from typing import Any, List, Optional, Tuple

from ..base_probe import BaseProbe, Observation
from ..env import DiscoveryEnv
from ..paths import install_root

#: Endpoints that identify an inference server without knowing the product.
MODEL_ENDPOINTS = ("/v1/models", "/api/tags")


class RuntimeProbe(BaseProbe):
    name = "runtime"

    def collect(self, env: DiscoveryEnv) -> List[Observation]:
        out: List[Observation] = []
        out.extend(self._weights_on_disk(env))
        out.extend(self._listeners(env))
        return out

    def _weights_on_disk(self, env: DiscoveryEnv) -> List[Observation]:
        base = env.expand("~/.ollama/models/manifests")
        if not env.is_dir(base):
            return []
        models = []
        for logical, path in env.walk(base, max_depth=4):
            try:
                if path.is_file():
                    models.append(logical.split("manifests/", 1)[-1])
            except OSError:
                continue
        entry = self.catalog.get("ollama") or {"name": "Ollama"}
        home = env.expand("~/.ollama")
        return [Observation(
            probe=self.name, channel="filesystem", kind="model_runtime",
            name=entry.get("name", "Ollama"), path=home, matched_on="ollama_manifests",
            catalog_id="ollama", vendor=entry.get("vendor"), realpath=env.realpath(home),
            install_root=install_root(home), owner=env.user,
            extra={"models": sorted(models)}, confidence=0.55,
        )]

    def _listeners(self, env: DiscoveryEnv) -> List[Observation]:
        out: List[Observation] = []
        for socket in env.sockets:
            if socket.state != "LISTEN":
                continue
            payload, endpoint = self._identify(env, socket.port)
            if payload is None:
                continue
            entry = self.catalog.match_port(socket.port)
            process = next((p for p in env.processes if p.pid == socket.pid), None)
            name = (entry or {}).get("name")
            if not name and process:
                name = posixpath.basename(process.exe)
            out.append(Observation(
                probe=self.name, channel="runtime", kind="model_runtime",
                name=name or "unidentified model runtime",
                path=process.exe if process else "port:%d" % socket.port,
                matched_on="endpoint:%s" % endpoint, catalog_id=(entry or {}).get("id"),
                vendor=(entry or {}).get("vendor"),
                realpath=env.realpath(process.exe) if process else None,
                install_root=install_root(process.exe) if process else None,
                owner=(process.user if process else env.user),
                extra={"models": _model_names(payload), "port": socket.port,
                       "endpoint": endpoint, "serving": True, "running": True},
                confidence=0.7,
            ))
        return out

    def _identify(self, env: DiscoveryEnv, port: int) -> Tuple[Optional[Any], Optional[str]]:
        for endpoint in MODEL_ENDPOINTS:
            payload = env.http_get(port, endpoint)
            if payload:
                return payload, endpoint
        return None, None


def _model_names(payload: Any) -> List[str]:
    if not isinstance(payload, dict):
        return []
    for key in ("data", "models"):
        items = payload.get(key)
        if not isinstance(items, list):
            continue
        names = []
        for item in items:
            if isinstance(item, dict):
                names.append(str(item.get("id") or item.get("name") or ""))
            else:
                names.append(str(item))
        return sorted(name for name in names if name)
    return []
