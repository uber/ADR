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

#: Weight file extensions. Weights are inventory in their own right: data at
#: rest, often tens of gigabytes, frequently without any runtime installed.
WEIGHT_SUFFIXES = (".gguf", ".safetensors", ".bin", ".pth", ".mlmodelc")

WEIGHT_DIRS = ("~/models", "~/.cache/huggingface/hub", "~/.cache/torch/hub",
               "~/Documents/models")

MIN_WEIGHT_BYTES = 50_000_000


class RuntimeProbe(BaseProbe):
    name = "runtime"

    def collect(self, env: DiscoveryEnv) -> List[Observation]:
        out: List[Observation] = []
        out.extend(self._model_dirs(env))
        out.extend(self._listeners(env))
        out.extend(self._loose_weights(env))
        return out

    def _model_dirs(self, env: DiscoveryEnv) -> List[Observation]:
        """Runtimes identified by the model store they maintain."""
        out: List[Observation] = []
        for entry in self.catalog.entries:
            for template in entry.get("model_dirs", []) or []:
                base = env.expand(template)
                if not env.is_dir(base):
                    continue
                models = self._model_names(env, base)
                out.append(Observation(
                    probe=self.name, channel="filesystem", kind=entry.get("kind", "model_runtime"),
                    name=entry["name"], path=base, matched_on="model_dir",
                    catalog_id=entry["id"], vendor=entry.get("vendor"),
                    realpath=None, install_root=install_root(base),
                    identity_hint="attr:%s" % entry["id"], owner=env.user,
                    extra={"models": models}, confidence=0.55,
                ))
        return out

    def _model_names(self, env: DiscoveryEnv, base: str) -> List[str]:
        names = []
        for logical, path in env.walk(base, max_depth=4):
            try:
                if not path.is_file():
                    continue
            except OSError:
                continue
            relative = logical[len(base):].strip("/")
            if relative:
                names.append(relative)
        return sorted(names)

    def _loose_weights(self, env: DiscoveryEnv) -> List[Observation]:
        """Model weights with no runtime attached are still data on the endpoint."""
        out: List[Observation] = []
        for template in WEIGHT_DIRS:
            base = env.expand(template)
            if not env.is_dir(base):
                continue
            total, files = 0, []
            for logical, path in env.walk(base, max_depth=4):
                if not logical.lower().endswith(WEIGHT_SUFFIXES):
                    continue
                try:
                    size = path.stat().st_size
                except OSError:
                    continue
                total += size
                files.append(posixpath.basename(logical))
            if not files:
                continue
            out.append(Observation(
                probe=self.name, channel="filesystem", kind="model_weights",
                name="Model weights (%s)" % posixpath.basename(base.rstrip("/")),
                path=base, matched_on="weight_files", realpath=env.realpath(base),
                install_root=base, owner=env.user,
                extra={"models": sorted(files), "bytes": total}, confidence=0.5,
            ))
        return out

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
                probe=self.name, channel="runtime",
                kind=(entry or {}).get("kind", "model_runtime"),
                name=name or "unidentified model runtime",
                path=process.exe if process else "port:%d" % socket.port,
                matched_on="endpoint:%s" % endpoint, catalog_id=(entry or {}).get("id"),
                vendor=(entry or {}).get("vendor"),
                realpath=env.realpath(process.exe) if process else None,
                install_root=install_root(process.exe) if process else None,
                identity_hint=(None if process or not entry else "attr:%s" % entry["id"]),
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
