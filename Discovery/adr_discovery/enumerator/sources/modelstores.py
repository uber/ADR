"""Local model stores that package and application registries do not index."""

from __future__ import annotations

from ...contracts.records import Candidate, Priority

MODEL_ROOTS = (
    "~/.ollama/models", "~/.cache/huggingface/hub", "~/.cache/lm-studio/models",
    "~/Library/Application Support/LM Studio/models", "~/.local/share/Jan/models",
    "~/.cache/gpt4all",
)
MODEL_SUFFIXES = (".gguf", ".safetensors")
MAX_MODELS = 500


def from_model_stores(gate, homes: tuple[str, ...]) -> tuple[Candidate, ...]:
    out: list[Candidate] = []
    for template in MODEL_ROOTS:
        for home in homes:
            root = home + template[1:]
            if not gate.list_dir(root).ok:
                continue
            for entry in gate.walk(root, max_depth=4):
                if entry.is_dir:
                    continue
                name = entry.path.rsplit("/", 1)[-1]
                if not (name.endswith(MODEL_SUFFIXES) or name.startswith("sha256-")):
                    continue
                out.append(Candidate("model_weight_candidate", entry.path, "model_store",
                                     Priority.HOME, {"name": name, "size": entry.size}))
                if len(out) >= MAX_MODELS:
                    gate.ledger.truncate(root, len(out), len(out) + 1)
                    return tuple(out)
    return tuple(out)
