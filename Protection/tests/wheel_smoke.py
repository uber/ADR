"""Run with python -I in a clean wheel-only environment, outside the checkout."""

import importlib.util
import json
import sys
from pathlib import Path

from adr_protection import api_v1


def main():
    assert Path(api_v1.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
    for name in ("adr_desktop", "adr_sensor", "adr_discovery", "fastapi"):
        assert importlib.util.find_spec(name) is None, f"Unexpected host dependency: {name}"
    source = {
        "schema_version": 1,
        "feed_id": api_v1.BUNDLED_FEED_ID,
        "revision": 1,
        "published_at": "2026-10-05T00:00:00Z",
        "indicators": [{
            "id": "synthetic", "status": "active", "kind": "file_sha256",
            "summary": "Inert packaging fixture.", "references": [],
            "target": {"sha256": "a" * 64},
        }],
    }
    parsed = api_v1.parse_feed_json(json.dumps(source).encode())
    generation = api_v1.compose_generation(parsed)
    matcher = api_v1.compile_generation(generation)
    matches = matcher.match({"kind": "file_sha256", "sha256": "a" * 64})
    assert len(matches) == 1
    assert matches[0]["indicator_id"] == "adr-public-artifacts/synthetic"
    assert matcher.match({"kind": "skill_sha256", "sha256": "a" * 64}) == []
    assert api_v1.generation_summary(generation)["total"] == 1
    print("Protection wheel: standalone import, validation, matching and summaries passed.")


if __name__ == "__main__":
    main()
