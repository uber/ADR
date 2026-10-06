"""UserPromptSubmit adapter. Never writes the submitted prompt to disk or stdout."""

import json
import sys
from pathlib import Path

from .config import read_private_json, strict_json
from .environment_vault import PROMPT_LIMIT, PROMPT_MESSAGE, UNAVAILABLE_MESSAGE
from .local_client import request


def run_prompt_hook(state_dir: Path, harness: str, guard_protocol=False):
    blocked, reason = True, UNAVAILABLE_MESSAGE
    try:
        if harness not in ("claude", "codex"):
            raise ValueError("Unsupported prompt hook")
        event = strict_json(sys.stdin.buffer.read(PROMPT_LIMIT * 2 + 1), max_bytes=PROMPT_LIMIT * 2)
        prompt = event.get("prompt")
        if not isinstance(prompt, str) or len(prompt.encode()) > PROMPT_LIMIT:
            raise ValueError("Invalid prompt")
        auth = read_private_json(state_dir / "hook-access.json", maximum=16384)
        response = request(
            state_dir,
            "POST",
            "/api/hooks/prompt-check",
            token=auth["token"],
            payload={"harness": harness, "prompt": prompt},
            timeout=2.5,
        )
        if response.get("blocked") is False:
            blocked = False
        elif response.get("message") == PROMPT_MESSAGE:
            reason = PROMPT_MESSAGE
    except Exception:
        pass
    if guard_protocol:
        print("secret" if blocked and reason == PROMPT_MESSAGE else "deny" if blocked else "pass")
    else:
        print(json.dumps({"decision": "block", "reason": reason} if blocked else {}))
    return 0
