"""Isolated agent configuration and diagnostics for synthetic browser checks."""

import os
from contextlib import contextmanager, suppress
from pathlib import Path
from unittest.mock import patch

AGENT_ROOT_VARIABLES = ("CODEX_HOME", "CLAUDE_CONFIG_DIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME")


@contextmanager
def isolated_agent_profile(home):
    """Do not let inherited agent configuration escape a disposable QA home."""
    environment = {name: value for name, value in os.environ.items() if name not in AGENT_ROOT_VARIABLES}
    with patch.object(Path, "home", return_value=home), patch.dict(os.environ, environment, clear=True):
        yield


@contextmanager
def browser_evidence(context, output):
    """Retain synthetic-only traces and a failure screenshot before teardown."""
    output.mkdir(parents=True, exist_ok=True)
    context.tracing.start(screenshots=True, snapshots=True, sources=False)
    try:
        yield
    except BaseException:
        for index, page in enumerate(context.pages):
            with suppress(Exception):
                page.screenshot(path=str(output / f"failure-{index}.png"), full_page=True, timeout=5000)
        raise
    finally:
        # Diagnostic collection must not hide the original assertion or timeout.
        with suppress(Exception):
            context.tracing.stop(path=str(output / "trace.zip"))
        with suppress(Exception):
            context.close()
