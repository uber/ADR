"""CI workflows, read for the agents they run.

A workflow is not an asset. What matters is that a repository is arranged
to run an agent with no person present -- which is the AI-agents target,
and is invisible to every other source because nothing about it exists on
the endpoint except a YAML file in a directory nobody scans for binaries.

Only the step's action reference and its declared environment names are
read. Nothing here reads a `run:` body: that is a script, out of scope by
§1, and it is also arbitrary user text.
"""

from __future__ import annotations

from ..isolate import as_env

#: Action references that are an agent, not a build step. Prefix match, so
#: a version suffix does not have to be enumerated.
AGENT_ACTIONS: tuple[tuple[str, str], ...] = (
    ("anthropics/claude-code-action", "claude-code"),
    ("anthropics/claude-code-base-action", "claude-code"),
    ("openai/codex-action", "codex-cli"),
    ("google-github-actions/run-gemini-cli", "gemini-cli"),
    ("github/copilot", "github-copilot"),
    ("cursor/cursor-agent", "cursor"),
    ("continuedev/continue-action", "continue"),
    ("aider-ai/aider-action", "aider"),
)


def steps_of(document: dict):
    """Yield (job_name, step) for every step in a workflow document."""
    jobs = document.get("jobs")
    if not isinstance(jobs, dict):
        return
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps")
        if not isinstance(steps, list):
            continue
        for step in steps:
            if isinstance(step, dict):
                yield str(job_name), step


def agent_steps(document: dict):
    """Only the steps that run an agent.

    A workflow full of build steps yields nothing, which is the precision
    half: `uses: actions/checkout@v4` is not an AI agent however many
    agents run after it.
    """
    for job_name, step in steps_of(document):
        uses = step.get("uses")
        if not isinstance(uses, str):
            continue
        reference = uses.split("@", 1)[0].strip()
        for prefix, catalog_id in AGENT_ACTIONS:
            if reference == prefix or reference.startswith(prefix + "/"):
                yield job_name, step, reference, catalog_id
                break


def env_names_of(step: dict) -> tuple[str, ...]:
    try:
        names = tuple(sorted(str(k) for k in as_env(step.get("env"))))
    except TypeError:
        names = ()
    with_block = step.get("with")
    if isinstance(with_block, dict):
        names += tuple(sorted(f"with.{k}" for k in with_block))
    return names
