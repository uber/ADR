"""Compose exact artifact matches with existing file and harness permissions."""

from pathlib import Path

from .artifact_identity import READ_TOOLS, identify_event
from .mcp_trust import trusted_tool
from .policy import DENIAL_REASONS, PATH_KEYS, Decision, evaluate, event_fields
from .threat_feed import compile_generation


def evaluate_operation(event, harness, snapshot, *, state_dir, allow_adr_trust=True,
                       environment=None, artifact_scope="all") -> Decision:
    if artifact_scope not in ("all", "direct_files"):
        raise ValueError("Unsupported artifact evaluation scope")
    if allow_adr_trust and trusted_tool(event, harness, state_dir):
        tool, _, _, session = event_fields(event, harness)
        base = Decision("pass", "ADR MCP permission checked", tool=tool, session_id=session)
    else:
        base = evaluate(event, harness, snapshot)
    if base.decision == "deny":
        return base
    threats = snapshot.get("threats")
    if threats is None:
        return base
    if not isinstance(threats, dict) or not isinstance(threats.get("enabled"), bool):
        raise ValueError("Invalid threat policy")
    generation = compile_generation(threats.get("generation"))
    if not threats["enabled"]:
        return base
    if artifact_scope == "direct_files":
        # An approval daemon does not inherit the invoking harness's registry,
        # CODEX_HOME, or XDG context. Only literal absolute file reads have an
        # artifact identity independent of that missing process context.
        tool, arguments, _, _ = event_fields(event, harness)
        paths = [arguments[key] for key in PATH_KEYS if arguments.get(key) is not None]
        if tool.lower() not in READ_TOOLS or not paths or any(
            not isinstance(path, str) or not Path(path).is_absolute()
            or path.startswith(("~", "file:")) for path in paths
        ):
            return base
    evidence = identify_event(event, harness, state_dir, environment=environment)
    for candidate in evidence.candidates:
        matches = generation.match(candidate.subject)
        if matches:
            match = matches[0]
            base.decision = "deny"
            base.reason_code = "known_malicious_artifact"
            base.reason = DENIAL_REASONS[base.reason_code]
            base.artifact = {
                "indicator_id": match["indicator_id"],
                "source_id": match["source_id"],
                "kind": match["kind"],
                "generation": match["generation_digest"],
                "target_display": match["target_display"],
            }
            return base
    return base
