import json

from adr_protection import api_v1

from adr_desktop import threat_feed
from adr_desktop.protection import evaluate_operation


def test_desktop_adapter_reuses_the_public_component_without_duplicate_logic():
    for name in threat_feed.__all__:
        if name != "load_bundled_feed":
            assert getattr(threat_feed, name) is getattr(api_v1, name)


def test_existing_baseline_and_serialized_policy_generation_keep_their_contract():
    baseline = threat_feed.load_bundled_feed()
    generation = threat_feed.compose_generation(baseline)
    restored = json.loads(json.dumps(generation))
    assert api_v1.validate_generation(restored) == generation
    subject = {
        "kind": "package", "ecosystem": "npm", "registry": "https://registry.npmjs.org",
        "name": "postmark-mcp", "version": "1.0.16",
    }
    assert api_v1.compile_generation(restored).match(subject) == threat_feed.match_subject(
        generation, subject,
    )


def test_host_still_owns_enforcement_and_unknown_results_do_not_grant_permissions(runtime):
    event = {"tool_name": "Read", "tool_input": {"file_path": "/synthetic/private"}, "cwd": "/"}
    runtime.change_policy(add={"path": "/synthetic/private", "kind": "file", "action": "block"})
    decision = evaluate_operation(event, "claude", runtime.policy, state_dir=runtime.state_dir)
    assert decision.decision == "deny"
    assert decision.reason_code == "protected_path"
