import sys
from pathlib import Path
from unittest.mock import mock_open, patch

sys.path.insert(0, str(Path(__file__).parent.parent / "context_providers"))
import policy_store_server


def test_load_empty_yaml_returns_safe_default():
    """An empty YAML file should not crash; it should yield an empty policy list."""
    with patch.object(Path, "exists", return_value=True):
        with patch("builtins.open", mock_open(read_data="")):
            result = policy_store_server.load_policy_data()
    assert result == {"policies": []}


def test_search_policies_matches_policy_body():
    """Keywords that only appear in a policy's body text must still match."""
    policies = [
        {
            "name": "Access Control Standard",
            "description": "Security requirements for access management",
            "category": "access_control",
            "policy": "The policy enforces the principle of least privilege.",
        },
        {
            "name": "Anti-malware Standard",
            "description": "Anti-malware requirements",
            "category": "malware_protection",
            "policy": "All systems must run approved anti-malware software.",
        },
    ]
    with patch.dict(policy_store_server.policy_data, {"policies": policies}):
        result = policy_store_server.search_policies(["least privilege"])
    assert [p["name"] for p in result["matching_policies"]] == ["Access Control Standard"]


def test_shipped_policy_store_body_is_searchable():
    """The shipped policy store keeps its main text under `policy`."""
    result = policy_store_server.search_policies(["least privilege"])
    assert result["total_matches"] > 0
