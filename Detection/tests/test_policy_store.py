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
