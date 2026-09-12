import argparse
import sys
from importlib.metadata import version
from unittest.mock import patch

import pytest

from adr_sensor.cli import _non_negative_int, get_version, main


def test_cli_version_matches_package_metadata():
    assert get_version() == version("adr-sensor")


def test_non_negative_int_rejects_negative_limits():
    with pytest.raises(argparse.ArgumentTypeError, match="zero or greater"):
        _non_negative_int("-1")


def test_non_negative_int_accepts_zero():
    assert _non_negative_int("0") == 0


@patch("adr_sensor.cli.AgentObserver")
def test_cli_passes_display_limit_to_observer(mock_observer_class, monkeypatch):
    observer = mock_observer_class.return_value
    observer.ingest_all.return_value = ([], [])
    monkeypatch.setattr(sys, "argv", ["adr-sensor", "--limit", "7", "--no-save"])

    main()

    observer.display_summary.assert_called_once_with([], [], limit=7)
