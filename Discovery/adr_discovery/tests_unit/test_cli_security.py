"""Security defaults at the process boundary."""

import os

import pytest

from adr_discovery import cli
from adr_discovery.cli import _load_json_mapping, _terminal, _write_private, build_parser
from adr_discovery.world.gate import Gate


def test_discovered_subprocess_api_does_not_exist():
    assert not hasattr(Gate(), "run")
    assert "allow-subprocess" not in build_parser().format_help()


def test_snapshot_is_private_and_never_overwrites(tmp_path):
    output = tmp_path / "output"
    target = _write_private(str(output), "snapshot.json", "{}")

    assert os.stat(target).st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        _write_private(str(output), "snapshot.json", "replacement")


def test_snapshot_target_symlink_is_not_followed(tmp_path):
    output = tmp_path / "output"
    output.mkdir()
    victim = tmp_path / "victim"
    victim.write_text("safe")
    (output / "snapshot.json").symlink_to(victim)

    with pytest.raises(FileExistsError):
        _write_private(str(output), "snapshot.json", "owned")

    assert victim.read_text() == "safe"


def test_terminal_controls_and_bidi_are_escaped():
    assert _terminal("good\x1b[31m\u202eevil") == "good\\x1b[31m\\u202eevil"


def test_optional_json_must_be_a_bounded_object(tmp_path, monkeypatch):
    document = tmp_path / "input.json"
    document.write_text("[]")
    with pytest.raises(ValueError, match="root must be an object"):
        _load_json_mapping(str(document), "test")

    monkeypatch.setattr(cli, "MAX_JSON_INPUT", 2)
    document.write_text("{} ")
    with pytest.raises(ValueError, match="exceeds"):
        _load_json_mapping(str(document), "test")
