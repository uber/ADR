import tomllib
from pathlib import Path

import pytest

from scripts.build_macos import build_identity, required_python_modules, validate_python_modules


def test_preview_identity_matches_project_version_and_selected_commit():
    revision = "a" * 40
    project = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text())["project"]
    identity = build_identity(42, revision)
    assert identity == {
        "CFBundleVersion": "42",
        "CFBundleShortVersionString": project["version"],
        "ADRBuildChannel": "development",
        "ADRSourceRevision": revision,
    }


def test_unstamped_local_build_does_not_claim_a_clean_commit():
    assert "ADRSourceRevision" not in build_identity(1, None)


@pytest.mark.parametrize("number,revision", [
    (0, None), (-1, None), (1, "short-sha"), (1, "main"),
    (1, "a" * 40 + "\n"), (1, "../local/path"),
])
def test_invalid_build_identity_is_rejected(number, revision):
    with pytest.raises(ValueError):
        build_identity(number, revision)


def test_bundle_validation_requires_frozen_parsers_not_just_copied_source_files():
    modules = required_python_modules()
    assert "adr_sensor.parsers.claude_parser" in modules
    assert "adr_sensor.parsers.codex_parser" in modules
    assert "adr_sensor.parsers.antigravity_parser" in modules
    listing = "\n".join(" " + name for name in modules)
    validate_python_modules(listing)
    copied_only = listing.replace("adr_sensor.parsers.codex_parser", "adr_sensor/parsers/codex_parser.py")
    with pytest.raises(ValueError, match=r"adr_sensor\.parsers\.codex_parser"):
        validate_python_modules(copied_only)


def test_bundle_validation_rejects_a_missing_runtime_dependency():
    listing = "\n".join(required_python_modules() - {"tabulate"})
    with pytest.raises(ValueError, match="tabulate"):
        validate_python_modules(listing)
