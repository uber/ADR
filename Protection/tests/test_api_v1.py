import ast
import copy
import json
import socket
import subprocess
import sys
import urllib.request
from pathlib import Path

import pytest

from adr_protection import api_v1

FIXTURE = Path(__file__).parent / "fixtures" / "artifact_v1.json"


@pytest.fixture
def contract():
    return json.loads(FIXTURE.read_text())


def test_v1_golden_contract_preserves_normalization_digest_matches_and_summary(contract):
    # Expected bytes/rows were captured before extraction, not generated from
    # the implementation under test.
    source = contract["input"]
    generation = api_v1.compose_generation(source)
    assert api_v1.CONTRACT_VERSION == 1
    assert generation == contract["generation"]
    assert api_v1.validate_generation(generation) == contract["generation"]
    assert api_v1.parse_feed_json(json.dumps(source)) == contract["generation"]["feeds"][0]
    assert api_v1.parse_feed_json(json.dumps(source).encode()) == contract["generation"]["feeds"][0]
    assert api_v1.match_subject(generation, contract["subject"]) == contract["matches"]
    compiled = api_v1.compile_generation(generation)
    assert compiled.match(contract["subject"]) == contract["matches"]
    assert compiled.catalog() == {row["indicator_id"]: row for row in contract["matches"]}
    assert api_v1.generation_summary(generation) == contract["summary"]
    assert set(generation) == api_v1.GenerationV1.__required_keys__
    assert set(generation["feeds"][0]) == api_v1.FeedV1.__required_keys__
    assert set(contract["matches"][0]) == api_v1.ArtifactMatchV1.__required_keys__


@pytest.mark.parametrize("changed", [
    {"version": "1.0.1"},
    {"version": None},
    {"name": "another-package"},
    {"registry": "https://private.example"},
    {"ecosystem": "npm"},
])
def test_unknown_identity_is_a_nonmatch_not_a_safe_verdict(contract, changed):
    subject = {**contract["subject"], **changed}
    assert api_v1.match_subject(contract["generation"], subject) == []


@pytest.mark.parametrize("kind,target,subject", [
    ("file_sha256", {"sha256": "a" * 64}, {"kind": "file_sha256", "sha256": "a" * 64}),
    ("skill_sha256", {"sha256": "b" * 64}, {"kind": "skill_sha256", "sha256": "b" * 64}),
    ("mcp_endpoint", {"url": "https://example.org/mcp"}, {
        "kind": "mcp_endpoint", "url": "https://EXAMPLE.ORG:443/mcp",
    }),
])
def test_all_non_package_identity_kinds_use_the_same_public_contract(contract, kind, target, subject):
    source = contract["input"]
    source["indicators"][0].update(kind=kind, target=target)
    matches = api_v1.compile_generation(api_v1.compose_generation(source)).match(subject)
    assert len(matches) == 1 and matches[0]["kind"] == kind
    assert set(matches[0]) == api_v1.ArtifactMatchV1.__required_keys__


def test_custom_feed_order_revocations_and_explicit_all_versions_are_preserved(contract):
    baseline = contract["input"]
    custom = copy.deepcopy(baseline)
    custom["feed_id"] = "owner-local"
    target = custom["indicators"][0]["target"]
    target.pop("versions")
    target["all_versions"] = True
    compiled = api_v1.compile_generation(api_v1.compose_generation(baseline, custom))
    assert [row["indicator_id"] for row in compiled.match(contract["subject"])] == [
        "adr-public-artifacts/sample", "owner-local/sample",
    ]
    assert [row["indicator_id"] for row in compiled.match({**contract["subject"], "version": None})] == [
        "owner-local/sample",
    ]
    custom["indicators"][0].update(status="revoked", revoked_reason="Inert fixture withdrawn.")
    generation = api_v1.compose_generation(baseline, custom)
    assert api_v1.match_subject(generation, contract["subject"]) == [
        {**contract["matches"][0], "generation_digest": generation["digest"]},
    ]
    assert api_v1.generation_summary(generation)["revoked"] == 1
    custom["feed_id"] = baseline["feed_id"]
    with pytest.raises(ValueError):
        api_v1.compose_generation(baseline, custom)


@pytest.mark.parametrize("change", [
    {"schema_version": 2}, {"schema_version": True}, {"revision": -1},
    {"unexpected_field": "not a v1 field"}, {"indicators": {}},
])
def test_closed_feed_contract_rejects_incompatible_data(contract, change):
    with pytest.raises(ValueError):
        api_v1.validate_feed({**contract["input"], **change})


@pytest.mark.parametrize("raw", [
    b"\xff", '{"schema_version":1,"schema_version":1}', '{"value":NaN}',
    '{"value":Infinity}', "[]", "null", " " * (api_v1.MAX_FEED_BYTES + 1),
])
def test_strict_json_validation_is_part_of_the_component(raw):
    with pytest.raises(ValueError):
        api_v1.parse_feed_json(raw)


def test_corrupt_authority_is_not_replaced_with_empty_matches(contract):
    generation = contract["generation"]
    generation["digest"] = "0" * 64
    with pytest.raises(ValueError):
        api_v1.compile_generation(generation)
    with pytest.raises(ValueError):
        api_v1.match_subject(generation, {})


def test_compiled_results_are_independent_and_do_not_echo_private_subject_data(contract):
    generation = contract["generation"]
    compiled = api_v1.compile_generation(generation)
    subject = {**contract["subject"], "path": "/private/example", "credential": "synthetic-private-value"}
    matches = compiled.match(subject)
    assert matches == contract["matches"]
    generation["feeds"].clear()
    matches[0]["references"].clear()
    matches[0]["summary"] = "Changed externally"
    assert compiled.match(subject) == contract["matches"]
    assert "/private/example" not in json.dumps(compiled.match(subject))


def test_component_operations_do_not_access_files_network_or_processes(contract, monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("The component must not perform host I/O")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(Path, "open", forbidden)
    parsed = api_v1.parse_feed_json(json.dumps(contract["input"]))
    generation = api_v1.compose_generation(parsed)
    assert api_v1.compile_generation(generation).match(contract["subject"]) == contract["matches"]


def test_component_imports_are_only_standard_library_or_internal():
    package = Path(api_v1.__file__).parent
    for path in package.glob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                names = [(node.module or "").split(".")[0]]
            else:
                continue
            assert set(names) <= sys.stdlib_module_names, (path.name, names)
