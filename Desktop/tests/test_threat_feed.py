import copy
import hashlib
import json
import socket
import subprocess
import urllib.request
from dataclasses import FrozenInstanceError

import adr_protection.artifacts as threat_feed
import pytest

from adr_desktop.threat_feed import (
    BUNDLED_FEED_ID,
    MAX_FEED_BYTES,
    MAX_GENERATION_BYTES,
    MAX_INDICATORS,
    compile_generation,
    compose_generation,
    generation_summary,
    load_bundled_feed,
    match_subject,
    normalize_endpoint,
    normalize_package_name,
    normalize_registry,
    parse_feed_json,
    validate_feed,
    validate_generation,
)

# Synthetic benign bytes, never presented as public threat intelligence.
SYNTHETIC_DIGEST = hashlib.sha256(b"ADR synthetic artifact test\n").hexdigest()


def indicator(kind="package", *, identifier="synthetic", target=None, **changes):
    if target is None:
        target = {
            "ecosystem": "npm",
            "registry": "https://registry.npmjs.org",
            "name": "@example/synthetic",
            "versions": ["1.2.3"],
        }
    return {
        "id": identifier,
        "kind": kind,
        "status": "active",
        "summary": "Synthetic fixture; not a malware claim.",
        "references": ["https://example.org/advisory"],
        "target": target,
        **changes,
    }


def feed(*records, feed_id=BUNDLED_FEED_ID):
    return {
        "schema_version": 1,
        "feed_id": feed_id,
        "revision": 1,
        "published_at": "2026-10-05T00:00:00Z",
        "indicators": list(records),
    }


def package_subject(name="@example/synthetic", version="1.2.3", **changes):
    return {
        "kind": "package",
        "ecosystem": "npm",
        "registry": "https://registry.npmjs.org",
        "name": name,
        "version": version,
        **changes,
    }


@pytest.fixture
def baseline():
    return compose_generation(load_bundled_feed())


def test_baseline_reports_the_evidence_we_have_and_the_coverage_we_do_not(baseline):
    summary = generation_summary(baseline)
    assert {key: summary[key] for key in (
        "total", "file_sha256", "skill_sha256", "npm", "pypi", "mcp_endpoint", "package_versions",
    )} == {
        "total": 4, "file_sha256": 1, "skill_sha256": 0,
        "npm": 2, "pypi": 1, "mcp_endpoint": 0, "package_versions": 8,
    }
    assert summary["feeds"] == [{
        "feed_id": BUNDLED_FEED_ID, "revision": 1, "published_at": "2026-10-05T00:00:00Z",
        "active": 4, "revoked": 0,
    }]
    assert all(record["references"] for record in baseline["feeds"][0]["indicators"])
    assert not any(record["target"].get("all_versions") for record in baseline["feeds"][0]["indicators"])


@pytest.mark.parametrize("ecosystem,name,version", [
    ("npm", "postmark-mcp", "1.0.16"),
    ("npm", "ua-parser-js", "0.7.29"),
    ("npm", "ua-parser-js", "0.8.0"),
    ("npm", "ua-parser-js", "1.0.0"),
    ("pypi", "ultralytics", "8.3.41"),
    ("pypi", "ultralytics", "8.3.42"),
    ("pypi", "ultralytics", "8.3.45"),
    ("pypi", "ultralytics", "8.3.46"),
])
def test_each_disclosed_package_release_matches(baseline, ecosystem, name, version):
    registry = "https://registry.npmjs.org" if ecosystem == "npm" else "https://pypi.org/simple/"
    matches = match_subject(
        baseline, package_subject(name, version, ecosystem=ecosystem, registry=registry),
    )
    assert len(matches) == 1
    assert matches[0]["indicator_id"].startswith(BUNDLED_FEED_ID + "/")
    assert matches[0]["generation_digest"] == baseline["digest"]


@pytest.mark.parametrize("subject", [
    package_subject("postmark-mcp", "1.0.15"),
    package_subject("postmark-mcp", "1.0.17"),
    package_subject("postmark-mcp", None),
    package_subject("postmark-mcp", "latest"),
    package_subject("postmark-mcp", "^1.0.16"),
    package_subject("postmark-mcp", "1.0.16-beta.1"),
    package_subject("postmark-mcp", "1.0.16+local"),
    package_subject("postmark-mcp", "1.0.16", registry="https://private.example"),
    package_subject("postmark-mcp", "1.0.16", registry="http://registry.npmjs.org"),
    package_subject("@activecampaign/postmark-mcp", "1.0.16"),
    package_subject("my-postmark-mcp", "1.0.16"),
    package_subject("ua-parser-js", "0.7.30"),
    package_subject("ua-parser-js", "0.8.1"),
    package_subject("ua-parser-js", "1.0.1"),
    package_subject("mcp-remote", "0.1.15"),
    package_subject("ultralytics", "8.3.43", ecosystem="pypi", registry="https://pypi.org"),
    package_subject("ultralytics", "8.3.41+local", ecosystem="pypi", registry="https://pypi.org"),
    package_subject("torchtriton", None, ecosystem="pypi", registry="https://pypi.org"),
])
def test_unlisted_releases_names_and_origins_never_inherit_a_malicious_label(baseline, subject):
    assert match_subject(baseline, subject) == []


def test_pytorch_digest_is_a_file_hash_not_a_skill_hash(baseline):
    digest = "2385b29489cd9e35f92c072780f903ae2e517ed422eae67246ae50a5cc738a0e"
    assert len(match_subject(baseline, {"kind": "file_sha256", "sha256": digest})) == 1
    assert match_subject(baseline, {"kind": "skill_sha256", "sha256": digest}) == []
    assert match_subject(baseline, {"kind": "file_sha256", "sha256": SYNTHETIC_DIGEST}) == []


@pytest.mark.parametrize("kind", ["file_sha256", "skill_sha256"])
def test_explicit_hash_kinds_match_only_the_complete_identity(kind):
    generation = compose_generation(feed(indicator(kind, target={"sha256": SYNTHETIC_DIGEST})))
    assert len(match_subject(generation, {"kind": kind, "sha256": SYNTHETIC_DIGEST})) == 1
    assert match_subject(generation, {"kind": kind, "sha256": SYNTHETIC_DIGEST[:32]}) == []
    other_kind = "skill_sha256" if kind == "file_sha256" else "file_sha256"
    assert match_subject(generation, {"kind": other_kind, "sha256": SYNTHETIC_DIGEST}) == []


@pytest.mark.parametrize("raw,expected", [
    ("Example.._Name", "example-name"),
    ("example---name", "example-name"),
    ("EXAMPLE.name", "example-name"),
])
def test_pypi_normalization_is_ecosystem_specific(raw, expected):
    assert normalize_package_name("pypi", raw) == expected
    target = {"ecosystem": "pypi", "registry": "https://pypi.org", "name": raw, "versions": ["1.2.3"]}
    generation = compose_generation(feed(indicator(target=target)))
    assert match_subject(
        generation, package_subject(expected, ecosystem="pypi", registry="https://pypi.org"),
    )


def test_npm_keeps_scope_and_punctuation_and_rejects_noncanonical_uppercase():
    assert normalize_package_name("npm", "@example/a_b") == "@example/a_b"
    assert normalize_package_name("npm", "a.b") == "a.b"
    with pytest.raises(ValueError):
        normalize_package_name("npm", "Example")
    generation = compose_generation(feed(indicator()))
    assert match_subject(generation, package_subject()) != []
    assert match_subject(generation, package_subject("synthetic")) == []
    assert match_subject(generation, package_subject("@elsewhere/synthetic")) == []


@pytest.mark.parametrize("ecosystem,url,expected", [
    ("npm", "https://REGISTRY.NPMJS.ORG:443/", "https://registry.npmjs.org"),
    ("pypi", "https://PYPI.ORG/simple/", "https://pypi.org"),
    ("pypi", "https://pypi.org/", "https://pypi.org"),
    ("pypi", "https://private.example/simple/", "https://private.example/simple"),
    ("npm", "https://private.example/team-a/", "https://private.example/team-a"),
    ("npm", "http://registry.npmjs.org", "http://registry.npmjs.org"),
])
def test_registry_normalization_does_not_collapse_private_repositories(ecosystem, url, expected):
    assert normalize_registry(ecosystem, url) == expected


@pytest.mark.parametrize("version", [None, "9.9.9", "1.2.3-beta.1"])
def test_all_versions_requires_an_explicit_record_and_still_binds_name_and_origin(version):
    record = indicator()
    record["target"].pop("versions")
    record["target"]["all_versions"] = True
    generation = compose_generation(feed(record))
    assert match_subject(generation, package_subject(version=version))
    assert match_subject(
        generation, package_subject(version=version, registry="https://other.example"),
    ) == []
    assert generation_summary(generation)["package_versions"] == 0


@pytest.mark.parametrize("url,matched", [
    ("https://MCP.EXAMPLE:443/Tool", True),
    ("https://mcp.example/Tool", True),
    ("http://mcp.example/Tool", False),
    ("https://mcp.example/tool", False),
    ("https://mcp.example/Tool/", False),
    ("https://mcp.example.evil.test/Tool", False),
    ("https://mcp.example:444/Tool", False),
    ("https://mcp.example/Tool?token=secret", False),
    ("https://secret@mcp.example/Tool", False),
    ("https://mcp.example/Tool#fragment", False),
    ("https://mcp.example/%54ool", False),
])
def test_endpoint_matches_are_exact_not_host_or_prefix_matches(url, matched):
    generation = compose_generation(feed(indicator("mcp_endpoint", target={"url": "https://mcp.example/Tool"})))
    assert bool(match_subject(generation, {"kind": "mcp_endpoint", "url": url})) is matched


def test_endpoint_root_and_ipv6_authority_normalization_are_explicit():
    assert normalize_endpoint("https://MCP.EXAMPLE:443") == "https://mcp.example/"
    assert normalize_endpoint("http://[0:0:0:0:0:0:0:1]:80/mcp") == "http://[::1]/mcp"


@pytest.mark.parametrize("url", [
    "file:///tmp/server", "https://mcp.example/path?", "https://mcp.example/path#",
    "https://mcp.example:0/path", "https://mcp.example:/path", "https://mcp.example:99999/path",
    "https://mcp.example\\@other.example/", "https://mcp.example/%XX", "https://mcp.example/\n",
    "https://mcp.example./", "https://éxample.org/", "https://mcp.example/a b",
])
def test_ambiguous_or_credential_capable_url_shapes_are_rejected(url):
    with pytest.raises(ValueError):
        normalize_endpoint(url)


def test_revocations_are_inert_and_custom_ids_cannot_revoke_the_baseline():
    bundled = feed(indicator())
    revoked = indicator(status="revoked", revoked_reason="Synthetic fixture withdrawn.")
    custom = feed(revoked, feed_id="owner-local")
    generation = compose_generation(bundled, custom)
    matches = match_subject(generation, package_subject())
    assert [row["indicator_id"] for row in matches] == [BUNDLED_FEED_ID + "/synthetic"]
    assert generation_summary(generation)["revoked"] == 1
    assert generation_summary(generation)["total"] == 1
    with pytest.raises(ValueError, match="impersonate"):
        compose_generation(bundled, feed(revoked))


def test_equal_record_ids_in_distinct_namespaces_retain_both_sources():
    generation = compose_generation(feed(indicator()), feed(indicator(), feed_id="owner-local"))
    matches = match_subject(generation, package_subject())
    assert {row["indicator_id"] for row in matches} == {
        BUNDLED_FEED_ID + "/synthetic", "owner-local/synthetic",
    }


@pytest.mark.parametrize("change", [
    {"schema_version": True}, {"schema_version": 2}, {"revision": True}, {"revision": -1},
    {"published_at": "2026-02-30T00:00:00Z"}, {"published_at": "2026-10-05"},
    {"published_at": "2026-10-05T00:00:00+02:00"}, {"feed_id": "../other"},
    {"unexpected": "field"}, {"indicators": {}},
])
def test_invalid_feed_headers_fail_as_a_whole(change):
    value = feed(indicator())
    value.update(change)
    with pytest.raises(ValueError):
        validate_feed(value)


@pytest.mark.parametrize("change", [
    {"id": "bad/id"}, {"status": "suspected"}, {"kind": "regex"},
    {"summary": "Hidden \u202e instruction"}, {"summary": "s" * 513},
    {"target": {"name": "synthetic"}}, {"unexpected": "field"},
    {"status": "revoked"}, {"revoked_reason": "not revoked"},
    {"references": ["https://example.org/?token=secret"]},
    {"references": ["http://example.org/advisory"]},
    {"references": ["https://example.org/"] * 2},
    {"references": ["https://example.org/"] * 9},
])
def test_invalid_records_reject_the_feed_not_just_one_record(change):
    invalid = indicator(identifier="invalid", **change)
    with pytest.raises(ValueError):
        validate_feed(feed(indicator(), invalid))


@pytest.mark.parametrize("version", ["latest", "*", "^1.2.3", ">=1.2.3", "1.2", "1.2.3\n"])
def test_npm_feed_targets_cannot_smuggle_ranges_or_tags(version):
    record = indicator()
    record["target"]["versions"] = [version]
    with pytest.raises(ValueError):
        validate_feed(feed(record))


@pytest.mark.parametrize("target_change", [
    {"versions": []}, {"versions": ["1.2.3", "1.2.3"]}, {"versions": ["1.2.3"] * 129},
    {"all_versions": True}, {"all_versions": False}, {"regex": ".*"},
    {"registry": "https://token@registry.npmjs.org"},
])
def test_package_targets_are_one_exact_closed_shape(target_change):
    record = indicator()
    record["target"].update(target_change)
    with pytest.raises(ValueError):
        validate_feed(feed(record))


def test_omitted_versions_does_not_implicitly_mean_all_versions():
    record = indicator()
    record["target"].pop("versions")
    with pytest.raises(ValueError):
        validate_feed(feed(record))


def test_duplicate_json_keys_and_indicator_ids_are_rejected():
    raw = json.dumps(feed(indicator()))
    with pytest.raises(ValueError, match="Duplicate JSON"):
        parse_feed_json(raw.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1'))
    with pytest.raises(ValueError, match="Duplicate JSON"):
        parse_feed_json(raw.replace('"name": "@example/synthetic"', '"name": "a", "name": "b"'))
    with pytest.raises(ValueError, match="Duplicate indicator"):
        validate_feed(feed(indicator(), indicator()))


@pytest.mark.parametrize("raw", [b"\xff", '{"a":NaN}', '{"a":Infinity}', '{"a":1.5}', "[]", "null"])
def test_non_json_or_unsupported_json_values_raise_value_error(raw):
    with pytest.raises(ValueError):
        parse_feed_json(raw)


def test_depth_and_size_limits_reject_inputs_without_recursing_unboundedly():
    with pytest.raises(ValueError):
        parse_feed_json("[" * 10000 + "]" * 10000)
    with pytest.raises(ValueError):
        parse_feed_json(" " * (MAX_FEED_BYTES + 1))
    nested = {}
    for _ in range(10):
        nested = {"nested": nested}
    with pytest.raises(ValueError):
        validate_feed(nested)
    cyclic = {}
    cyclic["loop"] = cyclic
    with pytest.raises(ValueError):
        validate_feed(cyclic)
    with pytest.raises(ValueError):
        validate_feed(feed(*[indicator(identifier=f"r-{index}") for index in range(MAX_INDICATORS + 1)]))


def test_combined_generation_limits_apply_even_when_individual_feeds_fit():
    records = [indicator(identifier=f"r-{index}") for index in range(1100)]
    with pytest.raises(ValueError):
        compose_generation(feed(*records), feed(*records, feed_id="owner-local"))
    # Short records make each feed fit, while the combined byte budget fails.
    records = [
        indicator("file_sha256", identifier=f"r-{index}", target={"sha256": SYNTHETIC_DIGEST},
                  summary="x" * 400)
        for index in range(500)
    ]
    assert validate_feed(feed(*records))
    with pytest.raises(ValueError, match="byte limit"):
        compose_generation(feed(*records), feed(*records, feed_id="owner-local"))


def test_generation_is_deterministic_independent_data_with_a_verified_digest():
    first = indicator(identifier="z")
    second = indicator(identifier="a")
    source = feed(first, second)
    generation = compose_generation(source)
    assert len(json.dumps(generation).encode()) < MAX_GENERATION_BYTES
    assert generation == compose_generation(feed(second, first))
    assert generation == validate_generation(json.loads(json.dumps(generation)))
    source["indicators"][0]["target"]["versions"].append("9.9.9")
    assert "9.9.9" not in generation["feeds"][0]["indicators"][1]["target"]["versions"]
    tampered = copy.deepcopy(generation)
    tampered["feeds"][0]["indicators"][0]["target"]["versions"] = ["9.9.9"]
    with pytest.raises(ValueError, match="digest"):
        validate_generation(tampered)
    with pytest.raises(ValueError, match="digest"):
        match_subject(tampered, {})


@pytest.mark.parametrize("change", [
    {"schema_version": True}, {"feeds": []}, {"feeds": [{}, {}, {}]},
    {"digest": "0" * 63}, {"extra": "field"},
])
def test_generation_shape_is_closed(change, baseline):
    value = copy.deepcopy(baseline)
    value.update(change)
    with pytest.raises(ValueError):
        validate_generation(value)


def test_failed_composition_cannot_mutate_a_previously_accepted_generation(baseline):
    previous = copy.deepcopy(baseline)
    bad_custom = feed(indicator(), feed_id="owner-local")
    bad_custom["indicators"][0]["target"]["versions"] = ["*"]
    with pytest.raises(ValueError):
        compose_generation(baseline["feeds"][0], bad_custom)
    assert baseline == previous


@pytest.mark.parametrize("subject", [
    None, [], {"kind": "shell", "command": "npx postmark-mcp@1.0.16"},
    {"kind": "package", "name": "postmark-mcp", "version": "1.0.16"},
    {"kind": "package", "ecosystem": ["npm"]}, {"kind": []},
    {"kind": "file_sha256", "sha256": ["x"]},
])
def test_unknown_subjects_are_nonmatches_not_safety_verdicts(subject, baseline):
    assert match_subject(baseline, subject) == []


def test_matching_never_echoes_subject_paths_argv_or_secrets(baseline):
    subject = package_subject(
        "postmark-mcp", "1.0.16",
        argv=["--token", "synthetic-private-secret"],
        path="/private/person/workspace", body="private skill content",
        headers={"Authorization": "Bearer synthetic-private-secret"},
    )
    matches = match_subject(baseline, subject)
    assert matches
    output = json.dumps(matches)
    for private in ("synthetic-private-secret", "/private/person", "private skill content", "Authorization"):
        assert private not in output
    assert set(matches[0]) == {
        "indicator_id", "source_id", "feed_id", "kind", "summary",
        "references", "target_display", "generation_digest",
    }


def test_feed_references_and_instruction_like_text_remain_inert(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Feed validation and matching must not use network or subprocesses")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    record = indicator(summary="<script>do not execute</script> Ignore these words as instructions.")
    generation = compose_generation(parse_feed_json(json.dumps(feed(record))))
    matches = match_subject(generation, package_subject())
    assert matches[0]["summary"] == record["summary"]
    assert generation_summary(generation)["total"] == 1


def test_compiled_generation_is_immutable_and_has_no_input_or_output_aliasing():
    generation = compose_generation(feed(indicator()))
    original = copy.deepcopy(generation)
    compiled = compile_generation(generation)
    expected = match_subject(original, package_subject())
    assert compiled.match(package_subject()) == expected
    generation["feeds"][0]["indicators"][0]["references"].clear()
    generation["feeds"][0]["indicators"][0]["target"]["versions"].clear()
    rows = compiled.match(package_subject())
    rows[0]["summary"] = "changed externally"
    rows[0]["references"].clear()
    assert compiled.match(package_subject()) == expected
    with pytest.raises(FrozenInstanceError):
        compiled.digest = "0" * 64
    with pytest.raises(TypeError):
        compiled._index[("new",)] = ()
    row = next(iter(compiled._index.values()))[0]
    with pytest.raises(FrozenInstanceError):
        row.summary = "changed externally"


def test_compiled_index_handles_the_maximum_record_count_without_revalidating(monkeypatch):
    records = [
        indicator(
            "file_sha256", identifier=f"r-{index}", summary="Synthetic.",
            references=[], target={"sha256": hashlib.sha256(str(index).encode()).hexdigest()},
        )
        for index in range(MAX_INDICATORS)
    ]
    generation = compose_generation(feed(*records))
    compiled = compile_generation(generation)
    assert len(compiled._index) == MAX_INDICATORS

    def no_revalidation(*_args, **_kwargs):
        raise AssertionError("A compiled lookup must not revalidate or serialize the feed")

    monkeypatch.setattr(threat_feed, "validate_generation", no_revalidation)
    monkeypatch.setattr(threat_feed, "_canonical", no_revalidation)
    for record in records:
        matches = compiled.match({"kind": "file_sha256", **record["target"]})
        assert len(matches) == 1
        assert matches[0]["indicator_id"] == BUNDLED_FEED_ID + "/" + record["id"]
    assert compiled.match({"kind": "file_sha256", "sha256": SYNTHETIC_DIGEST}) == []


def test_compiled_exact_and_all_version_matches_preserve_feed_record_order():
    all_versions = indicator(identifier="a-all")
    all_versions["target"].pop("versions")
    all_versions["target"]["all_versions"] = True
    exact = indicator(identifier="z-exact")
    generation = compose_generation(feed(all_versions, exact))
    compiled = compile_generation(generation)
    assert [row["indicator_id"] for row in compiled.match(package_subject())] == [
        BUNDLED_FEED_ID + "/a-all", BUNDLED_FEED_ID + "/z-exact",
    ]
    assert [row["indicator_id"] for row in compiled.match(package_subject(version=None))] == [
        BUNDLED_FEED_ID + "/a-all",
    ]


@pytest.mark.parametrize("records,custom,expected_ids", [
    ([indicator()], None, [BUNDLED_FEED_ID + "/synthetic"]),
    ([indicator(status="revoked", revoked_reason="Fixture withdrawn.")], None, []),
    (
        [indicator(target={
            "ecosystem": "npm", "registry": "https://registry.npmjs.org",
            "name": "@example/synthetic", "versions": ["1.2.3", "1.2.4"],
        })],
        None,
        [BUNDLED_FEED_ID + "/synthetic"],
    ),
    (
        [indicator(identifier="a"), indicator(identifier="b")],
        feed(indicator(identifier="a"), feed_id="owner-local"),
        [BUNDLED_FEED_ID + "/a", BUNDLED_FEED_ID + "/b", "owner-local/a"],
    ),
])
def test_catalog_coalesces_indexed_versions_not_distinct_indicator_ids(records, custom, expected_ids):
    generation = compose_generation(feed(*records), custom)
    compiled = compile_generation(generation)
    catalog = compiled.catalog()
    assert list(catalog) == expected_ids
    for qualified_id, row in catalog.items():
        assert row["indicator_id"] == qualified_id
        assert row["generation_digest"] == compiled.digest == generation["digest"]
    assert catalog == {row["indicator_id"]: row for row in compiled.match(package_subject())}


@pytest.mark.parametrize("kind,target,subject", [
    ("package", None, package_subject()),
    (
        "file_sha256", {"sha256": SYNTHETIC_DIGEST},
        {"kind": "file_sha256", "sha256": SYNTHETIC_DIGEST},
    ),
    (
        "skill_sha256", {"sha256": SYNTHETIC_DIGEST},
        {"kind": "skill_sha256", "sha256": SYNTHETIC_DIGEST},
    ),
    (
        "mcp_endpoint", {"url": "https://example.org/mcp"},
        {"kind": "mcp_endpoint", "url": "https://example.org/mcp"},
    ),
])
def test_catalog_rows_are_independent_of_inputs_other_catalogs_and_matching(kind, target, subject):
    generation = compose_generation(feed(indicator(kind, target=target)))
    compiled = compile_generation(generation)
    expected = compiled.match(subject)[0]
    identifier = expected["indicator_id"]
    catalog = compiled.catalog()
    assert catalog[identifier] == expected
    catalog[identifier]["references"].clear()
    catalog[identifier]["summary"] = "Modified outside the matcher."
    catalog.clear()
    generation["feeds"][0]["indicators"].clear()
    assert compiled.catalog() == {identifier: expected}
    assert compiled.match(subject) == [expected]


def test_catalog_does_not_rematch_or_revalidate_records(monkeypatch, baseline):
    compiled = compile_generation(baseline)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Catalog enumeration uses compiled rows only")

    monkeypatch.setattr(threat_feed, "validate_generation", forbidden)
    monkeypatch.setattr(threat_feed.CompiledGeneration, "match", forbidden)
    catalog = compiled.catalog()
    assert len(catalog) == 4
    assert all(row["generation_digest"] == baseline["digest"] for row in catalog.values())
