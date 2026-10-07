# ADR Protection components

The first component is **offline artifact intelligence**: validate a feed, compile it once, and match exact file/skill hashes, package releases, or MCP endpoints. It is an ordinary Python library with no runtime dependencies outside the standard library.

This package does not start a daemon, open an application profile, inspect subject files, install packages, fetch URLs, or make model requests. The host supplies inputs and decides how a match affects an operation. An empty match is **not** a safety verdict or permission to execute.

## Public contract

Import supported interfaces from `adr_protection.api_v1`, not implementation-private helpers. `CONTRACT_VERSION` is `1`; typed JSON records are also exported there.

| Call | Output and behavior |
| --- | --- |
| `parse_feed_json(text_or_bytes)` | A normalized `FeedV1`; bounded UTF-8, duplicate keys and nonfinite values rejected. |
| `validate_feed(value)` | An independent normalized `FeedV1`; rejects malformed/unknown fields and unsupported schema versions. |
| `compose_generation(baseline, custom=None)` | A `GenerationV1` with the same canonical SHA-256 digest as the existing Desktop contract. The baseline namespace cannot be replaced by custom data. |
| `validate_generation(value)` | A normalized, digest-verified generation; corrupt authority is an error, never silently empty intelligence. |
| `compile_generation(value)` | An immutable compiled handle. Obtain it through this function; its constructor and private index layout are not public API. |
| `compiled.match(subject)` / `match_subject(generation, subject)` | Independent `ArtifactMatchV1` rows in baseline/custom and indicator order. Unsupported or incomplete subjects return no matches, not a safe verdict. |
| `compiled.catalog()` | One independent row per active qualified indicator ID; package versions do not duplicate a record. |
| `generation_summary(value)` | Actual active/revoked coverage, feed revisions, and digest. No completeness or safety claim. |
| `normalize_endpoint`, `normalize_registry`, `normalize_package_name` | The same exact-identity rules used by matching. They do not resolve or contact a registry/server. |

Invalid feed/generation/normalization input raises `ValueError`. Do not parse exception-message text as a protocol. References and descriptions are inert data, never instructions. Unknown subject fields are not copied into results.

### Serialized records

- `FeedV1`: `schema_version`, `feed_id`, `revision`, `published_at`, `indicators`.
- `GenerationV1`: `schema_version`, `feeds`, `digest`.
- `ArtifactMatchV1`: `indicator_id`, `source_id`, `feed_id`, `kind`, `summary`, `references`, `target_display`, `generation_digest`.
- Supported kinds: `file_sha256`, `skill_sha256`, `package`, `mcp_endpoint`.
- Package targets bind ecosystem, registry, name, and exact versions. `all_versions: true` is a separate explicit declaration, not the default for a missing version.
- File and skill hashes are distinct identities. Endpoint matching is exact after authority normalization; it is not host/prefix matching.

See [`contracts.py`](adr_protection/contracts.py) for the full typed shapes. These describe the data; runtime validators enforce the cross-field constraints.

### Compatibility policy

The v1 entry point and serialized behavior are stable across implementation moves. The input schemas are closed: incompatible fields, kinds, normalization, matching order, error semantics, or digest changes require a new contract version and migration tests. Adding another independent API does not rewrite v1.

Golden fixtures retain fixed expected generation digests and match rows captured before extraction. Do not regenerate them merely to make a changed implementation pass. Changes to intelligence records are separate from changes to the engine's contract.

## Use in a host

```python
from adr_protection.api_v1 import compile_generation, compose_generation, parse_feed_json

# Feed bytes come from the host's reviewed source, not an automatic downloader.
baseline = parse_feed_json(reviewed_feed_bytes)
generation = compose_generation(baseline)
matcher = compile_generation(generation)

# Identity acquisition, registry provenance, and operation policy belong to the host.
matches = matcher.match({
    "kind": "package",
    "ecosystem": "npm",
    "registry": "https://registry.npmjs.org",
    "name": "example-package",
    "version": "1.0.0",
})
```

Desktop supplies its existing reviewed baseline and retains identity inspection, authorization, consent, scanning, persistence, approvals, and enforcement. Its old `adr_desktop.threat_feed` path is a thin compatibility adapter. Policy schema 1, saved generations, and all existing HTTP/MCP/guardian interfaces are unchanged.

File-policy evaluation and other protection components are follow-up extractions; this package does not claim to be a complete prevention engine.

## Development

From `Protection/`:

```sh
uv sync --locked --extra dev
uv run --locked pytest -q
uv run --locked ruff check adr_protection tests
uv build
```

The component has independent tests and a non-editable-wheel check in Desktop CI. No Desktop, Sensor, Discovery, web framework, or native credential provider is needed to use its public API.
