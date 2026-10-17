# ADR Discovery

ADR Discovery inventories AI tooling on an endpoint, including AI binaries,
desktop applications, agents, MCP servers, skills, plugins, and related
programmable surfaces. It records the evidence behind each finding and reports
coverage gaps so an incomplete scan is not mistaken for a clean machine.

The collector runs on Python 3.11+ and has no runtime dependencies outside the
standard library.

## Quick start

Run a scan from this directory with [`uv`](https://docs.astral.sh/uv/):

```sh
uv run adr-discovery --dry-run --json
```

To see exactly what the collector would emit without writing a snapshot:

```sh
uv run adr-discovery --dry-run --explain
```

Use `--output-dir` to save scan output:

```sh
uv run adr-discovery --output-dir ./output
```

Run `uv run adr-discovery --help` for all options.

## Common workflows

Scan a fixture tree instead of the live endpoint:

```sh
uv run adr-discovery --root /path/to/fixture --dry-run --json
```

Compare the current scan with an earlier snapshot:

```sh
uv run adr-discovery --diff /path/to/snapshot.json --dry-run --json
```

Keep a local, owner-only zip of every skill, named by its folder hash:

```sh
uv run adr-discovery --output-dir ./output --archive-skills
```

To report a malicious skill, ask Claude Code to use the
`submit-malicious-skill` skill in `.claude/skills/`: it prepares a GitHub
issue naming the skill's folder hash, and you attach the skill's zip to that
issue.

Apply a tenant policy or last-used telemetry during a scan:

```sh
uv run adr-discovery \
  --policy /path/to/policy.json \
  --telemetry /path/to/telemetry.json \
  --dry-run --json
```

Discovery does not execute binaries that it finds. Machine access is bounded,
and risky text is redacted at collection time.

On Windows, each system inventory helper has a default 10-second limit to
allow for PowerShell cold startup. The remaining whole-scan time can shorten
that limit; explicit helper budgets are preserved. Timeouts are reported as
coverage gaps, without retrying or prewarming helpers.

Socket tables list peer addresses, not hostnames. By default Discovery sends
nothing over the network, so a connection is matched to a model provider only
when its peer is already a name, and the resolver is recorded as unavailable
in coverage. `--resolve` looks up a short list of provider hostnames once
through the host's resolver (bounded to a few seconds, and only when a
connection needs it) and matches peers by address. Only hosts served from a
small fixed set of addresses are resolved; a match is a review signal, never
a finding on its own, and it cannot see through a proxy.

### Policy file

A policy sets each asset's `sanction` (`approved`, `forbidden`, `unsanctioned`
or `unknown`). Catalogued tools are named by catalog id; everything else
(MCP servers, skills, package-launched servers) by identity indicators that use
the same kinds as a shared known-bad artifact feed. See
[`examples/policy.example.json`](examples/policy.example.json).

| Field | Meaning |
| --- | --- |
| `approved`, `forbidden` | Catalog ids |
| `tenant_domains` | Domains you own; other destinations raise `third_party_destination` |
| `approved_indicators`, `forbidden_indicators` | Lists of indicators, below |

| Indicator | Matches |
| --- | --- |
| `{"kind": "skill_sha256", "sha256": ...}` | Skills whose folder hash equals it (`skill_sha256` on the asset; schema 1.2, see the [package documentation](adr_discovery/README.md#the-snapshot)) |
| `{"kind": "file_sha256", "sha256": ...}` | Assets whose `content_hash` equals it |
| `{"kind": "mcp_endpoint", "url": ...}` | MCP servers declaring that URL (scheme/host case, query and trailing slash ignored) |
| `{"kind": "package", "ecosystem": "npm"\|"pypi", "name": ..., "versions": [...] \| "all_versions": true}` | MCP servers launched with `npx`/`bunx`/`pnpm dlx`/`uvx`/`pipx` for that package, and package-manager assets. A launch that pins no version matches only `all_versions` |
| `{"kind": "name", "asset_kind": ..., "name": ...}` | Assets of that kind with exactly that name |

Rules: `forbidden` beats `approved`. A forbidden match raises a high-severity
`forbidden_asset` finding. `unsanctioned` is reported only for assets the policy
addresses: catalogued assets when `approved` is non-empty, and, for
`approved_indicators`, assets of the kinds those indicators describe (skills for
`skill_sha256`, MCP servers for `mcp_endpoint` and `package`, the stated
`asset_kind` for `name`); `file_sha256` addresses no kind. Invalid policy input
is rejected with an error naming the field and entry.

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | The scan completed with full available coverage. |
| `2` | The scan completed, but one or more surfaces were unavailable, unreadable, or truncated. A snapshot is still produced. |
| Other | The command could not complete because of an error or invalid input. |

## Development

Install the development dependencies and run the checks:

```sh
uv sync --extra dev
uv run pytest -q
uv run ruff check .
```

The test suite has two layers:

- `adr_discovery/tests_unit/` verifies modules, contracts, security boundaries,
  and the composed pipeline.
- `tests/` is the black-box endpoint harness used to compare known installations
  with the collector's reported snapshot.

## Project layout

```text
adr_discovery/
  catalog/       known-tool catalog and validation
  contracts/     shared records, evidence, and snapshot types
  coverage/      coverage accounting
  enumerator/    endpoint source enumeration
  extractor/     declaration and surface extraction
  identifier/    evidence-based identification
  judge/         risk, sanction, and finding evaluation
  redact/        sensitive-data redaction
  reporter/      snapshots and deltas
  resolver/      observation merging and confidence
  world/         bounded, platform-specific machine access
  cli.py         command-line interface
  pipeline.py    pipeline composition
tests/           black-box endpoint test harness
```

For the architecture, data model, security boundaries, current limitations,
and implementation details, see the [package documentation](adr_discovery/README.md).
For end-to-end validation and VM provisioning, see the
[test harness documentation](tests/README.md).

## License

Apache-2.0.
