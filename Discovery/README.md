# ADR Discovery

ADR Discovery answers a question most enterprises cannot answer today: **which AI tools are actually present on this endpoint?**

It inventories desktop AI applications, CLI coding agents, IDE and browser extensions, local model runtimes, MCP servers, and the skills, hooks and scheduled jobs that make an agent programmable. Known tools are fingerprinted against a catalog; unknown ones are scored and queued for review rather than silently dropped.

This is Plane A of ADR Discovery: the endpoint collector. It is standard-library-only on Python 3.11+, so it deploys to hosts that cannot reach PyPI.

## Architecture

A scan runs six stages and emits one snapshot:

```
enumerate → fingerprint → infer → resolve → rank → report
   probes     catalog     open-world  merge   risk   snapshot
```

- **Probes** enumerate candidate surfaces. Each reads the world through an injected `DiscoveryEnv` rather than touching the live machine, so the whole pipeline can be pointed at a fixture world and graded.
- **The catalog** (`adr_discovery/catalog.json`, version `2026.08.18`, 42 entries) fingerprints the tools we know: 13 apps, 12 CLI agents, 7 model runtimes, 5 extensions, 3 AI browsers, plus agent platforms and frontends.
- **The open-world scorer** decides something is an AI tool *without* knowing what it is, from five signals: `runtime_shape`, `state_shape`, `network_intent`, `credential_affinity`, and `mcp_participation`.
- **The resolver** merges every observation into assets, so one tool reached by two paths is one asset rather than two.

A snapshot is emitted even when nothing is found. To fleet coverage, a host that reported an empty inventory and a host that never reported are very different facts.

### Probes

| Probe | What it finds |
| ---------------- | ------------------------------------------------------------------------------ |
| `mcp`            | MCP servers — the highest-risk surface, and the only one that is purely declared |
| `cli_agent`      | CLI coding agents: binaries, the packages that installed them, and state directories proving somebody ran them |
| `app`            | Desktop AI applications, from whichever registry the platform maintains          |
| `runtime`        | Local model runtimes and the weights they hold                                   |
| `extension`      | IDE and browser extensions — where a large share of real shadow AI lives         |
| `agent_artifact` | Skills, commands, hooks, plugins, rules and instruction files                     |
| `scheduler`      | Scheduled, delegated and background agents that run without a person watching     |
| `identity`       | Which account an agent is authenticated as, and how                              |
| `location`       | Agents living outside this OS's own tree (containers, WSL, remote roots)          |
| `process`        | What is actually running, and what it spawned                                     |

## Quick start

```bash
cd Discovery
uv sync --extra dev
uv run adr-discovery
```

Or install the package and use the console script directly:

```bash
pip install -e .
adr-discovery
```

### CLI usage

```bash
adr-discovery                        # scan, print a summary, write a snapshot to ./output
adr-discovery --json                 # print the whole snapshot as JSON
adr-discovery --dry-run              # scan and print, write nothing
adr-discovery --dry-run --explain    # show exactly what would be collected, then scan
adr-discovery --output-dir ./inv     # choose where the snapshot lands
```

`--explain` prints the probes that will run, the catalog version, every redaction rule, and the open-world weights, per probe and per field. It exists so an employee can audit the collector *before* it reports anything.

### Python API

```python
from adr_discovery import discover
from adr_discovery.runner import live_env

snapshot = discover(live_env())
print(snapshot.stats)                     # {'asset_count': ..., 'error_count': ..., 'wall_ms': ...}
for asset in snapshot.assets:
    print(asset.kind, asset.name, asset.version, asset.liveness)
```

Comparing two snapshots is a first-class operation:

```python
from adr_discovery import diff_snapshots, fleet_drift
```

## Output schema

A `DiscoverySnapshot` carries `hostname`, `username`, `platform`, `timestamp`, and four lists:

- **`assets`** — the inventory. Each `DiscoveredAsset` has `kind`, `name`, `identity`, `owner`, `vendor`, `version`, `install_path`, `install_method`, `catalog_id`, `config_scope`, `liveness`, `transport`, `parent_agent`, `models`, `risk`, `last_used`, and a list of `Evidence` recording which probe saw it, on which channel, at which path, and how confidently.
- **`review_queue`** — probable AI, unclassified. Scored by the open-world stage with the signals that fired.
- **`findings`** — currently `undeclared_mcp_server` and `unpinned_mcp_server`.
- **`errors`** — every path the collector refused or failed to read, with a reason. Silence is never used to mean success.

## Privacy

The collector is built to be auditable by the person it runs on. It never collects:

- file contents, beyond allowlisted config keys
- environment variable *values* (names only)
- URL query strings, fragments and userinfo
- values of credential-bearing flags: `--api-key`, `--auth`, `--header`, `--input`, `--message`, `--password`, `--prompt`, `--query`, `--secret`, `--system-prompt`, `--token`, `-m`, `-p`
- anything under `~/.ssh/`, `~/Documents/`, `~/Desktop/`, `~/Pictures/`, `~/Music/`, `~/Movies/`, `~/Library/Mail/`, or the Outlook data directory

Redaction happens inside identity construction, not at the call site, so two callers cannot disagree about it and a rotated credential leaves an asset's identity untouched.

## Testing

The fidelity suite builds fixture endpoints on disk, runs a real scan against each, and reports per-expectation agreement:

```bash
uv run pytest tests/ -q          # 241 cases, fails the build on any regression
python3 tests/run_suite.py       # scorecard: 490 checks, grouped
python3 tests/run_suite.py R-46  # one case
python3 tests/run_suite.py -v    # every check, including passes
```

The scorecard is grouped rather than a single pass count, because "480 of 490" hides which *kind* of wrong it is.

[tests/README.md](tests/README.md) describes the end-to-end fidelity measurement: three VMs, a manifest of real tools installed per OS, and a comparison of what was installed against what the collector reported. [tests/FIXTURE_SUITE.md](tests/FIXTURE_SUITE.md) covers the fast per-commit suite above — the fixture-world DSL, the expectation helpers, the five case groups, and how to add a case.

## Development

```bash
uv sync --extra dev
uv run pytest tests/ -q
uv run ruff check .
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
