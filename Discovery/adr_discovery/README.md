# ADR Discovery

ADR Discovery answers a question most enterprises cannot answer today: **which AI tools are actually present on this endpoint?**

It inventories AI binaries, AI agents, MCP servers and skills — accurately enough that a security team can act on the answer, and honestly enough that they can tell when it is incomplete. Known tools are identified against a catalog with proofs; unknown ones are scored on behaviour and queued for review rather than silently dropped.

This is Plane A of ADR Discovery: the endpoint collector. It is standard-library-only on Python 3.11+, so it deploys to hosts that cannot reach PyPI.

## Status

`adr_discovery/` is the implementation that ships today. This README describes the architecture it is being restructured toward — read the module boundaries and the code layout below as the specification, not as a description of the present package tree.

| | |
| --- | --- |
| **Design of record** | `adr-discovery-design.html` — the full argument, the module contracts, and the evidence behind each decision |
| **Shipping today** | `adr_discovery/` — roughly 4,900 lines, the pipeline whose measured behaviour this design responds to |
| **In progress** | The M1–M7 split below, and the end-to-end fidelity harness under `tests/` |

The rewrite exists because the old layout had no boundary a linter could check. Five probes each carried their own copy of `PROJECT_ROOTS`; a filename match was enough to become an asset; and a suite of 490 checks derived from the catalog passed while real placement failures went undetected. The sections below are organized around not repeating that.

## What it has to find

Four targets. They are not variations on one search — each lives somewhere different, is proven by different evidence, and fails differently. They are the contract, and a category the module has no representation for cannot be reported missing.

| Target | Where it lives | What proves it |
| --- | --- | --- |
| **AI binaries** — CLI agents, runtimes, desktop apps, AI browsers, extensions | Package managers, app bundles, extension directories, model stores | An installed artifact: a file, a package record, a listening port |
| **AI agents** — definitions on disk, and live sessions | Process table, definitions, CI, cloud runners | Something running, or arranged to run without a person present |
| **MCP servers** — stdio, SSE, HTTP, containerized | Config files across a dozen host applications, policy stores, bundles | A declaration, and sometimes a running child process. Often nothing on disk at all |
| **Skills** — skills, slash commands, output styles, plugins | Agent state directories, plugins, repositories | A file in a structure an agent knows how to load |

### Deliberately out of scope

Two categories are excluded on purpose rather than by omission, and both are named in `coverage.out_of_scope` so a reader can tell a clean machine from an unasked question.

- **Instruction and rules files** — `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, Cursor and Windsurf rules. These are prose that steers an agent, not software that runs. Their *filenames* remain markers that locate a repository where an agent works; no instruction file becomes an asset.
- **Scripts the agent executes** — hooks, and the mechanisms that start an agent unattended: launchd plists, cron entries, systemd timers, scheduled tasks, login items. Discovery reports the agent, not the mechanism that starts it.

## Architecture

Six sources answer first, a thin endpoint plane turns them into an inventory, and a central plane sees what no endpoint can.

```
                        ┌───────────────────────────────────────────┐
  OS registries  ──┐    │  Endpoint · Plane A                       │
  Filesystem     ──┤    │  no root · no network · seconds           │
  Kernel/runtime ──┼──▶ │                                           │
  Sensor telemetry ┤    │  M1 World access ── the only door         │
  Network egress ──┤    │   ├ M2 Enumerate    where to look         │
  Exec journal   ──┘    │   ├ M3 Extract      what is declared      │ ──▶ snapshot
                        │   ├ M4 Identify     what it really is     │     + coverage
                        │   ├ M5 Resolve      one thing, one asset  │
                        │   ├ M6 Judge        risk, sanction        │
                        │   └ M7 Report       snapshot, delta       │
                        └───────────────────────────────────────────┘
```

### The six sources

Most of what we want to know is already indexed by something; querying it is cheaper and more complete than searching for it.

| Source | Yields |
| --- | --- |
| Package databases — dpkg, rpm, apk, brew, npm, pipx, uv, cargo, go, snap, flatpak | Installed software with provenance attached |
| Application registries — LaunchServices, Uninstall hive, AppX, `.desktop` | Desktop applications, versions, publishers |
| Kernel — `/proc/<pid>/exe`, `cwd`, listening sockets | What is running, from where, and what it serves |
| Application state — browser profiles, IDE extension roots, agent state dirs | Extensions and per-tool state, per profile rather than per default |
| Network — outbound connections, the resolver cache | What the machine *talks to*. The only channel that yields evidence for a tool the catalog has never heard of |
| Exec events — ESF, eBPF, ETW/Sysmon | What *ran between scans*, with argv and parent intact. Optional; absence is a coverage fact, never an empty result |

What no registry indexes — repositories, agent directories, skill folders — is found by a marker-keyed sweep (`.git`, `.claude/`, `.mcp.json`, `agents/`, `skills/`), breadth-ordered under one shared budget, reporting every boundary it hits.

The last two sources answer a different question from the first four. Listening sockets find a *server*; almost every AI tool is a *client*, and the connection it opens is the one piece of evidence it cannot suppress and still function. And a snapshot cannot see a short run — an agent that runs forty seconds a night is absent from every daily scan and present on the machine the whole time.

> **Exec capture is an architectural fork, not a free source.** It is privileged, always-on and buffered — three properties Plane A does not otherwise have. It is optional; an endpoint without it reports execution as an unreached surface. Redaction happens at the ring buffer, filtering to AI-relevant executions, rather than collecting broadly and redacting later.

### The seven modules

| | Module | Owns | Prevents |
| --- | --- | --- | --- |
| M1 | World access | Every read of the machine, under a budget and a deny-list | Escapes, races, silent unreadable surfaces |
| M2 | Enumerator | Where to look: registries first, then a marker sweep | Missing anything outside a remembered path |
| M3 | Extractor | Turning a located surface into declarations | One malformed record erasing a file |
| M4 | Identifier | Deciding what a candidate actually is, and how sure | Renamed tools vanishing; decoys becoming assets |
| M5 | Resolver | Merging observations into assets; confidence; liveness | False splits and false merges |
| M6 | Judge | Risk verdicts, sanction state, findings | Findings the operator learns to dismiss |
| M7 | Reporter | Snapshot, coverage, delta, fleet drift | A partial inventory reading as a complete one |

Three concerns cut across rather than sitting in the line: **C1 Catalog** is data, not code, so the landscape's weekly churn is not on the release train. **C2 Redaction** happens inside whichever stage touches risky text, never as a pass at the end. **C3 Coverage** is written by every stage, because every stage can fail to see something.

## Code structure

One directory per module. Directory names are the module names above verbatim, so the map and the filesystem cannot drift apart.

```
adr_discovery/
├── cli.py                argument parsing, exit codes. Nothing else.
├── pipeline.py           the composition root — the only file importing more than one stage
│
├── contracts/            the types the stages hand each other
│   ├── records.py          Candidate · Declaration · Observation · Asset · Finding
│   ├── evidence.py         Evidence{stage, channel, path, proof, confidence}
│   └── snapshot.py         Snapshot + Coverage — the output shape, versioned
│
├── world/                M1 · the only door to the machine
│   ├── gate.py             canonicalize → contain → verify the fd → read under budget
│   ├── budget.py           one ceiling, shared, and reported when it is hit
│   └── platform/           the only place an OS difference may exist
│       └── darwin.py · linux.py · windows.py
│
├── enumerator/           M2 · where to look
│   ├── sources/            one file per source above — add a source, add a file
│   │   ├── packages.py · appreg.py · kernel.py · appstate.py
│   │   ├── network.py      outbound connections · resolver cache
│   │   └── execjournal.py  ESF · eBPF · ETW/Sysmon — optional
│   ├── sweep.py            marker traversal, breadth-ordered, under the shared budget
│   ├── markers.py          the marker set, as data
│   └── roots.py            priority roots — one definition
│
├── extractor/            M3 · what is declared
│   ├── isolate.py          the per-record try boundary, written once
│   └── formats/            json.py · toml.py · yaml.py · plist.py · workflow.py
│
├── identifier/           M4 · what it really is
│   ├── ladder.py           provenance → content → behaviour → convention, stop at proof
│   ├── verify.py           run the version probe, then check the shape of the answer
│   └── openworld.py        score the uncatalogued on properties, never on names
│
├── resolver/             M5 · one thing, one asset
│   └── keys.py · merge.py · confidence.py
├── judge/                M6 · risk, sanction, findings
│   └── risk.py · sanction.py · findings.py
├── reporter/             M7 · snapshot, coverage, delta
│   └── snapshot.py · delta.py · identity.py
│
├── catalog/              C1 · data, not code
│   ├── catalog.json        ships on its own cadence
│   └── load.py             schema-validated at load; never trusted raw
├── redact/               C2 · imported by whoever touches risky text
└── coverage/             C3 · the ledger every stage writes to
```

### The rules that make it modular

A boundary described only in a document is a boundary that has already been crossed. Each rule is checked by a test that walks the import graph, and that test is a build gate.

| Rule | The regression it prevents |
| --- | --- |
| Only `world/` imports `os`, `pathlib`, `subprocess`, `socket` | Probes quietly growing private file access, each with its own containment bug |
| No stage imports a sibling stage | The cycle that makes any one stage impossible to test alone |
| Only `pipeline.py` imports more than one stage | Execution order becoming an emergent property of the import graph |
| `catalog/` imports nothing from the package | The landscape's weekly churn ending up on the release train |
| Every stage is a function from its input type to its output type, reading no module-level state | `PROJECT_ROOTS` in five files — the defect this rewrite exists for |
| Every stage returns its coverage alongside its result | A partial answer that reads as a clean machine |

Every other guarantee in this file is a claim about intent. The import test is a claim about the code, it runs in under a second, and it fails on the pull request that would have reintroduced the problem.

## The snapshot

One normalized record per asset, keyed so policy can act on it and a delta can track it.

```
asset_id      stable across version upgrades, store rebuilds, credential rotation
kind          cli_agent · app · ai_browser · model_runtime · model_weights
              extension · mcp_server · mcp_bundle · skill · command
              plugin · output_style · agent_definition · ci_agent · cloud_agent
identity      catalog id, or a content-derived identity for the uncatalogued
              name · vendor · version · install_path · install_root · install_method
owner         a person, or "system" — never whoever ran the scan
location      local · wsl:<distro> · container · remote:<host>
evidence[]    {stage, channel, path, proof, confidence}   ← why we believe it
verification  how identity was established: provenance · content · behaviour
confidence    derived from channel count, reported as a band
liveness      running · installed · declared_only
last_used     from Sensor session telemetry
risk          {pinned, factors[], credential_kinds[], env_names[], …}
```

`evidence` makes every claim checkable, and `verification` says which rung of the ladder established identity — so a reader can tell a package-owned binary from a filename that looked right.

### Coverage travels with it

Carried in the snapshot beside the assets, not in a log:

```
coverage:
  roots_swept     which, and to what depth
  boundaries_hit  depth reached · entry cap · budget exhausted
  denied          surfaces refused, and why
  unavailable     registries and services that could not be queried
  truncated       files and lists cut short, with true counts
  probes          which ran, which degraded, which failed
  out_of_scope    categories deliberately not collected, named
```

The rule is one line: **every asset that exists and is not in the snapshot must be explained by a coverage record.** A snapshot is emitted even when nothing is found — to fleet coverage, a host that reported an empty inventory and a host that never reported are very different facts.

## Privacy

This runs on employee laptops in a jurisdictionally messy fleet. The constraints below decide whether it can ship at all.

- **No file contents.** Paths, metadata, hashes and allowlisted config keys only. A skill body holds business context and is not inventory data.
- **Names, never values.** Environment variable names, flag names, hosts and paths survive; their values do not. Query strings, fragments and userinfo are stripped from URLs.
- **Applied at collection**, inside the stage that touches the risky text — not as a filter afterwards, which is something a new probe can be added behind.
- **Both directions are measured.** A leak is obvious; over-redaction is not. A dropped flag name is an undetected permission bypass, so signal retention is measured alongside leak count.
- **Personal paths are denied centrally**, enforced at M1, so a stage added tomorrow inherits it.
- **`--dry-run --explain` prints exactly what would leave the machine**, per stage and per field. The collector is open source; an employee can read it and check.

The tension worth naming: M4's content and provenance evidence is stronger than name matching precisely because it looks harder at the machine. The line held here is *hash and identify, never transmit content; report that a credential is reachable, never which one it is.*

## Testing

Accuracy claims state which layer produced them. A suite whose worlds are built from the catalog measures internal consistency — it cannot measure accuracy, and reporting it as accuracy is how real placement failures survived 490 passing checks.

| Layer | Measures | Ground truth from |
| --- | --- | --- |
| Fixture corpus | Internal consistency, regressions | The catalog — and must be labelled as such |
| Golden endpoints | Real precision and recall | Real installs; the filesystem is the answer key |
| Placement matrices | Whether identity rests on names or on evidence | One artifact, many placements |
| Sensor-attested recall | Hard misses, continuously, in production | Session telemetry — a tool that ran exists |
| Capture–recapture | The unknown unknowns | Two independent channels and their overlap |

### The two instruments

[tests/README.md](../tests/README.md) documents the end-to-end fidelity measurement: real tools installed on a clean guest per OS, a scan before and after, and a comparison of what was installed against what the collector reported. Because it installs real software, signs into real accounts and starts real listeners, it is not part of per-commit CI — it runs against a release candidate, when the catalog changes, and when a new OS version ships.

[tests/FIXTURE_SUITE.md](../tests/FIXTURE_SUITE.md) documents the fast per-commit suite: synthetic endpoints built on disk, scanned by a real pipeline, in about four seconds on any CI box.

The two are complementary and neither replaces the other. The fixture suite has a perfect oracle — it built the machine — but can only contain situations somebody imagined, so it catches regressions. The VM run has real input nobody predicted but a slower, costlier oracle, so it discovers defects. Every defect a VM run finds should be reduced to a fixture case, which is the intended flow of work between them.

Automating that VM run — provision, install a manifest, scan, score, and replay the scoring over recorded runs without touching a VM — is in progress under `tests/`.

Unit tests mirror the package tree — one directory per module, importing only that module. The arrangement is the assertion: a module that cannot be tested without standing up three others does not have a boundary, whatever the directory listing says.

## Build order

Sequenced by how much of the measured failure each step removes, not by module number.

| Step | Work | Closes |
| --- | --- | --- |
| 1 | Extract every hard-coded root into M2; single sweep, single budget, boundaries reported | 4 of 5 in-scope placement misses; duplicated tuples in five files |
| 2 | Kernel and registry sources; all browser profiles | Wrong-path attribution; extensions on non-default profiles; provenance for M4 |
| 3 | M4 evidence ladder with verified version shapes; catalog gains its `proofs` block | The fabricated asset; the renamed agent; missing versions |
| 4 | Content identity in M5; attributes bind to installs | The Ollama split, and its whole class |
| 5 | Coverage ledger as a first-class snapshot field | Every silent boundary, including the ones not yet found |
| 6 | Golden-endpoint corpus and a placement matrix per target, in CI | The circularity that let all of the above pass |

Steps 1 and 2 are mechanical and remove most of the measured miss rate. Step 3 changes the module's character and is the one to be careful with: it must not cost precision.

## License

Apache License 2.0. See [LICENSE](../LICENSE).
