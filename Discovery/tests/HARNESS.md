# The end-to-end harness

Implements the method in [../README.md](../README.md): install a known set of AI
tools on a clean VM, scan, and score what the collector reported against what
was actually installed.

```
manifests/*.toml ──► provision ──► install ──► scan ──► scoring ──► score.json
   120 entries       clean guest    by id     twice     pure fn     report.html
```

Everything here is standard-library Python and lives under `Discovery/tests/`.
Nothing outside this directory is imported, including the collector: see
[Why the collector is not imported](#why-the-collector-is-not-imported).

## Running it

```bash
cd Discovery                                    # anything below runs from here

python3 -m tests.manifest_check             # static checks - no VM, what CI runs
python3 -m tests.cli check --catalog adr_discovery/catalog.json
python3 -m tests.cli score tests/recorded/synthetic-linux --report
python3 -m tests.cli run --os linux --out runs/2026-08-linux --driver lima
python3 -m tests.cli run --os mac  --out runs/2026-08-mac \
        --driver tart --image adr-macos --user admin --identity ~/.ssh/adr_e2e

python3 -m unittest discover -s tests -t .       # the harness's own tests
python3 -m tests.tools.faultcheck               # does the scorer respond to known faults?
```

`--driver dry` runs the installer against a guest that records commands instead
of executing them. It exercises ordering, canary substitution and the recorded
outcomes with no hypervisor; it has no collector in it, so the score it produces
is meaningless by construction and says so (every entry a miss, scan failed).

## What is here

| Path | What it is |
| --- | --- |
| `manifests/` | The 120 entries, plus canary shapes and vendor sources. TOML, reviewed like code. |
| `manifest.py` | The only reader of those files. Validates at load; three static checks. |
| `provision/` | `restore`/`run`/`push`/`pull`, and the drivers behind it. |
| `install/` | Executes entries by id in dependency order; writes `manifest.actual.json`. |
| `scoring/` | The product: `(before, after, manifest.actual) → score.json`. |
| `report/` | One self-contained HTML page per run. |
| `recorded/` | Captured runs, checked in - the scoring engine's own fixtures. |
| `test_*.py` | 88 tests for the harness itself. Milliseconds, no VM. |
| `tools/` | `synthesize.py` builds a run directory without a guest; `faultcheck.py` proves the scorer responds to known defects. |

## Status

Built: the manifest, the scoring engine, the report, the Linux and macOS
drivers, the runner, and three of the fourteen recipe families - `declare-mcp`
(27 entries), `artifact` (24) and `npm-global` (9).

Validated against real guests, not only in simulation:

| | guest | applicable | installed | failed |
| --- | --- | ---: | ---: | ---: |
| Linux | Ubuntu 24.04.4 aarch64 (lima) | 105 | 52 | 0 |
| macOS | 15.7.7 arm64 (tart) | 110 | 50 | 1 |
| Windows | — | 103 | — | not validated |

The macOS failure is real and not the harness's: Kilo CLI's own postinstall
fails on macOS arm64 while the same entry installs cleanly on Linux arm64.

The six-entry gap against the plan's P1 target of 60 is the `M-SITE` rows that
declare inside an application's own config directory (`M-SITE-03`..`M-SITE-08`),
which the runner correctly defers until `app-installer` exists.

Windows has no driver here. This host is Apple silicon and cannot run a Windows
guest without a hypervisor that is not installed, so the QEMU driver the plan
describes is deliberately absent rather than shipped unexercised.

The other eleven families record `unimplemented`. That is a deliberate fourth
status alongside `installed` / `unavailable` / `failed`: it keeps those entries
out of the denominator and keeps them loud. `PENDING` in
`install/recipes/__init__.py` names each one and the phase it belongs to.

Two things need a human before a real run:

- **Pins are unconfirmed.** `pins_confirmed = false` in `manifests/tools.toml`.
  The versions there are placeholders; each needs checking against the registry
  it installs from when the golden images are built.
- **57 vendor descriptors are unresolved.** `sources.toml` carries `url = ""`
  for every app installer and vendor binary. `check` lists them; the recipes
  refuse to run an entry whose source is unresolved rather than reporting a
  vendor that stopped shipping.

## Why the collector is not imported

The plan reaches for `diff_snapshots` from the collector to compute the delta.
This harness re-derives it in `scoring/snapshot.py` instead, for two reasons.

The harness must run from this directory alone, so scoring a recorded run needs
nothing installed beside it. That is the practical reason.

The load-bearing one is that a test which imports the thing it measures stops
being able to catch a whole class of defect. If the scorer computed "what
arrived" with the collector's own diff, a diff that dropped assets would drop
them from the measurement too, and the run would score a clean sheet while
quietly measuring less. Re-deriving means the two definitions can disagree - and
a disagreement is exactly the finding worth having.

The cost is that `scoring/snapshot.py` encodes an expectation about the snapshot
format. That is deliberate: the format is the collector's published contract,
and a test that fails when it changes silently is the correct outcome.

## The recorded runs

`recorded/` is the load-bearing directory. A run captured there becomes a
scoring fixture: change the scorer, replay every recorded run, see exactly which
verdicts moved.

`synthetic-linux` is **generated, not captured** - `tools/synthesize.py` built
it from the manifest with four defects injected on purpose (two misses, one
duplicate spanning five entries, one attributed invention, one unattributed).
Its `manifest.actual.json` says `"synthetic": true`, and a test asserts that it
does. It proves the scorer computes what we think it computes. Only a captured
run says anything about the collector.

## Checking the instrument

Two different questions, and both need answering before a score means anything.

`python3 -m unittest discover -s tests -t .` asks whether each piece behaves -
88 tests, no VM, about 70ms.

`python3 -m tests.tools.faultcheck` asks whether the instrument as a whole
responds correctly to known faults. It builds a defect-free control run,
confirms it scores 1.0/1.0 with the gate passing, then injects one real failure
mode at a time - a missed declaration site, one tool reported twice, an
invention, a lookalike believed, a wrong version, a wrong scope, a mutable tag
read as pinned, a leaked credential, silence about an unknown tool, an
unexplained error, and recall below the last accepted run - and checks that the
predicted signal appears and that nothing else moves.

Both halves matter. A scorer that misses a planted duplicate is broken; so is
one that reports defects nobody planted, because every false alarm costs
somebody the afternoon it takes to prove the collector was fine. Run it for each
OS: `--os mac`, `--os win`.

## Scoring, in one paragraph

Entries are matched by shape: an installed tool by catalog id, a declared server
by what it launches *and where it was declared*, an artifact by its path, a
state by the asset it attaches to. One entry matched once is a TP; matched by
two or more assets is a DUP, tracked separately because a duplicate is not a
partial success; matched by none is an FN. An asset no entry claims is an FP,
attributed to a negative control where one explains it. Field accuracy is
computed over true positives only and reported per field, never blended. A
canary leak, a dirty baseline, an unexplained error, any duplicate, a missed
review-queue entry, or recall below the last accepted run for that OS fails the
gate.
