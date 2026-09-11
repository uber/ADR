# ADR Discovery — test harness

How to run it, what is built, and what is not. The method and the 120-entry
manifest are specified in [README.md](README.md); this file is about the code.

## Run it

```sh
python3 -m tests.cli check                          # static manifest checks, no guest
python3 -m tests.cli synthesize runs/local --os linux
python3 -m tests.cli score runs/local --html runs/local/score.html
python3 -m tests.cli run --os linux --dry           # records commands, touches no guest
```

`score` exits non-zero when the gate fails, so it can be used directly in CI.

## Shape

Five components, and the boundary between them is a file on disk rather than a
function call. That is what lets a failed run be re-scored without re-running
it, a scoring bug be fixed and replayed against every recorded run, and anyone
debugging a false positive do it without a VM.

```
manifests/*.toml ──► install/runner.py ──► manifest.actual.json ─┐
                            │                                    ├──► scoring/ ──► score.json
provision/driver.py ──► before.json, after.json ─────────────────┘                  report/html.py
```

| Directory | What it is |
|---|---|
| `manifests/` | The 120 entries, in git, reviewed like code. The only place intent is stated. |
| `manifest.py` | The only reader of the above, plus the three static checks. |
| `provision/` | Guest lifecycle behind one four-verb interface. |
| `install/` | Recipe families, executed in dependency order, recording what happened. |
| `scoring/` | A pure function over three JSON files. The product. |
| `report/` | The scorecard. |
| `recorded/` | Captured runs, checked in, used as the scorer's own fixtures. |
| `tools/` | `synthesize.py` — build a run directory without a guest. |

## What is built

Phase P0 of the plan, complete: the scoring engine, the canary check, the
gate, `score.json`, the HTML scorecard, and a synthesizer that produces a
scoreable run without any VM. `recorded/synthetic-linux/` is the checked-in
run the scorer is regression-tested against; it scores 1.0/1.0 by
construction, and every fault the synthesizer can inject is asserted to move
the score.

Four recipe families execute for real against the driver interface:

| Family | Entries | Note |
|---|---|---|
| `declare-mcp` | 27 | JSON/TOML/YAML writers |
| `artifact` | 24 | file and symlink writes |
| `npm-global` | 9 | one command; refuses an unpinned version |
| `baseline-prereq` | 4 | verified, never installed |

On Linux that is 64 of 105 applicable entries, executable today with
`--dry`.

## Bootstrapping a guest

`tools/bootstrap.py` installs the manifest into a guest and verifies each row
independently. It does not import the collector: whether the tools are
*discoverable* is a separate question from whether they are *there*, and
answering the second one first is what makes the first one meaningful.

```sh
python3 -c "from tests.provision.lima import LimaDriver; from tests.tools import bootstrap; \
            print(bootstrap.provision(LimaDriver(), 'linux').counts)"
```

Two drivers are real: `provision/lima.py` (Linux, `limactl shell`) and
`provision/tart.py` (macOS, SSH). Both refuse `restore()` loudly rather than
returning silently — neither guest has a golden snapshot wired up, and a
caller that believes it got a clean machine and did not will report the last
run's leftovers as this run's findings.

### Measured results

| | Linux (`adr-disco-linux`) | macOS (`adr-macos`) |
|---|---|---|
| ok | 64 | 63 |
| failed | 1 | 2 |
| missing | 0 | 0 |
| skipped | 40 | 45 |
| applicable | 105 | 110 |

Ubuntu 24.04.4 aarch64 and macOS 15.7.7 arm64. `skipped` is every family that
needs a vendor installer, a desktop session, a sign-in or model weights.

## What is not built

- **No hypervisor drivers.** `provision/driver.py` defines the interface and a
  dry driver. `qemu.py`, `tart.py` and `images/` do not exist, so `run` only
  accepts `--dry`.
- **Ten recipe families are pending**, each registered with a reason and
  reporting `unavailable` rather than silently succeeding — see
  `install/recipes/PENDING`. They need a guest with vendors, a desktop session
  or model weights on it.
- **No scheduled runs and no trend tracking** (P5).

A pending family reports `unavailable` with a reason on purpose. A family that
quietly no-opped would shrink the denominator, and a denominator that shrinks
silently flatters every recall number after it.

## What the first real run found

- **T-CLI-09 (Goose) is unbuildable as written.** The row installs
  `@block/goose-cli`, which returns 404 from the npm registry — the package
  does not exist under that name at any version. Goose is not distributed on
  npm. This fails identically on both guests and is the one manifest defect
  the bootstrap surfaced.
- **`@kilocode/cli` cannot install on darwin-arm64 here.** Its postinstall
  fails to fetch the platform binary, and installing
  `@kilocode/cli-darwin-arm64` first does not help. Installs cleanly on Linux,
  so this is genuinely platform-specific and would never have surfaced from a
  Linux-only run.
- **`aider-chat` pins a Python range the guest violates.** It requires
  `>=3.10,<3.13`; the macOS guest's Homebrew Python is 3.14, so pipx cannot
  resolve it without being pointed at a 3.12 interpreter. Fixed by installing
  `python@3.12` in the guest. Linux (3.12.3) was unaffected.
- **Docker was absent from the macOS guest.** The CLI is now installed via
  Homebrew, but no daemon runs: Docker Desktop needs a GUI session, so the
  eleven `service` entries remain unrunnable there.
- **A failed npm postinstall leaves a dangling bin symlink.** `command -v` and
  `ls` both report the tool as present; running it says "No such file or
  directory". The recipe now removes the link on failure, because an
  environment carrying a broken symlink is worse than one honestly missing a
  tool.

## Two known gaps in the manifest

Found by field accuracy on the recorded run, and left visible rather than
papered over:

- **16 entries expect a `kind` the collector cannot emit** — `agent` (S-08…11),
  `hook` (S-13…16), `instructions` (S-17…19), `scheduled_agent` (AG-04…07) and
  `ai_frontend` (T-RT-08) are not members of `adr_discovery`'s `Kind`. Field
  accuracy for `kind` is therefore 0.84 on a run that is otherwise perfect.
- **4 entries expect `liveness = scheduled`** (AG-04…07), which `Liveness` does
  not define. `liveness` reads 0.94 for the same reason.

Either the collector's vocabulary grows or those rows change. Until one of
them happens, the numbers above are the floor rather than a regression.

## Scoring notes worth knowing

- **The delta, not the second scan.** Residual baseline noise present in both
  scans is not the manifest's invention.
- **`manifest.actual.json`, not the manifest.** Intent is what we meant to
  install; the recorded outcome is what happened, and only `installed` entries
  are scored.
- **Assets are claimed once.** Nineteen skill rows write into a handful of
  settings files, so rows sharing a key are given one asset each and only a
  genuine surplus is a duplicate.
- **Variants and assertions claim nothing.** A channel variant is scored on
  whether its base tool produced exactly one asset; an `assert_only` row is
  scored on the asset another row installed. Both leave the denominator when
  that base tool does not install.
- **Never pooled across OS.** The denominators differ, so recall and precision
  are reported per category and per OS.
