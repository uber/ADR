# The discovery fidelity suite

This suite answers one question: **when ADR Discovery scans a machine, does it report what is actually there?**

It does not mock the collector. Each case builds a fixture endpoint on disk — real files, real symlinks, real directory layouts — injects a synthetic process table, socket list and registry, then runs a **real scan** through the same `discover()` entry point the CLI uses. What the scan reports is compared against what the case declared.

241 cases produce 490 individual checks.

## Why a scorecard, not a pass count

`run_suite.py` reports agreement per group rather than a single number, because "480 of 490" hides *which kind* of wrong it is. A suite that loses ten checks in the MCP group has a different problem from one that loses ten spread across counting and phantoms, and a single total makes the two look identical.

```
checks by group:
  AG   68/68
  M    82/82
  R   125/125
  S    80/80
  T   135/135

490/490 checks pass, 0 cases with failures
```

`test_fidelity.py` wraps the same runner in pytest so any regression fails the build. The two are not redundant: the scorecard is for reading, the pytest wrapper is for gating.

## Running it

```bash
cd Discovery

uv run pytest tests/ -q          # 241 parametrized cases, one per case id
python3 tests/run_suite.py       # the grouped scorecard
python3 tests/run_suite.py -v    # every check, including the ones that pass
python3 tests/run_suite.py R     # only the hardening group
python3 tests/run_suite.py R-46  # one case
```

The filter argument is a prefix match on the case id, so `M` runs all 46 MCP cases and `M-12` runs one.

Neither runner needs network access, and neither reads your actual machine. Every case works inside a temporary directory that is removed afterwards, even when the case raises.

## How a case works

A case is a function returning `(world, expectations)`. The runner builds the world, scans it once, evaluates every expectation against that single snapshot, and records each one separately.

```python
@case("T-14")
def t14():
    """One sentence saying what this case exists to prove."""
    w = World(platform="linux", home="/home/alice")
    npm(w, "@anthropic-ai/claude-code", "2.1.235", "claude")
    return w, [only("claude-code", version="2.1.235"),
               total(1)]
```

Each case module keeps its own `CASES` dict and a local `case(case_id)` decorator that registers into it; `run_suite.load()` merges all five into one ordered mapping.

A case docstring is not decoration. When a check fails, the docstring is what tells the next reader whether the collector regressed or the expectation was wrong in the first place.

## Building a world

`World(platform=..., home=..., user=..., case_insensitive=...)` creates a temporary root. Platforms are `darwin`, `linux` and `windows`; on Windows `APPDATA` and `LOCALAPPDATA` are pre-set. Every method returns the world, so calls chain.

Paths are **logical**. `~` expands to the case's home and `%APPDATA%`-style variables expand from the world's environment, then everything is rooted inside the temporary directory. A case writes `~/.claude/settings.json` and never learns the real path.

### Filesystem

| Method | Creates |
| ------------------------------- | ------------------------------------------------------- |
| `dir(path)`                     | a directory |
| `file(path, content="x")`       | a text file |
| `bytes(path, payload)`          | a binary file |
| `json(path, obj)`               | a JSON file |
| `plist(path, obj, binary=True)` | a macOS property list, binary or XML |
| `link(path, target)`            | a symlink to another *logical* path in this world |
| `raw_link(path, raw_target)`    | a symlink to a literal string — for dangling links, loops, and usr-merge layouts |
| `path(*dirs)`                   | appends to `PATH` and creates each directory |
| `var(name, value)`              | sets an environment variable |

`raw_link` is the one to reach for when the *spelling* of a link matters. `raw_link("/bin", "usr/bin")` reproduces a usr-merge system, where one binary is reachable by two paths and a naive collector counts it twice.

### Injected services

The collector never touches the live machine, so anything outside the filesystem is supplied:

| Method | Supplies |
| ----------------------------------- | ---------------------------------------------------- |
| `proc(pid, exe, argv, ppid, user, cwd)` | an entry in the process table |
| `sock(port, pid)`                   | a listening socket |
| `http(port, endpoint, payload)`     | a response for a model-listing probe |
| `reg(**fields)`                     | a Windows registry record |
| `run(contains, out, code=0)`         | a subprocess response for any argv containing `contains` |
| `used(catalog_id, stamp)`           | a telemetry last-used timestamp |
| `users(*names)`                     | additional user accounts on the box |

`run("!timeout", ...)` makes any `--version` invocation raise `TimeoutError`, which is how the suite covers a binary that hangs instead of answering.

`scan()` pins the hostname to `fixture` and the timestamp to a fixed instant, so two runs of the same case produce byte-identical snapshots.

## Writing expectations

An expectation is a label plus a predicate over the snapshot. The predicate returns `True`/`None` to pass, `False` to fail, or **a string explaining what it saw** — which is what makes a failure readable without a debugger.

| Helper | Asserts |
| --------------------------------- | -------------------------------------------------------- |
| `only(catalog_id, **fields)`      | exactly one asset with that catalog id, and each field matches |
| `count(n, **filters)`             | exactly `n` assets match the filters |
| `total(n)`                        | the snapshot holds exactly `n` assets |
| `none_of(**filters)`              | nothing matches — the phantom check |
| `in_queue(name, signals, min_score)` | the open-world stage queued this name, with these signals |
| `not_queued(name)`                | the open-world stage did *not* queue it |
| `has(label, fn)`                  | anything else, as a named predicate |

`only()` accepts real `DiscoveredAsset` fields plus three shorthands: `channels`, `band` (for `confidence_band`), and `factors`, which checks that the given risk factors are a **subset** of those reported rather than an exact match.

For lower-level work, `framework.py` exports `assets(snapshot, **filters)`, `one(snapshot, **filters)`, `queued(snapshot, name)` and `findings(snapshot, kind)`.

Prefer `has()` with a sentence over a bare boolean. `has("the canonical spelling is reported, not the compat link", ...)` survives being read a year later; `assert x` does not.

## The groups

| Group | Cases | Checks | Covers |
| ---- | ---: | ---: | -------------------------------------------------------------- |
| `T`  | 74 | 135 | AI tools — one case per tool per install form |
| `M`  | 46 |  82 | MCP servers |
| `S`  | 36 |  80 | Skills, commands, hooks, plugins, rules and instruction files |
| `AG` | 36 |  68 | AI agents: running, defined, scheduled, delegated, disowned |
| `R`  | 49 | 125 | Hardening regressions |

**T — AI tools.** CLI coding agents, IDEs and editors, IDE and browser extensions, desktop apps and AI browsers, local model runtimes, install channels and platform layouts, fields about the tool, one-thing-one-asset, and must-not-be-invented.

**M — MCP servers.** Every place a server can be declared, transport and connection, the supply-chain verdict, what the server can reach, and counting — including what must *not* be counted as a server.

**S — the programmable surface.** Skills; commands, output styles and plugins; hooks; instruction and rules files; and must-not-be-invented.

**AG — agents.** Running agents, defined agents, scheduled and delegated ones, identity and credentials, and the open-world boundary between an agent and something that merely looks like one.

**R — hardening regressions.** One case per finding from the adversarial reviews, each pinned to the commit it reproduced on. These sit outside the four target groups on purpose: they are not coverage of a surface, they are proof that a specific defect stays fixed.

Two kinds of case carry disproportionate weight. **Phantom cases** (`none_of`, `not_queued`, the must-not-be-invented sections) assert the collector reports *nothing* — a scanner that invents assets is worse than one that misses them, because it costs an operator real time. **Counting cases** (`total`, `count`) assert that one thing reached two ways is one asset; most of the R group exists because that invariant broke in some new way.

## Adding a case

1. Pick the group and the next free id in that file.
2. Write the docstring first — state what the case proves, and if it came from a real machine rather than a hypothesis, say so.
3. Build the smallest world that reproduces it. Fixture noise makes a failure harder to read.
4. Assert what must be true *and* what must not be invented. A case that only checks presence will happily pass while the collector doubles the asset.
5. Run the group, then the whole suite:

```bash
python3 tests/run_suite.py T-75 -v
python3 tests/run_suite.py
```

For a defect found on a live machine, add it to `R` and describe the machine. Several R cases exist because a real container behaved in a way no fixture had predicted, and that provenance is the most useful line in the docstring.
