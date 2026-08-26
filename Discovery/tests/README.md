# Testing ADR Discovery

## What this test answers

> If we install a known set of AI tools on a real machine, does ADR Discovery report **exactly** that set — no misses, no inventions, and with the right facts about each one?

Everything below treats the collector as a black box. We never import its internals, never assert on which probe fired, and never inspect intermediate state. The only thing under examination is the snapshot it emits.

The measurement is a comparison between two lists:

```
   INSTALL MANIFEST                    DISCOVERY SNAPSHOT
   what we deliberately   ───► scan ───►   what the collector
   put on the machine                      says is on the machine

                    compare  ═══►  TP / FP / FN per category
```

## Current harness status

The 120-entry manifest is the target corpus, not a claim that every entry can
be installed automatically today. The harness currently provides manifest
validation, synthetic run generation, replayable scoring, JSON and HTML
scorecards, and dry-run command planning. Four recipe families execute against
the guest-driver interface; on Linux, 64 of 105 applicable entries currently
have executable recipes.

Linux and macOS guest drivers exist, but neither has automated golden-snapshot
restoration wired up. There is no Windows guest driver yet, and the integrated
`tests.cli run` command supports only `--dry`. See [HARNESS.md](HARNESS.md) for
the current recipe, driver, and measured-run status.

## Target test environment

The complete fidelity measurement targets three virtual machines, one per
operating system. Nothing should be scored as a golden-endpoint run on a
developer's own machine, because the method depends on knowing the complete
contents of the endpoint.

| VM | Operating system | Purpose |
| --- | --- | --- |
| `adr-disco-mac` | macOS (current major release) | App bundles, `~/Library` layouts, launchd agents, code signing |
| `adr-disco-linux` | Ubuntu LTS | Package managers, `/usr` layouts and usr-merge, cron and systemd units |
| `adr-disco-win` | Windows 11 | Registry entries, `%APPDATA%` layouts, Task Scheduler, `.exe` casing |

VMs rather than containers or the host, for three reasons that matter to the result:

1. **A known-clean baseline.** Every run starts from a snapshot with no AI tooling installed. Without that, a reported asset can't be attributed to the manifest.
2. **Rollback between runs.** Installing 30 tools mutates the machine permanently. A VM snapshot makes each run reproducible instead of cumulative.
3. **Real OS surfaces.** A container has no launchd, no Windows registry, no Task Scheduler, and no GUI app bundles. Those are surfaces the collector and manifest are intended to exercise.

For a complete golden run, each VM must be provisioned with the OS defaults plus
the runtimes the tools need (Node, Python, a browser, and a JetBrains IDE where
applicable) and **nothing else**. Those prerequisites are part of the baseline,
not the manifest.

## Method

```
1. RESTORE      VM snapshot → clean baseline, no AI tooling
2. BASELINE     run discovery → snapshot_before.json
3. INSTALL      apply the manifest for this OS, recording what actually installed
4. SCAN         run discovery → snapshot_after.json
5. COMPARE      diff the two snapshots against the manifest
6. SCORE        TP / FP / FN per category, plus field accuracy
```

**Step 2 is not a formality.** Anything the collector reports on a clean baseline is a false positive with no manifest to blame, and it sets the noise floor for the whole run. A baseline that is not near-empty invalidates the run.

**Step 5 uses the delta, not the raw snapshot.** The module already exposes `diff_snapshots`, so the comparison is against what *changed*, which removes any residual baseline noise from the measurement:

```python
delta = diff_snapshots(before, after)   # added / removed / changed assets
compare(delta.added, manifest)          # this comparison is the test result
```

**Step 3 records reality, not intent.** An install that fails, or that a vendor no longer ships for that OS, is struck from the manifest for that run and reported as such. A manifest entry that was never installed must never be scored as a miss.

## The install manifest

This is the complete inventory the harness intends to install and score. Every
row has a stable **id**, and the id is what the runner plans, what
`manifest.actual.json` records an outcome against, and what a scorecard reports
a miss under. Entries whose recipe family is not implemented are recorded as
unavailable rather than reported as successful; only entries recorded as
installed are scored for recall.

`catalog_id` is the join key between what we installed and what was reported. Rows with no `catalog_id` (MCP servers, skills, hooks) are matched by install path or launch identity instead.

Platform columns record where a vendor ships the tool. Availability is re-confirmed at provisioning time; where a vendor no longer ships for an OS, that run records the entry as `unavailable` rather than scoring it as a miss.

**120 entries in total:**

| Category | Entries | ids |
| --- | ---: | --- |
| AI tools | 50 | `T-CLI-*` `T-APP-*` `T-EXT-*` `T-RT-*` `T-CHAN-*` |
| MCP servers | 29 | `M-SITE-*` `M-PIN-*` `M-SP-*` |
| Skills & programmable surface | 19 | `S-*` |
| Agents | 12 | `AG-*` |
| Negative controls | 10 | `N-*` |

The manifest currently references 42 distinct `catalog_id` values, while the
collector catalog contains 35 entries. They are not synchronized: six current
catalog IDs have no manifest row, and 13 manifest IDs no longer exist under
those names in the catalog. Restoring one-to-one catalog coverage is open work.
Adding or renaming a catalog entry should include the corresponding manifest
change.

### Category 1 — AI tools

The `assets` entries the collector classifies as installed software. Five sub-tables, because the evidence channel differs for each.

#### 1a. CLI coding agents — `T-CLI-01` … `T-CLI-12`

Installed globally so their binaries land on `PATH`. Versions are pinned, because an unpinned install makes the expected `version` unscoreable.

| id | Tool | `catalog_id` | Install | mac | linux | win |
| --- | --- | --- | --- | :-: | :-: | :-: |
| `T-CLI-01` | Claude Code | `claude-code` | `npm i -g @anthropic-ai/claude-code@<pin>` | ✓ | ✓ | ✓ |
| `T-CLI-02` | Codex CLI | `codex` | `npm i -g @openai/codex@<pin>` | ✓ | ✓ | ✓ |
| `T-CLI-03` | Gemini CLI | `gemini-cli` | `npm i -g @google/gemini-cli@<pin>` | ✓ | ✓ | ✓ |
| `T-CLI-04` | opencode | `opencode` | `npm i -g opencode-ai@<pin>` | ✓ | ✓ | ✓ |
| `T-CLI-05` | Amp | `amp` | `npm i -g @sourcegraph/amp@<pin>` | ✓ | ✓ | ✓ |
| `T-CLI-06` | Kilo CLI | `kilo-cli` | `npm i -g @kilocode/cli@<pin>` | ✓ | ✓ | ✓ |
| `T-CLI-07` | Qwen Code | `qwen-code` | `npm i -g @qwen-code/qwen-code@<pin>` | ✓ | ✓ | ✓ |
| `T-CLI-08` | Copilot CLI | `copilot-cli` | `npm i -g @github/copilot@<pin>` | ✓ | ✓ | ✓ |
| `T-CLI-09` | Goose | `goose` | vendor installer — **not npm**, see below | ✓ | ✓ | ✓ |
| `T-CLI-10` | Aider | `aider` | `pipx install aider-chat==<pin>` | ✓ | ✓ | ✓ |
| `T-CLI-11` | Crush | `crush` | vendor binary → `/usr/local/bin` | ✓ | ✓ | ✓ |
| `T-CLI-12` | Grok CLI | `grok-cli` | vendor binary → `/usr/local/bin` | ✓ | ✓ | ✓ |

Expected for each: one asset, correct `version`, `install_path` on the real binary, `install_method` matching the channel, `liveness` = installed.

`T-CLI-09` is the one row where the install channel is not settled. `@block/goose-cli` does not resolve — the scope does not exist on the npm registry — and the plausible substitute is worse than nothing: the unscoped `goose-cli` package on npm is a wrapper around the **database migration tool** of the same name, so installing it would put an unrelated binary called `goose` on `PATH` and the harness would record a successful install of the wrong product. The row stays in the manifest and is recorded `unimplemented` until somebody confirms how Block ships it.

#### 1b. Desktop apps, IDEs and AI browsers — `T-APP-01` … `T-APP-16`

Installed from vendor installers so the real bundle, registry entry or `.desktop` file exists.

| id | Tool | `catalog_id` | mac | linux | win |
| --- | --- | --- | :-: | :-: | :-: |
| `T-APP-01` | Claude Desktop | `claude-desktop` | ✓ | n/a | ✓ |
| `T-APP-02` | Cursor | `cursor` | ✓ | ✓ | ✓ |
| `T-APP-03` | Windsurf | `windsurf` | ✓ | ✓ | ✓ |
| `T-APP-04` | VS Code | `vscode` | ✓ | ✓ | ✓ |
| `T-APP-05` | Zed | `zed` | ✓ | ✓ | n/a |
| `T-APP-06` | JetBrains IDE + AI Assistant | `jetbrains-ai` | ✓ | ✓ | ✓ |
| `T-APP-07` | Trae | `trae` | ✓ | n/a | ✓ |
| `T-APP-08` | Warp | `warp` | ✓ | ✓ | ✓ |
| `T-APP-09` | ChatGPT Desktop | `chatgpt-desktop` | ✓ | n/a | ✓ |
| `T-APP-10` | Perplexity | `perplexity` | ✓ | n/a | n/a |
| `T-APP-11` | Gemini Desktop | `gemini-desktop` | ✓ | n/a | ✓ |
| `T-APP-12` | Copilot Desktop | `copilot-desktop` | ✓ | n/a | ✓ |
| `T-APP-13` | Raycast | `raycast` | ✓ | n/a | n/a |
| `T-APP-14` | Comet browser | `comet` | ✓ | n/a | ✓ |
| `T-APP-15` | Dia browser | `dia` | ✓ | n/a | n/a |
| `T-APP-16` | ChatGPT Atlas | `atlas` | ✓ | n/a | n/a |

These require a logged-in graphical session on the VM; see *Test environment*.

#### 1c. IDE and browser extensions — `T-EXT-01` … `T-EXT-05`

Installed into the VS Code from `T-APP-04` via `code --install-extension <id>@<pin>`.

| id | Extension | `catalog_id` | Extension id | mac | linux | win |
| --- | --- | --- | --- | :-: | :-: | :-: |
| `T-EXT-01` | Cline | `cline` | `saoudrizwan.claude-dev` | ✓ | ✓ | ✓ |
| `T-EXT-02` | Continue | `continue` | `continue.continue` | ✓ | ✓ | ✓ |
| `T-EXT-03` | Roo Code | `roo-code` | `rooveterinaryinc.roo-cline` | ✓ | ✓ | ✓ |
| `T-EXT-04` | Kilo Code | `kilo-code` | `kilocode.kilo-code` | ✓ | ✓ | ✓ |
| `T-EXT-05` | GitHub Copilot | `copilot-ext` | `github.copilot` | ✓ | ✓ | ✓ |

#### 1d. Local model runtimes and platforms — `T-RT-01` … `T-RT-09`

Installed **and started**, with at least one small model pulled, so the listening port and the model-listing endpoint are both real.

| id | Runtime | `catalog_id` | Port / endpoint | Model to pull | mac | linux | win |
| --- | --- | --- | --- | --- | :-: | :-: | :-: |
| `T-RT-01` | Ollama | `ollama` | 11434 `/api/tags` | `qwen2.5:0.5b` | ✓ | ✓ | ✓ |
| `T-RT-02` | LM Studio | `lm-studio` | 1234 `/v1/models` | any 0.5B GGUF | ✓ | ✓ | ✓ |
| `T-RT-03` | llama.cpp | `llama.cpp` | 8080 `/v1/models` | any 0.5B GGUF | ✓ | ✓ | ✓ |
| `T-RT-04` | GPT4All | `gpt4all` | — | bundled small | ✓ | ✓ | ✓ |
| `T-RT-05` | Jan | `jan` | 1337 `/v1/models` | any small | ✓ | ✓ | ✓ |
| `T-RT-06` | vLLM | `vllm` | 8000 `/v1/models` | needs GPU | n/a | ✓ | n/a |
| `T-RT-07` | LocalAI | `localai` | 8080 `/v1/models` | any small | ✓ | ✓ | n/a |
| `T-RT-08` | Open WebUI | `open-webui` | 8080 `/` | — | ✓ | ✓ | ✓ |
| `T-RT-09` | OpenHands | `openhands` | — | — | ✓ | ✓ | ✓ |

`T-RT-03` and `T-RT-07` both default to 8080; the manifest assigns distinct ports so a port collision never masquerades as a detection failure.

#### 1e. Install-channel variants — `T-CHAN-01` … `T-CHAN-08`

Deliberate second installs of tools already listed above. These exist to prove **one tool reached two ways is still one asset**, which is the defect class that has broken most often. Each is scored for duplication, not for presence.

| id | Variant | Also installed as | OS | Asserts |
| --- | --- | --- | --- | --- |
| `T-CHAN-01` | Claude Code under an `nvm`-managed Node | `T-CLI-01` | linux | version-manager Node roots resolve to one asset |
| `T-CHAN-02` | Claude Code under an `fnm`-managed Node | `T-CLI-01` | mac | as above, second manager |
| `T-CHAN-03` | Codex installed to `~/.local/bin` | `T-CLI-02` | linux | user-local install does not double-count |
| `T-CHAN-04` | Claude Code reachable via both `/usr/bin` and `/bin` | `T-CLI-01` | linux | **usr-merge**: two spellings, one asset, canonical path reported |
| `T-CHAN-05` | Aider via `pip --user` alongside `pipx` | `T-CLI-10` | mac | two Python channels, one asset |
| `T-CHAN-06` | Ollama via distro package and vendor script | `T-RT-01` | linux | two package channels, one asset |
| `T-CHAN-07` | Cursor via `.deb` and AppImage | `T-APP-02` | linux | two app channels, one asset |
| `T-CHAN-08` | VS Code via `winget` and vendor `.exe` | `T-APP-04` | win | casing and registry vs filesystem agree |

### Category 2 — MCP servers

MCP is the only purely *declared* surface: a server exists because a config file says so, whether or not it has ever run.

#### 2a. Declaration sites — `M-SITE-01` … `M-SITE-14`

One server declared in each site the collector reads, so a missed site shows up as a specific miss rather than a lower total. Each declares the same trivial stdio server so the only variable is the site.

| id | Host application | Config file (mac / linux / win) | Expected `config_scope` |
| --- | --- | --- | --- |
| `M-SITE-01` | Claude Code | `~/.claude.json` | user |
| `M-SITE-02` | Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` · `~/.config/claude-desktop/…` · `%APPDATA%/Claude/…` | user |
| `M-SITE-03` | Cursor | `~/.cursor/mcp.json` | user |
| `M-SITE-04` | Windsurf | `~/.codeium/windsurf/mcp_config.json` · `%APPDATA%/Codeium/…` | user |
| `M-SITE-05` | VS Code | `…/Code/User/mcp.json` | user |
| `M-SITE-06` | Cline | `…/Code/User/globalStorage/saoudrizwan.claude-dev/` | user |
| `M-SITE-07` | Zed | `…/Zed/settings.json` | user |
| `M-SITE-08` | JetBrains | `…/JetBrains/options/mcp.json` | user |
| `M-SITE-09` | opencode | `~/.config/opencode/opencode.json` | user |
| `M-SITE-10` | Codex | `~/.codex/config.toml` | user |
| `M-SITE-11` | Goose | `~/.config/goose/config.yaml` | user |
| `M-SITE-12` | Managed policy | `/Library/Application Support/ClaudeCode/managed-settings.json` | enterprise_managed |
| `M-SITE-13` | ADR policy | `/Library/Application Support/ADR/managed-mcp.json` | enterprise_managed |
| `M-SITE-14` | Project-local | `<repo>/.mcp.json` under `~/dev`, `~/src`, `~/workspace`, `~/code` | project |

#### 2b. Launch forms and the supply-chain verdict — `M-PIN-01` … `M-PIN-09`

All declared in `~/.claude.json`, so the only variable is the launch line.

| id | Server | Launch | Expected verdict |
| --- | --- | --- | --- |
| `M-PIN-01` | filesystem | `npx -y @modelcontextprotocol/server-filesystem@2025.8.21` | pinned |
| `M-PIN-02` | git | `npx -y @modelcontextprotocol/server-git` | **unpinned** |
| `M-PIN-03` | github | `docker run ghcr.io/github/github-mcp-server:v0.5.0` | pinned |
| `M-PIN-04` | sqlite | `uvx mcp-server-sqlite@0.1.0` | pinned |
| `M-PIN-05` | fetch | `uvx mcp-server-fetch` | **unpinned** |
| `M-PIN-06` | memory | `docker run mcp/memory:latest` | **unpinned** — `latest` is mutable |
| `M-PIN-07` | playwright | `npx @playwright/mcp@1.x` | **unpinned** — a range, not a version |
| `M-PIN-08` | local script | `node ~/dev/tools/my-server.js` | local, unpinned |
| `M-PIN-09` | remote | SSE endpoint over HTTPS | remote transport, no pinning verdict |

#### 2c. Special cases — `M-SP-01` … `M-SP-06`

| id | Case | Setup | Expected |
| --- | --- | --- | --- |
| `M-SP-01` | Undeclared server | Start an MCP server by hand, in no config | `undeclared_mcp_server` finding |
| `M-SP-02` | Scope precedence | Same server in `M-SITE-12` **and** `M-SITE-01` | `config_scope: enterprise_managed`, one asset |
| `M-SP-03` | Token in argv | Declared with `--token {{canary:mcp_token}}` | server reported, canary absent from snapshot |
| `M-SP-04` | Auth header | Declared with an `Authorization` header canary | as above |
| `M-SP-05` | Key in env | Declared with an API key in `env` | variable **name** only, value absent |
| `M-SP-06` | Malformed bundle | A bundle manifest declaring nothing runnable | recorded as malformed, **not** as a server |

### Category 3 — Skills, commands, hooks and instruction files — `S-01` … `S-19`

The programmable surface: what an installed agent has been *told* to do. Created as real files. Project-level artifacts go in checkouts under `~/dev`, `~/src`, `~/workspace` and `~/code`, since those are the roots the collector walks.

| id | Artifact | Exact path |
| --- | --- | --- |
| `S-01` | User skill | `~/.claude/skills/pdf-filler/SKILL.md` |
| `S-02` | Project skill | `~/dev/demo-repo/.claude/skills/deploy-check/SKILL.md` |
| `S-03` | Claude command | `~/.claude/commands/ship.md` |
| `S-04` | Gemini command | `~/.gemini/commands/review.toml` |
| `S-05` | Codex prompt | `~/.codex/prompts/triage.md` |
| `S-06` | Project command | `~/dev/demo-repo/.claude/commands/release.md` |
| `S-07` | Output style | `~/.claude/output-styles/terse.md` |
| `S-08` | Claude subagent | `~/.claude/agents/reviewer.md` |
| `S-09` | Cursor agent | `~/.cursor/agents/refactor.md` |
| `S-10` | Windsurf agent | `~/.codeium/windsurf/agents/scan.md` |
| `S-11` | Project subagent | `~/dev/demo-repo/.claude/agents/tester.md` |
| `S-12` | Plugin | `~/.claude/plugins/acme-tools/` |
| `S-13` | User hook | `PreToolUse` in `~/.claude/settings.json`, runs a shell command |
| `S-14` | Project hook | `PreToolUse` in `~/dev/demo-repo/.claude/settings.json` |
| `S-15` | Local project hook | `PostToolUse` in `~/dev/demo-repo/.claude/settings.local.json` |
| `S-16` | Hook with a secret | Hook command containing `{{canary:hook_token}}` |
| `S-17` | Claude instructions | `~/.claude/CLAUDE.md` |
| `S-18` | Codex instructions | `~/.codex/AGENTS.md` |
| `S-19` | Gemini instructions | `~/.gemini/GEMINI.md` |

`S-13` through `S-16` carry the most weight: a hook is arbitrary code that runs on an agent event, so each must be reported with its command visible enough to review — and `S-16` must be reported with the canary redacted.

### Category 4 — Agents: running, scheduled and delegated — `AG-01` … `AG-12`

Agents are distinguished from tools by *liveness*, so each item is left in the required state immediately before the second scan.

| id | Item | How it is created | Expected |
| --- | --- | --- | --- |
| `AG-01` | Running agent | Start Claude Code, leave the session open | live liveness, session recorded |
| `AG-02` | Spawned child | The running agent launches a subprocess | parent/child relationship recorded |
| `AG-03` | Running runtime | `ollama serve` left running (`T-RT-01`) | live liveness on the runtime asset |
| `AG-04` | launchd agent | `.plist` in `~/Library/LaunchAgents` invoking `claude` | scheduled (mac) |
| `AG-05` | cron job | `crontab` entry invoking `claude` | scheduled (linux) |
| `AG-06` | systemd user unit | `~/.config/systemd/user/agent.service` | scheduled (linux) |
| `AG-07` | Scheduled task | Task Scheduler entry invoking `claude` | scheduled (win) |
| `AG-08` | Claude Code identity | Signed in with a corporate test account | account and auth method, no credential value |
| `AG-09` | Codex identity | Signed in with a corporate test account | as above |
| `AG-10` | Gemini CLI identity | Signed in with a corporate test account | as above |
| `AG-11` | Personal account | One agent signed in with a non-corporate account | flagged in risk factors |
| `AG-12` | Shell-exported key | `export ANTHROPIC_API_KEY={{canary:env_key}}` in `~/.zshrc` | variable **name** only, canary absent |

`AG-08` through `AG-11` need real authenticated sessions. Because OAuth device flows resist unattended scripting, these are signed in by hand once while building the golden image and captured in the snapshot; the run asserts the sessions are still valid and fails loudly if they have expired.

### Negative controls — `N-01` … `N-10`

Without these the false-positive rate cannot be measured, and a collector that reported everything would score perfectly on every table above.

| id | Installed | Must **not** appear as |
| --- | --- | --- |
| `N-01` | Node.js | an AI tool |
| `N-02` | Python + pipx | an AI tool |
| `N-03` | Docker | an AI tool |
| `N-04` | git | an AI tool |
| `N-05` | Slack desktop (non-AI Electron app) | an AI app |
| `N-06` | Prettier VS Code extension | an AI extension |
| `N-07` | `~/bin/mcp-backup.sh` — a shell script whose path contains "mcp" | an MCP server |
| `N-08` | nginx on 8081 serving non-model JSON | a model runtime |
| `N-09` | Dangling symlink `/usr/local/bin/claude` → missing target | any asset |
| `N-10` | `~/bin/ask-corp-llm.sh` — an in-house AI wrapper unknown to the catalog | an **asset** — it belongs in `review_queue` |

`N-01` through `N-04` are installed as part of the golden image, since the manifest depends on them. They are baseline, not manifest — but they are still scored, because "the prerequisites are not AI tools" is exactly the kind of claim that quietly stops being true.

`N-10` is the open-world check: an unrecognized tool that looks like AI should be **queued for review**, not confidently classified and not silently dropped.

## Comparing, and scoring

For each category, every manifest entry is matched to reported assets by `catalog_id`, falling back to install path for uncatalogued items.

| Outcome | Meaning |
| --- | --- |
| **TP** | Installed, and reported once |
| **FP** | Reported, but not installed — an invention |
| **FN** | Installed, but not reported — a miss |
| **DUP** | Installed once, reported more than once |

`DUP` is tracked separately from TP rather than folded into it, because a duplicate is not a partial success: it inflates a fleet inventory and it is the failure mode that has recurred most.

**Per category:** `recall = TP / (TP + FN)` and `precision = TP / (TP + FP)`.

**Field accuracy**, over true positives only — a tool found with the wrong facts is only partly found:

| Field | Correct when |
| --- | --- |
| `version` | matches the version actually installed |
| `install_path` | points at the real binary or bundle |
| `install_method` | matches the channel used (npm, pip, dmg, msi, distro) |
| `config_scope` | matches where the server was declared, honouring precedence |
| `transport` | matches the declared transport |
| pinning verdict | matches the table in 2b |
| `liveness` | matches the state the item was left in |

**Redaction**, checked over the whole snapshot rather than per asset. Every credential planted during installation is a unique canary string. The check is a search of the serialized snapshot for each canary; any hit is a critical failure regardless of the scores above.

**Errors.** The scorecard records total and unexplained errors. Every error must
be explained by something the manifest deliberately created (a denied path or
a permission the VM lacks); unexplained errors fail the gate.

## Reporting the result

One table per category per OS, plus a run summary:

| Category | Installed | TP | FP | FN | DUP | Recall | Precision |
| --- | --: | --: | --: | --: | --: | --: | --: |
| AI tools — CLI agents | | | | | | | |
| AI tools — apps & browsers | | | | | | | |
| AI tools — extensions | | | | | | | |
| AI tools — model runtimes | | | | | | | |
| MCP servers | | | | | | | |
| Skills & programmable surface | | | | | | | |
| Agents | | | | | | | |
| Negative controls | — | — | | — | — | — | — |

Accompanied by: the baseline asset count, field accuracy per field, the review
queue contents, the canary check verdict, total and unexplained error counts,
and wall-clock scan time per OS.

Every FP and FN is listed individually with the evidence the collector recorded, because the aggregate number is for tracking and the individual rows are what get fixed.

## Running it

The implemented local workflows are:

```sh
python3 -m tests.cli check
python3 -m tests.cli synthesize runs/local --os linux
python3 -m tests.cli score runs/local --html runs/local/score.html
python3 -m tests.cli run --os linux --dry
```

The dry run records installation commands without touching a guest. Individual
Linux and macOS drivers can be used by the bootstrap tooling, but a complete
restore-install-scan-score workflow is not yet wired into `tests.cli run`.
Current driver-specific instructions and limitations are in
[HARNESS.md](HARNESS.md).

Once the complete golden run is automated, it will install real software, sign
into real accounts, and start real listeners. That workflow should run against
a release candidate, when the catalog changes, and when a new OS version ships,
not as part of per-commit CI.

## Relationship to the fixture suite

This document describes the end-to-end fidelity measurement. The fast,
per-commit suite is a different instrument: collector module and pipeline tests
live under `adr_discovery/tests_unit/`, while harness validation and scoring
tests live directly under `tests/`. Run both with `pytest -q`.

The two are complementary, and neither replaces the other:

- The **fixture suite** has a perfect oracle (it built the machine) but can only contain situations someone imagined. It catches regressions.
- The **VM run** has real input that nobody predicted but a costlier, slower oracle. It discovers defects.

Every defect found by a VM run should be reduced to a fixture case in the `R` group, so the fast suite prevents it from returning. That is the intended flow of work between the two documents.
