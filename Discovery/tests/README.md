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

## Test environment

Three virtual machines, one per operating system. Nothing is tested on a developer's own machine, because the whole method depends on knowing the complete contents of the endpoint.

| VM | Operating system | Purpose |
| --- | --- | --- |
| `adr-disco-mac` | macOS (current major release) | App bundles, `~/Library` layouts, launchd agents, code signing |
| `adr-disco-linux` | Ubuntu LTS | Package managers, `/usr` layouts and usr-merge, cron and systemd units |
| `adr-disco-win` | Windows 11 | Registry entries, `%APPDATA%` layouts, Task Scheduler, `.exe` casing |

VMs rather than containers or the host, for three reasons that matter to the result:

1. **A known-clean baseline.** Every run starts from a snapshot with no AI tooling installed. Without that, a reported asset can't be attributed to the manifest.
2. **Rollback between runs.** Installing 30 tools mutates the machine permanently. A VM snapshot makes each run reproducible instead of cumulative.
3. **Real OS surfaces.** A container has no launchd, no Windows registry, no Task Scheduler, and no GUI app bundles. Those are exactly the surfaces four of the ten probes exist to read.

Each VM is provisioned with the OS defaults plus the runtimes the tools need (Node, Python, a browser, a JetBrains IDE where applicable) and **nothing else**. Those prerequisites are part of the baseline, not the manifest.

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

The manifest is grouped by the categories the collector reports, so each table maps directly onto a slice of the snapshot. `catalog_id` is the join key between "what we installed" and "what was reported".

Platform columns record where a vendor ships the tool. Availability is re-confirmed at provisioning time; where a tool has disappeared for an OS, the cell becomes `n/a` for that run rather than an expected miss.

The manifest covers **all 42 entries in the catalog**, and that is a property worth keeping: a catalog entry with no manifest row is a tool the collector claims to recognize but that nothing ever verifies. Adding a catalog entry should mean adding a manifest row in the same change.

### Category 1 — AI tools

The `assets` entries the collector classifies as installed software. Four sub-tables, because the evidence channel differs for each.

#### 1a. CLI coding agents

Installed globally so their binaries land on `PATH`. Each should resolve to one asset with a version and an install method.

| Tool | `catalog_id` | Install | macOS | Linux | Windows |
| --- | --- | --- | :-: | :-: | :-: |
| Claude Code | `claude-code` | `npm i -g @anthropic-ai/claude-code` | ✓ | ✓ | ✓ |
| Codex CLI | `codex` | `npm i -g @openai/codex` | ✓ | ✓ | ✓ |
| Gemini CLI | `gemini-cli` | `npm i -g @google/gemini-cli` | ✓ | ✓ | ✓ |
| opencode | `opencode` | `npm i -g opencode-ai` | ✓ | ✓ | ✓ |
| Amp | `amp` | `npm i -g @sourcegraph/amp` | ✓ | ✓ | ✓ |
| Kilo CLI | `kilo-cli` | `npm i -g @kilocode/cli` | ✓ | ✓ | ✓ |
| Qwen Code | `qwen-code` | `npm i -g @qwen-code/qwen-code` | ✓ | ✓ | ✓ |
| Copilot CLI | `copilot-cli` | `npm i -g @github/copilot` | ✓ | ✓ | ✓ |
| Goose | `goose` | `npm i -g @block/goose-cli` | ✓ | ✓ | ✓ |
| Aider | `aider` | `pipx install aider-chat` | ✓ | ✓ | ✓ |
| Crush | `crush` | vendor binary | ✓ | ✓ | ✓ |
| Grok CLI | `grok-cli` | vendor binary | ✓ | ✓ | ✓ |

**Install-channel variants.** At least three of the above are installed a second way on at least one VM — a version-manager Node (`nvm`, `fnm`), a distro package, and a user-local `~/.local/bin` install. These exist to test that one tool reached two ways is still **one asset**, which is the defect class that has broken most often.

#### 1b. Desktop apps, IDEs and AI browsers

Installed from vendor installers so the real bundle, registry entry or `.desktop` file exists.

| Tool | `catalog_id` | macOS | Linux | Windows |
| --- | --- | :-: | :-: | :-: |
| Claude Desktop | `claude-desktop` | ✓ | n/a | ✓ |
| Cursor | `cursor` | ✓ | ✓ | ✓ |
| Windsurf | `windsurf` | ✓ | ✓ | ✓ |
| VS Code | `vscode` | ✓ | ✓ | ✓ |
| Zed | `zed` | ✓ | ✓ | n/a |
| JetBrains IDE + AI Assistant | `jetbrains-ai` | ✓ | ✓ | ✓ |
| Trae | `trae` | ✓ | n/a | ✓ |
| Warp | `warp` | ✓ | ✓ | ✓ |
| ChatGPT Desktop | `chatgpt-desktop` | ✓ | n/a | ✓ |
| Perplexity | `perplexity` | ✓ | n/a | n/a |
| Gemini Desktop | `gemini-desktop` | ✓ | n/a | ✓ |
| Copilot Desktop | `copilot-desktop` | ✓ | n/a | ✓ |
| Raycast | `raycast` | ✓ | n/a | n/a |
| Comet browser | `comet` | ✓ | n/a | ✓ |
| Dia browser | `dia` | ✓ | n/a | n/a |
| ChatGPT Atlas | `atlas` | ✓ | n/a | n/a |

#### 1c. IDE and browser extensions

Installed into the VS Code from 1b, and into the browser where applicable.

| Extension | `catalog_id` | Extension id | All three VMs |
| --- | --- | --- | :-: |
| Cline | `cline` | `saoudrizwan.claude-dev` | ✓ |
| Continue | `continue` | `continue.continue` | ✓ |
| Roo Code | `roo-code` | `rooveterinaryinc.roo-cline` | ✓ |
| Kilo Code | `kilo-code` | `kilocode.kilo-code` | ✓ |
| GitHub Copilot | `copilot-ext` | `github.copilot` | ✓ |

#### 1d. Local model runtimes

Installed **and started**, with at least one small model pulled, so the listening port and the model-listing endpoint are both real.

| Runtime | `catalog_id` | Port / endpoint | macOS | Linux | Windows |
| --- | --- | --- | :-: | :-: | :-: |
| Ollama | `ollama` | 11434 `/api/tags` | ✓ | ✓ | ✓ |
| LM Studio | `lm-studio` | 1234 `/v1/models` | ✓ | ✓ | ✓ |
| llama.cpp | `llama.cpp` | 8080 `/v1/models` | ✓ | ✓ | ✓ |
| GPT4All | `gpt4all` | — | ✓ | ✓ | ✓ |
| Jan | `jan` | 1337 `/v1/models` | ✓ | ✓ | ✓ |
| vLLM | `vllm` | 8000 `/v1/models` | n/a | ✓ | n/a |
| LocalAI | `localai` | 8080 `/v1/models` | ✓ | ✓ | n/a |
| Open WebUI | `open-webui` | 8080 `/` | ✓ | ✓ | ✓ |
| OpenHands | `openhands` | — | ✓ | ✓ | ✓ |

Expected: each running runtime reports `liveness` reflecting that it is live, plus the models it holds.

### Category 2 — MCP servers

MCP is the only purely *declared* surface: a server exists because a config file says so, whether or not it has ever run. The manifest therefore has two axes — **where** the server is declared, and **what** is declared.

#### 2a. Declaration sites

One server declared in each site the collector reads, so a missed site shows up as a specific miss rather than a lower total.

| Host application | Config file (macOS / Linux / Windows) | Scope |
| --- | --- | --- |
| Claude Code | `~/.claude.json` | user |
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` · `~/.config/claude-desktop/…` · `%APPDATA%/Claude/…` | user |
| Cursor | `~/.cursor/mcp.json` | user |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` · `%APPDATA%/Codeium/…` | user |
| VS Code | `…/Code/User/mcp.json` | user |
| Cline | `…/Code/User/globalStorage/saoudrizwan.claude-dev/` | user |
| Zed | `…/Zed/settings.json` | user |
| JetBrains | `…/JetBrains/options/mcp.json` | user |
| opencode | `~/.config/opencode/opencode.json` | user |
| Codex | `~/.codex/config.toml` | user |
| Goose | `~/.config/goose/config.yaml` | user |
| Managed policy | `/Library/Application Support/ClaudeCode/managed-settings.json` | enterprise_managed |
| ADR policy | `/Library/Application Support/ADR/managed-mcp.json` | enterprise_managed |
| Project-local | `<repo>/.mcp.json` under `~/dev`, `~/src`, `~/workspace`, `~/code` | project |

**Precedence case.** One server is declared in *both* the enterprise policy file and a user config. It must report `config_scope: enterprise_managed` — not "whichever was read last".

#### 2b. Launch forms

The same handful of servers, declared in different launch forms, because the supply-chain verdict is derived from the launch line.

| Server | Launch | Expected verdict |
| --- | --- | --- |
| filesystem | `npx -y @modelcontextprotocol/server-filesystem@2025.8.21` | pinned |
| git | `npx -y @modelcontextprotocol/server-git` | **unpinned** |
| github | `docker run ghcr.io/github/github-mcp-server:v0.5.0` | pinned |
| sqlite | `uvx mcp-server-sqlite@0.1.0` | pinned |
| fetch | `uvx mcp-server-fetch` | **unpinned** |
| memory | `docker run mcp/memory:latest` | **unpinned** (`latest` is mutable) |
| playwright | `npx @playwright/mcp@1.x` | **unpinned** (range, not a version) |
| local script | `node ~/dev/tools/my-server.js` | local, unpinned |
| remote | SSE/HTTP endpoint | remote transport |

**Undeclared-server case.** One MCP server is started by hand without appearing in any config. It must surface as an `undeclared_mcp_server` finding.

**Credential case.** One server is declared with `--token`, one with an `Authorization` header, and one with an API key in `env`. The values are canary strings; see *Redaction* below.

### Category 3 — Skills, commands, hooks and instruction files

The programmable surface — what an installed agent has been *told* to do. Created as real files in real locations, both user-level and project-level.

| Artifact | User-level location | Project-level location |
| --- | --- | --- |
| Skills | `~/.claude/skills/<name>/` | `<repo>/.claude/skills/` |
| Slash commands | `~/.claude/commands/` · `~/.gemini/commands/` · `~/.codex/prompts/` | `<repo>/.claude/commands/` |
| Output styles | `~/.claude/output-styles/` | — |
| Subagent definitions | `~/.claude/agents/` · `~/.cursor/agents/` · `~/.codeium/windsurf/agents/` | `<repo>/.claude/agents/` |
| Plugins | `~/.claude/plugins/` | — |
| Hooks | `~/.claude/settings.json` | `<repo>/.claude/settings.json` · `settings.local.json` |
| Instruction files | `~/.claude/CLAUDE.md` · `~/.codex/AGENTS.md` · `~/.gemini/GEMINI.md` | `<repo>/CLAUDE.md` · `AGENTS.md` |

Project-level artifacts are placed in checkouts under `~/dev`, `~/src`, `~/workspace` and `~/code`, since those are the roots the collector walks.

**Hooks matter most.** A hook is arbitrary code that runs on an agent event, so the manifest includes at least one `PreToolUse` hook running a shell command. It must be reported, with the command visible enough to review and any secret redacted.

### Category 4 — Agents: running, scheduled and delegated

Agents are distinguished from tools by *liveness*. This category is about state at scan time, so each item is left in the required state before step 4.

| Item | How it is created | Expected in snapshot |
| --- | --- | --- |
| Running agent | Start Claude Code and leave the session open | asset with live liveness, parent agent recorded |
| Spawned child | Have the running agent launch a subprocess | process relationship recorded |
| launchd agent | `.plist` in `~/Library/LaunchAgents` invoking a CLI agent | scheduled (macOS) |
| cron job | `crontab` entry invoking a CLI agent | scheduled (Linux) |
| systemd user unit | `~/.config/systemd/user/*.service` | scheduled (Linux) |
| Scheduled task | Task Scheduler entry invoking a CLI agent | scheduled (Windows) |
| Authenticated identity | Sign in to Claude Code, Codex and Gemini CLI | account and auth method per agent, no credential values |
| Personal account on corp machine | Sign one agent in with a non-corporate account | flagged in risk factors |
| Shell-exported key | `export ANTHROPIC_API_KEY=…` in `~/.zshrc` | variable **name** only, never the value |

### Negative controls — what must **not** be reported

Without these the false-positive rate cannot be measured, and a collector that reports everything would score perfectly on every table above.

| Installed | Must not appear as |
| --- | --- |
| Node, Python, Docker, git | an AI tool |
| A non-AI Electron app (e.g. Slack) | an AI app |
| A non-AI VS Code extension (e.g. Prettier) | an AI extension |
| A shell script whose path contains `mcp` | an MCP server |
| A web server on a common port serving non-model JSON | a model runtime |
| A dangling symlink on `PATH` named `claude` | any asset |
| An in-house AI wrapper script, unknown to the catalog | an *asset* — it belongs in `review_queue` |

The last row is the open-world check: an unrecognized tool that looks like AI should be **queued for review**, not confidently classified and not silently dropped.

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

**Errors.** `stats.error_count` must be zero, or every error must be explained by something the manifest deliberately created (a denied path, a permission the VM lacks). Unexplained errors fail the run.

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

Accompanied by: the baseline asset count, field accuracy per field, the review queue contents, the canary check verdict, `stats.error_count`, and wall-clock scan time per OS.

Every FP and FN is listed individually with the evidence the collector recorded, because the aggregate number is for tracking and the individual rows are what get fixed.

## Running it

```bash
# per VM, from a clean snapshot
adr-discovery --json > snapshot_before.json
<apply the manifest for this OS>
adr-discovery --json > snapshot_after.json
```

Then score `snapshot_before.json`, `snapshot_after.json` and the recorded manifest.

Because this run installs real software, signs into real accounts and starts real listeners, it is **not** part of per-commit CI. Run it against a release candidate, when the catalog changes, and when a new OS version ships.

## Relationship to the fixture suite

This document describes the end-to-end fidelity measurement. The fast, per-commit suite is a different instrument and is documented separately in [FIXTURE_SUITE.md](FIXTURE_SUITE.md): 241 cases that build synthetic endpoints and run in about four seconds on any CI box.

The two are complementary, and neither replaces the other:

- The **fixture suite** has a perfect oracle (it built the machine) but can only contain situations someone imagined. It catches regressions.
- The **VM run** has real input that nobody predicted but a costlier, slower oracle. It discovers defects.

Every defect found by a VM run should be reduced to a fixture case in the `R` group, so the fast suite prevents it from returning. That is the intended flow of work between the two documents.
