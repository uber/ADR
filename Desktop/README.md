# ADR Desktop

**Agent Security and Observability** for the person using AI agents: see their activity, put
boundaries around important files, and let agents use service credentials without
copying those credentials into prompts.

**P0 developer preview.** The macOS app has a menu-bar icon and a bundled Python
runtime; an installed Python is not needed to run the built app. It is separate
from, and does not change, the existing Sensor, Discovery, or Detection CLIs.
It does not send ADR product telemetry or use an ADR-hosted backend. Capture and
artifact matching stay local. Optional Security reviews send approved evidence
through the user's locally installed agent and its configured model provider.

## Development branch

All Desktop development stays on **`desktop-dev`** until community launch.
Create Desktop feature branches from `desktop-dev` and target it when proposing
changes, including the Sensor and Discovery updates needed by the app. Do not
merge the preview into `main` or publish a desktop release before launch review.
The branch's CI runs development checks; it does not publish an application.
It tests Linux/macOS, exercises synthetic browser workflows, and builds
commit-labelled Apple Silicon/Intel preview archives. See
[development CI and preview builds](docs/CI.md) for checks, diagnostics, and
the distinction between a development artifact and a public release.

## Included in this preview

### ADR Insights

- Start/pause collection from the menu bar or local UI.
- Reuses the existing ADR Sensor parsers for Claude Code, Cursor, Codex, Copilot
  CLI, DeepSeek Harness, Antigravity CLI, opencode, Gemini CLI, Cline, Warp, and Claude Desktop,
  subject to each collector's OS/format support.
- Sessions, messages, tool arguments/results, projects, reported token usage,
  collection health, search, and JSON export.
- A separate, explicitly initiated ADR Discovery scan for installed agents,
  MCP servers, skills, and extensions.
- Local SQLite persistence, full-content snapshot deduplication, changed-result
  revisions, and controls to delete collected history.
- Full-text search of captured messages, tool inputs, and tool results.
- Community-focused session retrieval: agent/project/date filters, highlighted
  answer and tool-result previews, URL-backed search state, and a finder inside
  each transcript. Native titles and transcript words can match together.
- “Updated” uses captured activity, including resumed conversations, rather
  than collection time. Related work, latest-answer navigation and copy actions
  keep useful context close without changing original captures.
- **ADR Context**, an agent-facing capability for opt-in search across captured
  agents and projects on the device. The same ADR plugin includes vault commands
  and protection hooks. A separate Context UI is P2.
- Consecutive tool calls appear in a single expandable activity group.
  Parser-generated tool-only placeholder text is hidden in the view, not
  removed from stored history or exports.
- Conversations group explicitly related sub-agent sessions into expandable
  branches. Forks remain separate and link to their source conversation.
  Matching titles alone never cause sessions to be merged.
- Meaningful request/native titles replace setup-text titles. Repeated agent
  instructions and environment records live in a collapsed **Session setup**
  section, with occurrence counts. Actual repeated user requests are unchanged.
  Search and ADR Context still include every captured sub-agent session.

Existing history receives a metadata-only presentation migration. For older
Codex captures, it reads the local catalog and bounded session headers for
already-captured IDs. It does not enable capture, collect new conversations,
rewrite snapshots or widen sharing permissions. Sessions without an available
parent remain visible on their own.

Collection runs a Sensor pass over local agent logs, then waits **5 minutes by
default** before the next pass. Settings offers **5, 15, 30, or 60 minutes**.
Starting or resuming capture runs a pass immediately; paused capture runs none.
Existing seconds-based preview settings move to 5 minutes without changing
capture consent or saved history. The UI's status refresh does not run the Sensor.
Collection is not a live network tap. No new redaction or clipping is applied
to normalized Sensor payloads.
The existing collectors' filtering and any upstream omissions still apply.
There is an explicit 8 MiB per-session limit and a 1 GiB local store limit;
refused records surface as partial collection, not a successful empty scan.

### Security reviews

- **Review now** launches a bounded, read-only review of a selected captured
  session using `claude -p` or Codex's app-server and the CLI's current sign-in.
- **Review while idle** is off by default. Choose projects, device idle time,
  and either a fixed review budget or spare-subscription-capacity scheduling.
- Per-review and rolling 24-hour token budgets, a review-count ceiling,
  runtime limits, cancellation, and explicit permission for configured API or
  managed access. Claude additionally receives `--max-budget-usd`.
- Codex quota comes from `account/rateLimits/read`. An opt-in Claude status-line
  bridge preserves an existing status command and reports five-hour/seven-day
  usage. Missing, partial or stale quota never counts as spare capacity.
- Reports include validated message references, links to sessions, and explicit
  input coverage. Failed or partial reviews are never reported as clean.

Budgets are admission/stop thresholds, not provider-side hard token caps: an
in-flight response can overshoot. Unknown/interrupted usage keeps its reservation.
Codex has no claimed dollar cap. No credentials are extracted, accounts switched,
credits bought, repositories changed or PRs published. See
[Security reviews](docs/SECURITY_REVIEWS.md) for setup and limitations.

### AI inventory

Access diagnostics group unreadable paths by location and separate OS permissions,
read errors, optional missing paths, intentional exclusions and scan limits.
Every recorded detail remains reachable through pagination. **Set up device
access** opens the appropriate macOS settings and identifies the running app;
it does not claim to grant Full Disk Access automatically.

**Scan this device** runs a local Discovery pass independently of session
capture. Search all results by name or path; **Applications & CLIs** groups
desktop apps, CLI agents, AI browsers, and local model runtimes while keeping
their types visible. Results are paginated, not cut off after 200 items.
Application marks are local text badges; the UI never requests remote logos.

- **Installed / Running** comes from Discovery's identified assets.
- **Configured** means a local declaration was found, not that a skill,
  hook, or MCP server is enabled or running.
- **Unverified executable** means a filename resembles a known tool but
  package or publisher identity was not established. This includes standalone
  CLI builds when no supported provenance source is available.

Open **What this scan could check** for exact paths and reasons: operating
system permissions, the bounded scan limit, unavailable optional sources,
partial inputs, and deliberately skipped private/cache locations are shown
separately. ADR does not hide those limits or ask for broad elevated access.
The macOS app checks both system and user Applications directories, including
the public Codex/ChatGPT bundle identifier. Run another scan after upgrading
to refresh older inventory names and coverage.

### Known-malicious artifact protection

- **Malicious artifacts** checks supported skill/file reads, package installs or
  launches, and MCP calls against a reviewed local artifact list.
- Complete hashes, exact package identities, and verified configured endpoints
  establish matches—not familiar names or prose keywords.
- The bundled baseline covers eight exact malicious package releases and one
  binary hash. Skill hashes and MCP endpoints can be supplied through an
  owner-reviewed local JSON import; the baseline does not invent them.
- Installed-item findings and actual blocked activity are separate. Checks and
  imports stay on device, and no community reports are submitted automatically.
- Blocking is independent of file rules. Unknown artifacts retain the user's
  existing behavior; this does not certify them as safe.

See [Malicious artifact protection](docs/THREAT_PROTECTION.md) for feed format, tested
operations, and limits. Hooks do not universally intercept automatic skill
loading, MCP startup, arbitrary scripts, or dependency resolution.

### File protection

- **Blocks and approvals** shows blocked operations and approval requests,
  including requests that were allowed after approval. Routine passed checks
  remain available for hook health and local auditing without filling the page
  or repeatedly closing its controls.
- **Add starter protections** in one click: an optional Block set for standard
  Keychain, SSH/GPG, cloud, Kubernetes, Git, and package-registry credential
  paths. Connect a protection hook first, then review the paths and add the
  set. Existing choices stay intact. The onboarding card disappears afterward;
  individual rules remain manageable. See the [starter set and its limits](docs/DEFAULT_PROTECTION.md).
- Choose a file/folder and **Ask first** or **Block**.
- Connect Claude Code, Codex, opencode, or GitHub Copilot CLI.
  Existing settings/hooks are preserved and backed up. Restart the agent after
  installing or removing a hook.
- Bounded pre-read checks recognize common credential formats. Supported
  post-tool hooks withhold a matching result before model delivery and direct
  the agent to the vault. Findings record credential types, never matched
  values. See [hook support and limits](docs/HOOKS.md).
- Resolve relative paths and symlinks; check protected-file hard links and
  recursive searches of protected descendants.
- Command and unknown-tool review is separate and **Off by default**. Opt into
  **Ask each time** or **Block** under **Advanced: command approvals**. Direct
  file rules and supported credential checks remain active when this is off;
  arbitrary command execution is not a filesystem sandbox.
- Ask rules and command approvals use the harness's native prompt where
  supported, or a one-shot native ADR dialog. Without an available approval
  surface they block; an unsupported `ask` value is never emitted as if safe.
- Concurrent ADR approvals queue in order rather than being rejected because
  another dialog is open. The bounded queue shares each request's 90-second
  deadline with its dialog and reports expiry, denial, or app unavailability.
- A small standalone guardian bounds hook runtime and returns an explicit deny
  if the core is missing, stalls, or produces an invalid decision.
- Cached Block rules work while the UI/daemon is closed. ADR-native approvals
  require the app to be running. The guardian lives in the
  private state directory, outside the movable `.app`.

**This is a cooperative harness control, not an OS sandbox.** It cannot enforce
policy on an agent launched without the hook, stop arbitrary local processes,
or eliminate the check/use race inside a third-party tool. Unknown tool access
is not silently labeled protected. See [the security model](docs/SECURITY.md).

### Credentials

- **Add credential** asks for a name and an environment-variable name. The
  value is entered in ADR's native secure window and encrypted in local files;
  multiline values can be pasted there too. There is no required API URL.
- Normal use does not require Keychain or recurring unlock prompts. Existing
  Keychain entries can be explicitly copied once into the local vault; their
  originals remain intact. Interrupted saves can be recovered without deleting
  a verified copy.
- **Connect installed agents** installs one ADR plugin for all detected,
  supported CLIs. It includes `adr_list_environment`, `adr_run_command`, history
  search, and hooks. There is no per-project, per-key, or separate vault setup.
- All saved variables, including future additions, are available to connected
  agents. Local Bash/child programs receive real values; the model receives
  names and filtered output. Ordinary shell tools do not inherit the vault;
  the plugin guides credential-dependent work through the ADR runner.
- The native runner filters selected values and common encoded echoes before
  returning stdout/stderr. It has a 60-second maximum, a 64 KiB combined output
  bound, and process-group cleanup. Code can consume the environment in the
  usual way (`os.environ`, `process.env`, or shell variable expansion).
- Updated Claude Code and Codex integrations check text at
  **UserPromptSubmit**. Recognized keys, explicit password assignments and
  known saved values block submission and direct the user to the vault UI.
  Replace the literal with `$VARIABLE` and submit again. New hooks require
  installation/update, restart, and the agent's trust review.
- No automatic import or resubmission occurs. Unfamiliar, unlabeled passwords
  cannot always be detected. Prompt-audit records contain only types/aliases,
  not submitted text. Existing captured history is not redacted.

Existing **API-only credentials** retain the previous HTTPS broker:

- Secrets are entered into a **native secure window**, not an HTML password
  field. The native app encrypts them in the private local profile.
- The browser, Python daemon, SQLite metadata, and MCP connection do not receive
  the stored service secret.
- Bearer tokens, API-key headers, and Basic-auth passwords for public HTTPS APIs.
- Credentials are bound to an origin and permitted path prefixes in the
  authenticated encrypted record. The requesting agent cannot change the destination.
- Vault-only MCP access to selected credential aliases. Choose **automatic
  allowed GETs** with explicit setup consent, or **ask before each request**.
  Vault connections do not grant conversation-history access.
- DNS results must be public addresses. The native transport pins the TCP
  connection to a validated address, verifies TLS against the service hostname,
  refuses redirects, and bounds responses.
- Direct/commonly encoded credential echoes are withheld. Results expire after
  five minutes. Connections and credentials can be revoked.
- **Use with an agent** explains the saved reference and provides an example
  agent request. **Recent vault requests** shows request outcomes. Vault access
  does not depend on file hooks.

See [using your credentials with agents](docs/CREDENTIALS.md) for setup,
supported formats, automatic approvals, and the distinction between a
credential detection and a saved vault entry.

API-only grants remain **GET-only** and never gain execution access. The
environment runner is separate and can invoke CLIs/SDKs that consume credentials
from their environment. It is not browser autofill, a dedicated SSH signing
agent, automatic credential-file creation, or a sandbox. A program receives the
selected values and can deliberately write, transform or transmit them; output
filtering is not universal DLP or isolation from same-user code.
The design is informed by the
[Roblox credential-protection publication](https://about.roblox.com/publications/how-roblox-gives-ai-agents-access-without-giving-them-credentials).

## Build and run the macOS app

Prerequisites for building: macOS, the Xcode command-line tools, Python 3.11+,
and [uv](https://docs.astral.sh/uv/).

From `Desktop/`:

```sh
uv sync --locked --extra dev
uv run python scripts/build_macos.py
open dist/ADR.app
```

The app appears as a shield and **ADR** in the menu bar. Choose **Open ADR
Insights**. Its private, one-time link authenticates the local browser; there is
no operator-token copy/paste step.

1. **Start local capture** to opt into reading supported agents' existing logs.
2. Choose **Connect installed agents** in the app, or run
   `adr-desktop connect all --allow-agent-access`. This installs protection,
   Context, and vault command tools together. Restart/trust the integration, then add starter
   protections or custom rules in **File protection**. A saved hook
   configuration is shown separately from an observed hook report.
3. In **Credential vault**, add a variable. Connected agents can use it
   immediately, with no extra configuration. Credential-dependent Bash/code
   runs through the plugin's `adr_run_command` tool.
4. Ask your connected agent to search earlier conversations. Its ADR Context
   tools can search messages and tool activity across captured agents. There
   is no separate history-MCP screen or manual MCP-configuration step.

One setup action authorizes the combined integration. Old history-only
capabilities are replaced on successful upgrade, not silently widened.
Earlier manually configured project/API/selected-variable connections retain
their original scopes. See [agent integration](docs/AGENT_INTEGRATION.md).

The app does not automatically install hooks, enable login startup, import
secrets, or turn on collection on first launch. **Start at login** is a separate
user-controlled setting. For login registration, put the app in a stable
application location.

The build is ad-hoc signed for local evaluation, not Developer ID signed or
notarized for public distribution. The native host targets macOS 13, but the
effective bundle minimum follows the Python runtime used to build it. Check
`Contents/Info.plist`; a build made with a macOS-26-only Python also requires
macOS 26. Release builds should use an intentionally selected deployment target.

## Headless/local development

```sh
uv run adr-desktop serve
# In a second terminal:
uv run adr-desktop open
```

The daemon binds **only to 127.0.0.1**, chooses an available port, and serves the
same UI. A private owner-access file supports the developer `open` command.
Native credential storage is deliberately unavailable without the menu-bar
host; there is no plaintext or mock fallback.

The core is portable Python. The macOS app is the validated desktop target;
native Windows/Linux tray applications and their native credential brokers are
not included. The POSIX guardian can be built on Linux with a C compiler.
Native Windows hook installation is refused in this preview.

## Storage and recovery

Default state:

- macOS: `~/Library/Application Support/ADR Desktop`
- Linux: `$XDG_DATA_HOME/adr-desktop` or `~/.local/share/adr-desktop`
- Windows headless: `%LOCALAPPDATA%\ADR Desktop`

Use `--state-dir` to choose a dedicated profile. State is private to the current
user. An OS-held lock prevents two daemons sharing a profile.

Deleting history pauses collection and removes only ADR's session copies, not
the agents' original logs, file rules, connection grants, or local vault records.
Captured history may already contain secrets. Model-bound history responses
are checked separately and withheld if they contain recognized or saved values
or cannot be checked. The original capture and local UI stay unchanged; the
check cannot recognize every unknown secret.

To remove only ADR's managed hooks, including when the UI cannot start:

```sh
uv run adr-desktop disconnect --harness all
# Bundled equivalent:
dist/ADR.app/Contents/Resources/core/ADRCore disconnect --harness all
```

Restart the affected agents afterward. Disconnect hooks before deleting the
app/state directory. To remove saved credentials, use the Credential vault page.
Keep `local-vault/key.v1` and its encrypted records together in profile backups.
The local key avoids unlock prompts but does not isolate secrets from the same
OS account or a copy of the entire profile. Old Keychain originals are retained
after migration and can be managed separately in Keychain Access.
Deleting an ADR credential does **not** revoke the upstream provider's token.

## Development checks

```sh
uv run pytest -q
uv run ruff check adr_desktop tests scripts
uv run python -m playwright install chromium
uv run python scripts/ui_qa.py
uv run python scripts/build_macos.py
dist/ADR.app/Contents/MacOS/ADR --self-test
dist/ADR.app/Contents/MacOS/ADR --vault-self-test
uv run python scripts/package_smoke.py
```

UI QA uses a disposable synthetic profile and a fresh browser, never the
developer's logged-in browser. Native vault checks use disposable encrypted
files and a synthetic legacy source, never real Keychain items.
For interactive MCP/browser testing and repeatable improvement passes, see
[the community UI lab](docs/COMMUNITY_QA.md).

See the [validation record](docs/VALIDATION.md) for executed checks and the
remaining platform/release-validation limits.

## Scope

The preview includes Insights, file hooks, the local credential vault,
known-malicious artifact matching, and opt-in local-agent Security reviews.
Automated community intelligence submissions, on-device learned prevention,
idle-time security patching, fleet management, and hosted services remain
follow-up work. No proprietary integrations or training datasets are required.
