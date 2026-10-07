# P0 validation record

Validated locally through October 7, 2026, on macOS 26.7 / Apple Silicon with
Python 3.11.16. This is a developer-preview validation record, not a claim of
production certification or cross-platform native testing. Earlier runs are
retained below.

## Component boundary and simpler setup — October 7, 2026

- **934 Desktop**, **586 Sensor**, **359 Discovery**, and **26 Protection**
  tests passed. Protection was checked on Python 3.11 and 3.13 and installed as
  a non-editable wheel into an empty environment outside the checkout, without
  Desktop or its dependencies.
- The artifact engine retains the original validation, normalization, matching
  order, and canonical digest behavior. Fixed expected records were captured
  from the original implementation before extraction. Desktop's compatibility
  adapter and existing enforcement tests exercise the same implementation.
- All seven synthetic browser suites passed, including the new empty-profile
  setup suite. Viewing features and hiding the introduction leave capture,
  scanning, agent installation, login startup, and model reviews off.
- Browser checks cover explicit capture failure/recovery, duplicate-click
  protection, slow installation, cancelled consent, missing/failed agents,
  idempotent retry, configured-versus-reported status, and preserved keyboard
  focus/disclosures during background refresh. Zero-session users still see
  pending approvals; update-needed vault connections are not called disconnected.
- Light, dark, and narrow screenshots were inspected. Testing used fresh
  Playwright browsers, temporary agent configuration roots, and synthetic native
  and plugin drivers—not the user's logged-in browser or live application.
- An Apple Silicon staging app built and passed signature/module verification,
  native security/local-vault self-tests, and packaged-core/MCP/guardian checks.
  The running app was not replaced. This pass does not claim new live-harness
  trust validation or change the native acceptance limitations recorded below.
- Ruff, JavaScript syntax, actionlint, and whitespace checks passed. The branch
  CI adds independent Protection tests and wheel installation, plus first-run
  browser coverage. [All 12 branch CI jobs passed](https://github.com/uber/ADR/actions/runs/37613019678):
  Linux on Python 3.11/3.13, macOS core tests, both browser groups, standalone
  components, and both Apple Silicon/Intel preview builds.
- CI exposed a lint package-root assumption and a same-route browser-test race.
  Package classification is now explicit, and settings tests await completed
  renders before opening disclosures. The recorded browser trace confirmed
  that the failed test clicked the old view while it was still busy; timeouts
  were not increased and assertions were not removed.

No extra long-lived process, new database, permission migration, automatic
model request, or public release was introduced.

## Known-malicious artifact protection — October 5, 2026

- **857 Desktop tests passed**, including feed validation, exact matching,
  complete-file hashes, registry precedence, third-party configuration symlinks,
  policy publication, last-known-good fallback, scoped owner APIs, native
  approval races, and unchanged file/vault behavior. Ruff, JavaScript syntax,
  and diff checks passed.
- The packaged app built and passed signature verification. Packaged smoke
  explicitly verified the bundled feed and a known-malicious-package denial
  through the actual native guardian without executing an installer. Native
  self-tests passed all existing vault groups.
- Dedicated real-API browser tests covered local import preview/cancellation,
  invalid and oversized input, stale revisions, independent toggle behavior,
  installed findings versus actual blocks, inventory links, safe rendering,
  and light/dark/narrow layouts. A separate interactive Playwright MCP pass
  exercised navigation, the switch, installed checks, screenshots and responsive
  layout. No external UI requests were observed. The interactive MCP client's
  file-root restriction prevented its file-upload step; imports were instead
  verified by the separate real-API browser suite, not claimed as an MCP import.
- A real Codex CLI 0.160.0 sentinel used a harmless local executable named `npm`;
  it only wrote test markers and never installed a package or contacted a
  registry. **Both the listed-release attempt and its adjacent-version control
  executed.** No ADR hook report arrived for that session, so this is not a
  successful live prevention test.
- Read-only native `hooks/list` inspection identified the activation blocker:
  ADR's PreToolUse and PostToolUse definitions were enabled but `modified`,
  with stored trust hashes different from the current definitions;
  UserPromptSubmit was enabled but `untrusted`. Plugin discovery reported no
  errors. The hook-trust control was not bypassed or modified by the test.
- **Live Codex acceptance remains pending owner review of the three specific
  ADR hooks in `/hooks`.** After review, repeat the sentinel in a fresh
  temporary directory and require a denied listed-release marker, an executed
  control marker, and a fresh ADR block receipt before claiming live protection.
- The normal local profile was backed up and the app reloaded. All prior
  session IDs, snapshots, credential entries, existing file rules, and capture
  preferences remained intact. Only the public bundled baseline was loaded
  into that profile; synthetic test feeds stayed in disposable profiles.

No malware was installed, no internal intelligence was copied into repository
data, and no commit or PR was published. Native harness trust is separate from
command approval flags. A configured plugin is not evidence of enforcement.

## Community UI, access guidance and local vault — October 5, 2026

- **511 Desktop tests** and **273 Discovery tests** passed. Focused retrieval
  tests include resumed-session activity, mixed title/transcript queries, exact
  scope, restartable derived-index backfill, immutable exports and query plans.
- Native optimized tests passed all **16 vault groups**, covering encrypted
  storage, concurrent reads/writes, corruption and key-loss behavior, explicit
  partial legacy copying, late expiry/cancellation/deletion, injection versus
  output protection, and command-output filtering. The combined app built,
  passed signing verification and passed packaged-core smoke checks.
- Both broad browser suites passed. The dedicated Sessions browser suite also
  passed against synthetic data, including light/dark and narrow layouts.
- The supervising workflow used **Playwright MCP interactively**, through real
  MCP protocol calls: navigation, text input, agent filtering, transcript
  matching, Back/focus restoration, first-run access setup, interrupted-save
  recovery, legacy-copy UI, paginated inventory details, screenshots and
  390px/1440px layout inspection. Screenshots use isolated synthetic profiles;
  native prompts and OS Settings actions in that lab are simulated.
- Separate implementation, independent review and corrective model-assisted
  passes were used. Confirmed findings were fixed, including false credential
  detections on storage failure, unnecessary read-lock contention, interrupted
  save recovery, stale migration publication and retrieval semantics.
- The existing local profile was backed up before reloading the packaged app.
  Session IDs and all previous snapshots remained present; ordinary capture
  advanced one selected revision without losing its predecessor. File rules
  and existing agent grants remained unchanged.
- A native-owner-approved copy moved the existing saved test entry into the
  encrypted local vault, retaining its Keychain original. A subsequent real
  MCP command used it in a loopback-only HTTP request: the authenticated request
  returned 204 and the negative control returned 401. The child had empty
  stdout/stderr; no value, hash or length was returned to the model.

No actual Full Disk Access grant, clean-machine privacy inheritance, production
signing/notarization, or universal provider-wire secret protection is claimed.
Opening an OS settings panel is not a permission grant. The local vault key and
ciphertext share a profile and do not isolate secrets from the same OS user.
No PR or commit was published by this iteration.

## Unified agent integration — October 3, 2026

- **429 Desktop tests passed.** Added coverage for one owner action across all
  supported harnesses, automatic availability of newly saved variables, reuse
  on updates, replacement rather than widening of old history tokens, failure
  recovery, partial installation reporting, disconnect revocation, cross-project
  execution, and unchanged file Block/Ask rules.
- The combined plugin exposes history and environment commands through one
  `adr` MCP server. Scoped legacy connections remain covered by the existing
  regression tests and retain their previous permissions.
- Model-bound history results containing saved credentials are withheld while
  stored captures remain unchanged. Tests cover ordinary history, unavailable
  checking, oversized results, and absence of new prompt-audit records.
- Both isolated browser suites passed. The tests now connect all supported
  synthetic agents in one action, save a variable afterward, and verify that
  every connection can use it without new grants or configuration. No project
  or per-key form appears. Light/dark and narrow layouts were visually reviewed.
- Native tests passed for temporary-Keychain round trips, credential inheritance,
  output filtering, and strict matching of short values in model-bound output.
  The packaged-core smoke checks, JavaScript syntax check, Ruff, diff checks,
  app build, and signature verification also passed.
- A fresh Codex CLI 0.160.0 session found the unified `adr_list_environment`
  and `adr_run_command` tools without a separate vault connection. It listed
  variable metadata only. A presence-only command against the local saved entry
  did **not** complete: the native call waited in `SecItemCopyMatching` for
  macOS Keychain authorization. No value, hash, or length was returned.
  The availability failure is now reported as a Keychain/check timeout rather
  than incorrectly claiming the command contains a pasted secret. Regression
  tests ensure only closed error messages can enter MCP responses.

These are API/MCP-contract, native, and synthetic browser checks; they do not
prove complete provider-wire coverage. Claude Code/Codex prompt checks still
depend on the agent loading and trusting the hook. The original captured logs
are unchanged. Earlier entries below describe the behavior of those builds;
the new model-bound history checks supersede their raw Context-response behavior.

## Environment vault and prompt guard — October 2, 2026

- **415 Desktop tests passed.** New coverage checks metadata-only creation,
  reserved variable names, explicit execution consent, opt-in current/future
  variable access, unchanged selected/API/history scopes, revocation,
  working-directory checks, file-rule precedence, prompt recognition and
  non-retention, validation-error non-reflection, and prompt-hook installation
  and removal without deleting other hooks.
- The real native temporary-Keychain tests passed for storing/loading an
  environment credential, checking a pasted value, Bash/child-process
  inheritance, stdout/stderr and Base64 filtering, output-limit withholding,
  timeouts and cancellation of stale execution requests. They never read the
  user's login-keychain credentials.
- Both synthetic browser suites passed, including the new two-field vault
  form, native-entry delegation, code examples, explicit all-variable sharing,
  future-sharing notice, stopped-prompt activity, and narrow/dark layouts.
- Packaged smoke checks exercised the compiled prompt guardian through the
  real loopback service: a synthetic password assignment was blocked without
  echoing it, and a variable-reference prompt passed. Headless environment
  creation returned unavailable rather than storing a plaintext substitute.
- The self-contained app built; native security tests, signature verification,
  bundled/source UI comparisons, Ruff, JS syntax and diff checks passed.

These are native execution/Keychain, HTTP/guardian, API/MCP-contract and browser
checks. The **new prompt-submission and environment-execution paths have not
been revalidated in a model-driven vendor session**; the earlier live Codex run
below covered the previous pre/post/Context integration. New prompt hooks must
be installed/updated and trusted before they can block submissions. No real
credentials were used and no existing agent permissions were widened.

## UI, inventory and live-plugin follow-up — October 2, 2026

- **354 Desktop tests passed**, including literal shell-file checks and
  regressions for working directories, quoted paths, comments, BSD option
  handling, and the priority of explicit command blocking over file approvals.
- **297 Discovery tests passed** across the unit and endpoint-fixture suites.
  Coverage includes system/user application roots, Codex desktop identity,
  unverified standalone CLI candidates, bounded scanning and extraction,
  readable hook names, and separate identities for callbacks with equal titles.
- Both isolated browser suites passed: `scripts/ui_qa.py` and
  `scripts/navigation_qa.py`. Tests cover more than 200 inventory items,
  search/filter persistence, scan-reason pagination, credential-form visibility
  and submitted metadata, automatic/per-request permission setup, session
  navigation and Back restoration, async route races, keyboard focus, error
  recovery, dark mode and narrow layouts. Dialog actions stay visible while
  their fields scroll. Screenshots were visually reviewed and use synthetic
  data only.
- **Real Codex sessions** verified native plugin installation and selective
  hook trust, cross-agent Context search/read, allowed and blocked file reads,
  stopped-daemon behavior, revoked access, and credential-shaped output
  withholding. The test registration and marketplace were removed afterward;
  synthetic permissions were revoked. See the
  [live Codex evidence and limits](LIVE_CODEX_VALIDATION.md).
- The live run exposed a missing check for simple shell file reads. The
  corrected packaged guardian also denies the corresponding synthetic hook
  request in `scripts/package_smoke.py`.
- Ruff, JavaScript syntax and diff checks passed. The self-contained app built
  and passed signature verification, native security self-tests, an isolated
  temporary-Keychain round trip and packaged-core smoke checks. A native
  pinned-HTTPS request with a deliberately invalid synthetic token returned
  the expected HTTP 401; no user credential was used.
- The local Discovery and Sensor dependencies were rebuilt into the package.
  Bundled UI assets and the Discovery catalog were compared with source.
  The existing Sensor lineage regression tests also passed.
- The running menu-bar app was reloaded after checking for active credential
  work and making a private database backup. The new process served the exact
  tested UI assets. All pre-existing session/grant/credential records remained
  present, and the file-policy digest was unchanged.

Post-tool withholding is not removal of original tool telemetry. The Codex
live run retained the original synthetic output in its raw local execution
events, even though the agent reported receiving ADR's replacement message.
No provider-wire payload inspection was performed. Sensor capture stays
unredacted, and Context sharing can include content preserved in those logs.

## Initial preview checks — October 1, 2026

- **254 Python tests passed**: local authentication/CSRF/host checks, capability
  separation, project scope and path aliases, full-content snapshots,
  unchanged-result deduplication, file policy, offline hooks, settings
  preservation, guarded process failures/timeouts, broker approval/revocation,
  stdio MCP, and real Claude-parser-to-store integration with synthetic logs.
  Regression coverage includes multi-tab bootstrap, stale/expired sessions,
  ticket reuse rejection, CSRF refresh isolation, minute-based capture
  intervals, saved-settings migration, and paused/scheduled collection.
  Starter-path tests cover opt-in behavior, platform-specific catalogs,
  metadata-only previews, concurrent/idempotent application, preservation
  of custom Ask rules and paused state, aliases and unsafe symlinks, atomic
  failure/capacity handling, authenticated API access, and both offline hooks.
  Further coverage includes full-text history indexing/migration, separate
  history/vault permissions, opt-in automatic GET use, same-profile hook
  gating, Codex/opencode installation preservation, credential-pattern
  withholding, native-approval authorization, and verified ADR MCP exemptions.
  The opencode V1/V2 contract test executes the JavaScript adapters against
  the real local guardian/core using synthetic files and outputs.
  Agent-package coverage includes combined hook/MCP manifests, Context-only
  permissions, explicit setup consent, native enrollment authorization,
  permission reuse on updates, failure revocation, and disconnect ordering.
  The generated Codex plugin passed the Plugin Creator schema validator.
- Ruff and JavaScript syntax checks passed.
- Browser UI checks passed with a disposable synthetic profile: all pages,
  session expansion, captured-text injection resistance, adding a file rule,
  native-credential-entry delegation, one-shot approval, narrow layout, and
  dark mode. Pause works after opening a second tab. A stale CSRF token is
  refreshed once, with one resulting mutation; generic errors and network
  failures are not retried. All four minute-based intervals save and survive
  a page reload, without starting paused capture. The existing browser
  profile was not used.
  Starter protection was disabled before connecting a hook in the disposable
  profile, then added in one click. Its onboarding card disappeared after
  application and stayed hidden after reload. Individual rules were removed
  and restored while protection remained paused. Custom rules stayed unchanged.
  Grouped tool calls, full-text session search, device-context setup consent,
  vault-only automatic-use setup, and narrow/dark layouts passed.
  The dedicated History MCP page/action was removed; Context is delivered as
  an agent capability. Native plugin-manager commands are replaced by a fake
  driver in browser tests, so no live agent settings are changed.
- The bundled native security tests passed: origin/path restrictions,
  non-public-address rejection, HTTP framing/redirect limits, and credential
  echo withholding.
- The native Keychain round trip passed using a newly created temporary
  keychain, which was deleted afterward. No existing user credential was read.
- A live pinned-HTTPS transport check passed against GitHub's `/user` endpoint
  with a fixed invalid synthetic token. It received the expected HTTP 401.
  This did not use a real provider credential.
- The self-contained `.app` built and passed `codesign --verify --deep --strict`.
- Packaged-core smoke tests passed: HTTP resource serving, private API access,
  multi-tab browser authentication, CSRF enforcement, all four capture
  intervals, starter connection gating and offline enforcement,
  legacy project MCP and device-wide history-search calls, and the standalone
  hook guardian.

## Hook approval follow-up — October 1, 2026

- **307 Python tests passed** after the approval fix. Regression cases cover
  default passthrough for unrelated tools, explicit strict-mode opt-in, saved
  policy migration, and preservation of protected-path and credential checks.
- Concurrent native approvals were exercised with an isolated fake native host:
  FIFO ordering, bounded capacity, expiry, shutdown, policy changes while
  waiting, unavailable dialogs, and rejection of late Allow responses.
- The real compiled guardian preserves each closed failure reason and rejects
  unrecognized reason tokens. Packaged smoke checks confirm unrelated Codex
  tools pass without a native UI, while explicit strict review reports an
  unavailable approval dialog accurately.
- Native self-tests cover expired, malformed, bounded, and remaining approval
  deadlines without opening a dialog. The app was rebuilt and its signature,
  native self-tests, packaged smoke tests, Python lint, and JavaScript syntax
  checks passed.
- The local preview was reloaded after validation. Existing file rules were
  verified unchanged and the already-managed guardian was upgraded. No agent
  plugin was installed, enabled, or re-enabled.

## Deliberate verification limits

- No real user credentials were added or exercised.
- Codex live validation used uniquely named synthetic plugin registrations and
  their own hook-trust decisions. It did not replace the user's normal
  integration or change unrelated security hooks.
- Claude, opencode and Copilot adapters still have synthetic contract tests,
  not equivalent live model-driven validation in this run. Their native
  installation commands remain simulated in automated browser tests.
- The bounded shell recognizer is not an arbitrary-command filesystem sandbox.
  Other shell syntax retains the user's explicit unclassified-command setting.
- The environment runner supplies text values to programs; it is not automatic
  prompt rewriting/import, SSH-agent service, browser autofill, or credential-file
  creation. Existing API-only entries remain GET-only. Generic execution does
  not isolate secrets from the authorized program or same-user processes.
- No login item was enabled.
- Native Windows/Linux tray, native Windows enforcement, signing/notarization
  for public distribution, and automatic signed updates are not included.
- The CI workflow is checked in for review; it has not run remotely because
  this work has not been published.
- Browser screenshots use synthetic data. Native menu-bar operation is
  implemented and the app/core process relationship and local health endpoint
  were checked; there was no automated pixel inspection of the system menu bar.

## Optional live transport check

This sends only a fixed invalid synthetic value to GitHub, not a Keychain value:

```sh
xcrun swiftc -swift-version 5 -O -framework Network -framework Security \
  native/HTTPTransport.swift native/TransportSmoke.swift -o build/transport-smoke
build/transport-smoke
```

## Security reviews — source preview, October 6, 2026

- The full Desktop suite passes with 906 tests. New tests cover both subprocess
  protocols, pretty-printed Claude authentication output, token/cost reservations,
  cancellation, parent-lifetime loss, restart accounting, multi-window quota,
  stale/partial observations, account separation, explicit paid-use consent,
  input coverage, exact evidence citations and history deletion.
- `scripts/reviews_ui_qa.py` drives the real owner API and UI through setup,
  consent, both review adapters, quota display, Claude status-line configuration
  and session navigation. Its agent subprocesses are inert protocol fixtures.
  Desktop/narrow/light/dark screenshots are synthetic; no model requests or
  external resource requests are made.
- JavaScript syntax, lint on the new modules/tests, and native Swift type-checking
  pass. Native type-checking includes the macOS idle-time endpoint.
- Installed-agent checks were limited to authentication/read-only protocol
  discovery. They do not establish a successful real-provider inference run.
  End-to-end provider validation still requires working CLI authentication and,
  for API/managed access, explicit permission to consume that account's capacity.
- No real session evidence was sent to a model, no background mode was enabled
  in the user's profile, and no real Claude status-line configuration was changed.
- In the subsequent owner-requested rollout on October 6, the app was built to
  a staging destination and its signature, packaged API/UI resources, native
  security/vault self-tests and frozen review-supervisor lifetime guard passed.
  The prior application and database/policy were backed up before replacement.
- After relaunch, the native host/core health check passed; all prior session
  and snapshot IDs and credential/grant metadata were retained. Capture
  preferences and file-protection rules were unchanged. Reviews remained
  unconsented/off, with no model jobs started. OS privacy settings were not
  changed; development-signature privacy attribution remains a separate issue.
