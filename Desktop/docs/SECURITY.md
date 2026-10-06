# ADR Desktop security model

## Trust boundaries

The local browser is the user interface, the Python core is the local control
plane/store, and the native macOS host owns secret entry, encrypted local storage, and
credential-backed HTTPS and command execution. Parsers run in subprocesses with separate output;
transcript content cannot become messages on the trusted native IPC channel.

The native broker has no `get secret` operation. An API credential's destination,
authentication method, and path scope are stored alongside its secret in the
authenticated encrypted record. Merely altering a destination in SQLite cannot
redirect that secret. Values are not exported through a generic secret API.

Environment credential use is included in the owner-approved ADR plugin. Their variable
names and values are encrypted together in the local profile. The native host supplies them
to an authorized child process, not to the core, MCP tool arguments, or a
global agent environment. Raw command/output text is not retained in the
execution audit. This cannot isolate secrets from the program that receives
them or from unrestricted same-account code. Local capability authorization
is a protocol boundary, not protection against local code tampering with
same-user files, stealing capabilities, inspecting processes, or deliberate
exfiltration.

The local vault uses CryptoKit AES-GCM with record-ID authenticated data, atomic
create-only writes, bounded reads, owner-only modes, and descriptor-relative
symlink/ACL checks. The generated key is stored beside encrypted records in the
private profile. This removes recurring unlock prompts, but is **not** a boundary
against the same OS user or theft of the whole profile. Missing keys are not
silently regenerated beside existing ciphertext.

Keychain is read only for an explicit, native-host migration of registered IDs.
Original items stay unchanged. Routine status, prompt/output checks, saves,
deletes and command execution do not access Keychain. Interrupted saves retain
their IDs and can be explicitly recovered after native validation. Failed or
uncertain operations are not treated as empty, safely repeatable saves.

Developer ID signing, notarization and clean-machine permission/upgrade testing
remain release work. The current ad-hoc development build cannot promise stable
macOS privacy attribution across every rebuild.

## Local authentication

- The service listens on loopback only. Host and Origin are checked; there is
  no permissive CORS configuration.
- A 60-second, one-use fragment ticket creates an HttpOnly, SameSite=Strict
  browser session, or renews the browser's existing valid session so other
  tabs remain usable. The ticket is consumed in either case. The page removes
  the ticket from the address bar.
- Browser mutations require a separate CSRF token. A stale token is rejected
  before the operation executes. The UI can refresh it through the same-origin,
  authenticated session endpoint and retry once, only for this rejection.
  Network failures, timeouts, and other HTTP errors are not retried.
- The native owner's capability travels over private parent/child pipes, not
  a persistent owner-token file. Headless developer mode uses an owner-only
  local file instead.
- Hook capabilities can report decisions and request an owner's native
  approval dialog; they cannot grant themselves approval or administer the app. MCP capabilities
  cannot alter policies, create credentials, mint owner sessions, or approve
  their own requests.
- **Connect installed agents** is one consent action for device-wide history
  search, protection hooks, and automatic use of all current/future environment
  credentials. Programs intentionally receive real values; the model should not.
  There is no per-project or per-key workflow in the unified plugin.
  Older manually configured history, selected-entry, project, and API-only grants
  retain their original scopes. A plugin upgrade replaces its history-only grant
  after success instead of widening the previously issued token.
- Agent integration setup bundles hooks, Context, and vault command tools. CLI setup
  in native-app mode requires an owner's native confirmation; an unprivileged
  local request cannot approve itself or receive a raw capability. Browser
  setup retains owner/CSRF checks. Failed fresh installs revoke the new grant;
  disconnect revokes both history and credential use before attempting native plugin removal.
- Model-bound history responses are checked for saved values and recognized key
  formats. A flagged, oversized, or uncheckable response is withheld. This does
  not rewrite Sensor captures or the local UI. Prompt detection remains bounded
  and heuristic, and unsupported harness submission paths are not protected.

The operating-system account is a trust boundary. Unrestricted same-account
code, accessibility automation, debugging privileges, root access, or a
compromised trusted app are not covered by a cooperative hook/API boundary.
Use OS sandboxing and least privilege for genuinely untrusted programs.

## File decisions

The policy file is the shared authority for the UI and offline adapters. An
update is acknowledged only after its atomic private-file write. Block wins
over ask. Normal accesses return an empty hook result, not `allow`, so ADR does
not bypass an agent's own permission system.

Checks cover direct paths, symlink resolution, protected-file hard links,
conservative macOS/Windows case matching, and recursive searches that include
a protected descendant. Strict execution review is a separate, explicit opt-in:
shell execution and unclassified tools pass through to the harness's own
permissions by default. In strict mode they ask or block. An empty protected-path
match is not presented as evidence that a command cannot access sensitive files.
This default does not claim to mediate arbitrary command or third-party-tool
filesystem access. Use strict review or an OS sandbox for that threat model.

The standalone guardian emits native deny/withhold output if the core fails,
is missing, has invalid output, or exceeds its four-second evaluation budget.
A checked operation awaiting a native owner decision can explicitly extend
that deadline to 120 seconds; a stalled evaluator cannot silently become an
allow. The core's own watchdog is an additional layer. Vendor hooks still are not a
kernel boundary: a missing guardian, a bypassed harness, vendor hook bugs,
different tool formats, and filesystem changes between check and use cannot
be made impossible by a pre-tool callback.

Native owner approvals use a bounded FIFO queue, with a shared 90-second budget
for waiting and displaying each request. Queue exhaustion, expiry, shutdown,
and unavailable native UI deny with distinct reasons. Policy changes are checked
before and after a dialog; neither queued requests nor late native responses can
override a new Block rule. The native host also rejects expired IPC requests
before displaying them. The guardian accepts a closed reason-code vocabulary,
not free-form output from the child process.

Supported file operations keep guarding ADR's own state and relevant hook
configuration paths, including while custom file rules are paused. This is not
protection from arbitrary same-account command execution. Close/restart an
agent when changing its settings.
Installation preserves other hook entries, checks for concurrent edits, and
keeps a private backup. Removing a hook merges out only ADR entries; it does
not restore an old whole configuration over newer user changes.

Credential-pattern checks are bounded and heuristic, not a proof that content
is secret-free. They do not identify every provider, encoding, image, encrypted
blob, or custom credential format. Pre-read inspection has a filesystem
check/use race; post-tool withholding cannot undo the operation's side effects
or guarantee that the harness never retained an original result.

ADR MCP calls bypass a redundant file-approval prompt only when the integration
can verify the exact packaged executable, same-profile access file, configured
server definition, and current backend grant. A familiar tool/server name alone
is insufficient. Wrappers, custom environments, conflicting project definitions,
and configurations the verifier cannot parse fall back to ordinary protection.
Other harness-level approval and trust controls remain in force.

Reference contracts and provider-specific limits are in [hook support](HOOKS.md).

## Artifact intelligence

[Malicious artifact protection](THREAT_PROTECTION.md) is deterministic, local matching of
reviewed exact identities, not a malware classifier or an OS execution boundary.
The source taxonomy remains separate from artifact indicators. Feeds contain no
executable rules, regexes, or network probes. Owner imports are fully validated,
revision-guarded, and published as one generation inside the existing policy.
Invalid imports retain the earlier generation; malformed trusted policy retains
the guardian's existing policy-unavailable denial behavior.

Existing file denies cannot be weakened by a non-match. Known artifact matches
deny before supported execution, including inside the vault runner. Approval
reevaluation in the daemon is limited to context-independent direct-file checks;
the final hook rechecks all supported identities in the original agent process
context. Registry/home/configuration assumptions from the daemon must not be
substituted for the invoking harness. A native owner's earlier answer never
overrides a new deny.

Block receipts are metadata-only and validated against accepted generations.
They do not retain raw commands, skill text, config environment/header values,
or credential-bearing URLs. Installed findings remain distinct from enforcement
receipts. An unlisted or unresolved artifact is not labeled safe.

Automatic loading, MCP initialization, general shell behavior, transitive build
dependencies, unsupported configuration, and changes after inspection need
separate controls. No startup interception or universal malware prevention is
claimed.

## Broker restrictions

### Environment execution

The core authenticates an execution grant, checks its selected entries and
working directory, evaluates supported file/command policy, and obtains native
approval when required. Queue wait and approval share one deadline. Access and
policy are rechecked before native execution and revocation suppresses results.
The working directory is not a filesystem sandbox.

The native runner uses a bounded, noninteractive Bash process and a clean base
environment. Credential aliases cannot override loader, interpreter-startup,
shell-control or other reserved process variables. Selected values are injected
only after native validation; process-group tracking retains PID ownership until
cleanup/reaping. Service restart and normal app shutdown cancel active groups.
Deliberately detached programs are outside this cooperative boundary.

Output is buffered and filtered before IPC. Literal, Base64, percent-encoded and
JSON-escaped forms are checked, but arbitrary transformations are not covered.
Oversized, timed-out or non-text output is withheld rather than returning a
possibly secret-bearing truncated prefix. Programs can still persist values in
files or send them over the network. Command execution can modify local or
external state and is not equivalent to the read-only API grant.

### Prompt submission

The installed Claude/Codex prompt hook forwards bounded text over authenticated
loopback/private IPC for local pattern/known-value checks. Text may contain
credentials in memory but is not stored in ADR's prompt-audit table or emitted
in validation errors. Only types and public aliases are retained. Failures block
submission instead of approving an unchecked prompt.

This requires a loaded/trusted, supported hook. It is not a network interceptor,
does not classify every arbitrary password, and cannot undo the harness's own
earlier history persistence. It does not automatically import or resubmit
credentials. Pausing file rules does not disable the separate prompt guard.

### API-only requests

Each request is immutable and bound to its requesting grant and credential ID.
An explicit automatic-use grant authorizes only the credential's saved HTTPS
origin and GET path prefixes. Otherwise the owner must approve that exact request
once. Existing grants keep per-request approval. Pending requests expire. Revocation prevents
new use and clears retrievable results, but cannot undo an HTTP request that
was already sent.

Only public HTTPS origins on port 443 and GET requests are supported. There
are no caller-selected authentication headers, arbitrary redirect targets,
cookies, proxy settings, or filesystem URLs. The native client validates DNS
answers, connects to that verified IP, requires TLS 1.2+, validates the
certificate against the original hostname, and never follows redirects.
Header and response sizes are bounded. Compressed/binary responses are
refused in the initial transport.

Known literal/encoded credential echoes are withheld, including JSON string
escaping. This is not universal data-loss prevention. An approved service is
trusted with the credential and could split, transform, or misuse it. Grant
only the smallest useful path scope; use provider-side limited/revocable
tokens whenever possible. GET is the only emitted method, but the service
ultimately controls whether its GET endpoints have side effects.

## Local data

Normalized Sensor payloads are not newly redacted or clipped. A local SQLite
full-text index covers the latest retained snapshot of each session, including
message content and tool data. Indexing does not upload data or grant MCP access.
Schema migration preserves existing snapshots and access restrictions.
A short UI title
or collapsed message is only a view; full normalized content remains stored.
Changed same-ID tool results create a new content-hashed revision. Capture
limits and parser failures are surfaced explicitly. Upstream omissions,
filtering, and unreported truncation cannot be reconstructed.

File rules and output checks are not retroactive transcript redaction. Previously captured
content can still be present in history; device-wide history consent can expose
that content to the connected agent. Revoke agent sharing
and delete local history if that is not wanted. Service secrets entered into
the native vault are distinct from secrets that already appear in agent logs.

No ADR product analytics, remote telemetry endpoint, hosted database, or remote
management service is configured. User-approved broker requests and commands
can intentionally access the network. Security reviews are independently opt-in:
the selected local agent sends approved session evidence to its configured
provider. Automatic idle reviews require separate project and scheduling consent.

## Security review jobs

Only the owner API can change review settings, start/cancel jobs or connect
Claude usage reporting. Existing MCP and hook grants cannot start inference or
approve sharing. The hook-only usage endpoint accepts bounded quota metadata,
not credentials, prompts, settings, or arbitrary commands.

Jobs use the selected local CLI's current authentication; ADR never reads,
copies or rotates that CLI's credentials. No account or billing fallback is
configured. Configured API/managed access needs explicit owner permission.
Claude runs in a temporary working directory with safe mode, no ordinary tools,
strict empty MCP configuration and no session persistence. Codex uses an
ephemeral read-only thread, disables execution/browser/app/plugin/skill surfaces,
disables configured MCP servers, and denies client-handled requests. Unexpected
tool activity aborts the review. These restrictions must be revalidated against
harness versions; they are not a kernel boundary against same-user tampering.

Only bounded, credential-checked evidence enters the review prompt. Captures
remain unchanged. Reports are untrusted text, not commands: their schema and
message citations are checked, credential-bearing results withheld, and no
remediation runs automatically. Incomplete input coverage is explicit.

Token/cost reservations are persisted before dispatch. Concurrent reviews are
not admitted, repeated request IDs are reconciled, and interrupted/uncertain
jobs retain their reservation. CLI-reported usage drives stopping and accounting;
provider requests already in flight can exceed a stop threshold. Claude's
reported cost is not necessarily an amount billed to a subscription account.
Codex does not report a guaranteed dollar cost, so it has token/time admission
limits only. See [Security reviews](SECURITY_REVIEWS.md).
