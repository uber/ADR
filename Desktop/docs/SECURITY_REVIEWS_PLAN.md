# Security reviews: useful security work with spare agent capacity

Status: initial local-CLI review implementation is in the developer preview;
automatic operation remains off by default. See [setup and current behavior](SECURITY_REVIEWS.md).
Research checked October 6, 2026. The initial implementation uses bounded
single-pass session reviews; full two-stage detection and patch preparation
remain follow-up work.

## What the person gets

ADR reviews captured agent sessions while the person is not using their agent,
then presents a short, evidence-linked inbox: what looks concerning, why it
matters, and what can be done about it. Optional repository improvements come
later as reviewable patches, not unrequested changes to the working tree.

The UI name is **Security reviews**, with **Review while idle** as an optional
mode. Keep this separate from **Malicious artifacts**, which matches known-bad
skill, MCP, package and file identities before supported operations.

Do not promise "free tokens" or aim to exhaust a subscription. The objective is
useful completed security work without crowding out the person's next task.
Stop when the queue is empty, even when capacity remains.

## What providers actually expose

### Codex: first integration candidate

The official [app-server API](https://developers.openai.com/codex/app-server)
provides `account/rateLimits/read` and `account/rateLimits/updated`, including
`usedPercent`, `windowDurationMins` and `resetsAt`. Use the multi-bucket
`rateLimitsByLimitId` when available; do not inspect only the legacy first bucket.
Account token-activity summaries are separate from remaining quota.

The documented [non-interactive CLI](https://developers.openai.com/codex/noninteractive)
supports scheduled work, structured output and existing CLI authentication.
For a distributed application, evaluate the official
[Sign in with ChatGPT integration](https://developers.openai.com/siwc/token-sharing-open-source)
and its registration, account and preview restrictions rather than treating
private CLI credentials as a generic API key.

The documented integration explicitly supports eligible ChatGPT-plan requests
from open-source and locally hosted applications. This offers a consumer-facing
sign-in flow without asking the person to construct an API endpoint. Verify
quota visibility for that exact authentication mode: limits available to a
normally signed-in Codex process are not automatically available to an app-server
using a custom Responses provider. Unsupported quota retrieval keeps automatic
spare-capacity mode unavailable, even if an on-demand review can run.

Use supported provider-owned sign-in. ADR must not read or copy `auth.json`,
intercept OAuth traffic, mint hidden credentials, buy additional credits, redeem
earned resets, or fall back to API billing. Do not copy CI credential-seeding
examples into Desktop. Detect the actual selected account/provider: an installed
Codex binary alone does not establish a consumer ChatGPT subscription.

### Claude: user-directed local processes

Claude Code's [status-line interface](https://code.claude.com/docs/en/statusline)
can report five-hour and seven-day usage percentages and reset timestamps.
Missing fields mean unknown, not unused capacity. Preserve any existing
status-line configuration; no silent replacement just to obtain these signals.

The chosen implementation is a user-directed local job, analogous to a cron
invocation of `claude -p`, with the person's current CLI sign-in. ADR does not
extract subscription credentials, offer Claude account login, or route raw API
requests with another application's tokens. Normal provider/account terms and
limits still apply; implementing a local launcher is not a representation of
provider approval for every distribution model.

Custom endpoints remain a separate provider option with an explicit cost/data
disclosure and their own budget. They must not be described as spare subscription
capacity. Local models are another possible adapter, not proof that a remote
subscription is available.

## Scheduling without pretending to know the future

Track provider-reported quota, not a made-up conversion from transcript tokens
to a fixed subscription allowance. Short and long windows can constrain the
same task; a short-window reset does not replenish a weekly allowance.

For each applicable window, estimate:

```text
available background headroom
  = reported remaining percentage
  - capacity reserved for the user
  - estimated interactive usage before that window resets
  - uncertainty margin
```

This is a scheduling estimate, not a hard billing guarantee. Token counts,
model choice, cache behavior and quota percentages are different measurements.
Do not pretend that 10,000 tokens always consume a known percentage.

Start with a user-selected idle schedule and reserve. Once enough local history
exists, forecast from time-of-day/day-of-week activity and observed usage deltas
within matching account/model/quota windows. Require minimum sample counts,
retain an uncertainty range and exclude ADR's own jobs from the interactive-use
estimate. A cold start offers a manual review, not a confident forecast.

Before starting each small job:

- The owner has enabled the mode and chosen which projects/sources may be reviewed.
- The account/provider has a supported authorization path.
- Quota observations are fresh, account-bound and cover the selected model's
  applicable windows. Refresh around a reset; never infer a reset happened.
- Every applicable window has room for the estimated job plus the reserve.
- The device is idle and no observed interactive agent work is active.
- The job fits inside the remaining time, with room for cancellation and review.
- A daily job/runtime ceiling and a single-worker limit have not been reached.

Recent collector timestamps are not proof of device inactivity. Use a native
idle signal plus available agent activity, explain blind spots such as other
devices, and keep the reserve conservative. Recheck between chunks and stop
dispatching immediately when activity resumes. Interrupt an active job where
the harness supports it; already consumed usage cannot be refunded.

Stale/unknown quota, incompatible versions, account switches, provider errors,
rate limits or uncertain previous-run outcomes pause scheduling. Do not retry
model work blindly or switch providers behind the user's back.

## Review workflow

1. Queue new or changed, opted-in session snapshots. Key work by the retained
   session ID, snapshot digest, detector version and review scope. Exclude ADR
   review sessions by recorded run identity to avoid reviewing reviews forever.
2. Perform a bounded first-pass triage using a versioned public ADR threat
   taxonomy. Reuse the original detector's triage/deeper-review pattern, without
   embedding the benchmark's environment, credentials or synthetic tools in
   Desktop. Include periodic sampled deep reviews to measure triage misses.
3. Analyze candidate sessions with the selected agent. Supply only the approved
   evidence needed for this job, with stable message/tool references. Large
   sessions need explicit chunk coverage and context preservation, not silent
   truncation followed by a clean verdict.
4. Validate a structured report: category, severity, confidence, explanation,
   exact evidence references, suggested next step and coverage limitations.
   An absent or invented reference makes the finding unverified. Failed,
   interrupted and partial reviews are not "no issues found."
5. Store the report locally and link each finding to the session/transcript.
   Mark reports stale when the underlying session changes. Allow dismissal and
   false-positive feedback without modifying the captured evidence.

Captured transcripts and tool outputs are untrusted input and may contain prompt
injection. The review worker must not execute their instructions. Disable tools,
connectors and credential access through verified harness controls, and test
that they are actually unavailable; a read-only shell sandbox alone is not a
tool-free analysis environment. Keep provider auth within the provider's
supported process and do not pass vault values to the review model.

Reuse existing model-bound credential checks on outgoing evidence. Preserve the
original Sensor capture unchanged. If safe export is not possible, explain
which review could not proceed rather than claiming the session was clean.

Enabling a cloud-backed review sends the selected evidence to the selected
provider as part of agent use. Consent must name that destination and explain
cross-agent history sharing. ADR does not add an ADR-hosted or Uber-hosted relay.
A configured enterprise gateway must be identified as such, not labeled local
or consumer-subscription usage. No consent, no background model requests.

## A small UI, not a security operations console

The new page should contain:

- **Review now** for an explicit selected session or approved scope.
- **Review while idle**, off by default, with the agent, reserve and schedule
  summarized in one sentence. Account/usage setup appears only when needed.
- A factual state such as "Waiting for idle time", "Keeping capacity for you",
  "Usage information unavailable", or "Reviewing 1 of 4 sessions".
- A concise findings list with **View in session**, **Dismiss**, and, later,
  **Prepare a fix**. No automatic blocking based solely on model findings.

Put forecasts under "Why now?" with the observation time, reset times and
uncertainty. Never show fabricated utilization savings or remaining tokens.
Update the existing local-only product copy if/when remote reviews are enabled.
Artifact matching and ordinary history browsing remain local.

## Implementation sequence

**First: on-demand reviews with one supported provider.** Add the review-job
store, evidence export boundary, structured report validator, cancellable runner
and session-linked results. Use synthetic inputs for end-to-end development.
Prove tool isolation, privacy consent and actual account routing before testing
against any real captured session.

**Then: quota-aware idle scheduling.** Add account-bound quota observations,
native idle/activity signals, reserves, short/long-window checks, restart-safe
queue handling and a daily work ceiling. Start with explicit quiet hours.
Forecasting is an incremental improvement to this scheduler, not a prerequisite
for a useful first release.

**Later: proposed fixes.** Owners choose repositories and permissible work.
Generate patches in isolated worktrees, run bounded checks, and show changes for
review. Never silently modify the active checkout, install dependencies, use
saved credentials, open a PR or push commits.

Before enabling unattended operation, test quota reset boundaries, stale and
missing usage, weekly exhaustion with short-window headroom, account changes,
interactive activity returning mid-job, concurrent dispatch, crash/restart,
duplicate tasks, provider timeouts, prompt injection, secret-bearing evidence,
long-session coverage and invalid model output. Measure false positives, missed
findings, review completion, user-visible interruptions and consumed capacity;
do not import the benchmark's published accuracy as a Desktop guarantee.
