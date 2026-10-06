# Security reviews

Security reviews use your installed Claude Code or Codex CLI to analyze
captured sessions and return findings linked to the original conversation.
This is a local job runner, not an ADR-hosted inference service.

## Set up

1. Install and sign in to the agent CLI you want to use.
2. Open **Security reviews → Review settings**. Choose the agent and optionally
   its model. Leaving the model blank uses the agent's configured default.
3. Set token, job-count and runtime limits. Explicitly allow configured API or
   managed access if you want to use it; the default does not authorize it.
4. Approve sending selected session evidence through that agent. This can
   include conversations captured from other agents. The CLI's configured
   model provider receives the evidence.
5. Choose **Review now**, select a session and confirm.

ADR does not read `auth.json`, extract Claude credentials, change accounts,
purchase credits, redeem rate-limit resets or silently switch billing modes.
If sign-in fails, fix it in the selected CLI. A configured enterprise gateway
remains that gateway; running locally does not make inference local.
The API/managed-access toggle is not a switch for a provider's extra-usage
setting. Your CLI's existing billing and overage choices still apply, including
on a subscription. ADR cannot disable them or guarantee subscription-only billing.

## Usage and limits

The token budget is specific to **ADR security review jobs**, across both
providers. It does not restrict your ordinary interactive agent sessions.

- **Tokens per review** are reserved before dispatch. The worker stops when
  reported usage reaches the threshold.
- **Review tokens per 24 hours** use a rolling ledger, not a calendar-day reset.
  Unknown, cancelled and interrupted work retains its reserved amount; successful
  usage-bearing results release unused reservation. Reported overruns count in full.
- **Reviews per 24 hours** and **seconds per review** independently bound work.
- **Claude cost limits** are passed to `claude -p --max-budget-usd`, with a
  rolling budget checked before each job. The CLI's USD-equivalent model cost
  is not necessarily an amount billed to a subscription.
- **Codex has token/time controls, not a claimed dollar cap.** No missing cost
  field is converted into a claim that a review was free.

These are admission and stop thresholds. A model response already in flight
can exceed a token or cost limit; stopping a local process does not refund
consumed capacity. Use provider billing controls as well if a strict spending
ceiling is required. ADR never automatically retries an uncertain model request.
On macOS/Linux, a separate lifetime watchdog bounds each CLI process and stops
it when the app's lifetime pipe closes, including after a core crash. Native
Windows worker supervision is not validated in this preview.

## Review while idle

This is off by default. Choose captured projects and an idle duration before
enabling it. The native macOS host reports device idle time; recent observed
agent-hook activity also prevents dispatch. Automatic mode waits if this signal
is unavailable. Manual reviews do not require the device to be idle.

Only one review runs at a time. New activity interrupts automatic work and
stops further dispatch. The queue excludes unchanged snapshots already attempted
and recorded review-run identities. A failed job requires an explicit retry;
it is not repeatedly charged in the background.

Two modes are available:

- **Use my review budget:** may run when provider quota is unknown, within the
  review-specific limits above. A reported provider limit stops work.
- **Use spare subscription capacity:** requires fresh, complete quota windows,
  a reserve for interactive use, a safety margin and a reset within the selected
  horizon. Short-window headroom does not override an exhausted weekly window.

Codex uses its documented
[`account/rateLimits/read`](https://developers.openai.com/codex/app-server)
interface, including multi-bucket responses. Unsupported quota retrieval is
shown as unknown. Observations expire after five minutes. The read does not
start an inference turn.

Claude can emit partial rate-limit observations during a
[`claude -p` run](https://code.claude.com/docs/en/headless).
To observe both subscription windows, open **Agent usage and capacity → Connect
Claude usage**. ADR wraps the existing status-line command, preserves its
displayed output, and forwards only the documented
[usage percentages and reset times](https://code.claude.com/docs/en/statusline)
to the local app. Restart Claude, then use it normally to obtain an observation.
Disconnect restores the previous command only if ADR's bridge is still present;
edits made outside ADR are not overwritten. Automatic status-line setup is
currently implemented for macOS/Linux, not native Windows.

**Refresh agent usage** checks Claude sign-in without spending tokens to probe
quota. It cannot manufacture a missing status-line observation.
Claude's last full observation can precede the idle period. Spare-capacity mode
can use it for up to 30 minutes as an estimate, with the age shown in the UI.
Repeated values do not extend freshness, and an older status line cannot reduce
newer observed usage within the same window. Partial review-process observations
can update a recent full snapshot but cannot make the older window fresh.

After enough recent observations for the same account/reset window exist, the
scheduler reserves projected consumption at the upper recent observed rate.
Before then it displays that it is learning and uses the explicit reserve and
safety margin. This is a conservative estimate, not a prediction that you will
definitely remain idle. Other-device use and provider changes can invalidate it.

## Reports and privacy

The first implementation performs a bounded, single-pass review for supported
evidence of prompt injection, exfiltration, credential exposure, unauthorized
or destructive actions, and malicious artifacts. It is not the entire original
ADR benchmark pipeline and carries no benchmark-accuracy claim.

Reports contain exact citations to included messages, severity, confidence and
suggested next steps. **View in session** opens the captured transcript.
New session activity marks the old report stale.
Deleting captured history also deletes copied review findings/evidence and stops
active reviews. Minimal usage receipts remain so history deletion cannot erase
spending from the rolling budget; data already sent to a provider cannot be recalled.

Large messages may not fit a review input budget. They are omitted from that
job, not truncated in the Sensor capture; the report shows included/total
messages and partial coverage. A partial, failed or interrupted review is
never labeled a clean whole-session result. An empty findings list is not
a safety certificate.

Transcripts are untrusted input. Claude uses safe mode, disables ordinary tools
and MCP servers, and does not persist the review session. Codex uses an
ephemeral read-only thread with execution, browser, app/plugin and skill
surfaces disabled. Unexpected tool/client requests abort the review.
Current harness compatibility and these restrictions need live validation on
each release; unsupported configurations are not bypassed.

Evidence is checked for recognized and saved credentials before dispatch.
Uncheckable or credential-bearing inputs are withheld. This does not rewrite
captures and is not a guarantee of identifying every possible secret format.
The result is also validated and credential-checked. Reports stay in the
local database. No repository changes, package installs, credential-backed
commands, external reports or PRs are created by the reviewer.

## Development verification

```sh
PYTHONPATH=.:../Discovery:../Sensor uv run pytest -q \
  tests/test_review_process.py tests/test_review_quota.py tests/test_security_reviews.py \
  tests/test_review_usage.py
PYTHONPATH=.:../Discovery:../Sensor uv run python scripts/reviews_ui_qa.py
```

The fixtures use subprocesses speaking the real CLI protocol shapes and
synthetic sessions. They do not use account credentials or call a model.
Native type-checks validate the macOS idle adapter; they do not substitute
for end-to-end installed-agent testing.
