# Protection connections

Protection hooks and MCP connections serve different purposes:

| Connection | Purpose | Depends on |
| --- | --- | --- |
| Protection hook/plugin | Check file operations and supported tool outputs | Installed integration, enabled rules, and a harness that has loaded/trusted it |
| ADR Context (MCP) | Search captured conversations across agents on this endpoint | Device-context consent during ADR agent setup and a running ADR service |
| Vault MCP | Use selected credentials without returning their values | Native encrypted-local-vault host and an explicit credential access grant |
| Vault commands in the ADR plugin | Run Bash/code with saved environment variables and filtered results | One-time ADR integration consent and the native host; no per-key or per-project setup |
| Prompt guard | Stop recognized credentials before prompt submission | Updated/trusted Claude Code or Codex UserPromptSubmit hook and running ADR service |

The same pre-tool adapters also support [known-malicious artifact
protection](THREAT_PROTECTION.md). Its local feed check is independent of file
rules and covers only the documented exact-identity operations. A normal ADR
MCP exemption does not bypass it; vault commands are checked within the runner.
Hooks reread/recheck the policy in the calling agent's context after positive
native approval, so a changed feed cannot be overridden by a stale approval.

Installing or updating the app does not install or trust any agent integration.
Use **Setup & settings → Protection → Connect installed agents** or the [agent integration command](AGENT_INTEGRATION.md),
then restart the agent. Native plugins contain both the hooks below and
ADR Context and vault commands through one MCP connection. A
configuration file alone is not proof that a running session loaded the hook:
ADR shows the last received hook report separately.

## Adapters

| Agent | Configuration | Before the tool | After the tool |
| --- | --- | --- | --- |
| [Claude Code](https://code.claude.com/docs/en/hooks) | `~/.claude/settings.json` | Native PreToolUse deny/ask | PostToolUse `updatedToolOutput` replaces a flagged result |
| [Codex](https://learn.chatgpt.com/docs/hooks) | `$CODEX_HOME/hooks.json`, default `~/.codex/hooks.json` | PreToolUse deny; ADR native dialog resolves Ask first | PostToolUse `decision: block` withholds the result |
| [opencode V1](https://opencode.ai/docs/plugins/), [V2](https://opencode.ai/v2/docs/build/plugins/) | `$XDG_CONFIG_HOME/opencode/plugins/adr-desktop.js`, default `~/.config/opencode/plugins/adr-desktop.js` | `tool.execute.before` / `execute.before` refuses a blocked operation | Replaces the full output/result, including metadata and attachments |
| [GitHub Copilot CLI](https://docs.github.com/en/copilot/reference/hooks-configuration) | `~/.copilot/hooks/adr-desktop.json` | preToolUse deny; ADR native dialog resolves Ask first | Not installed in this preview. Current Copilot contracts expose output transformation; ADR has not yet implemented or validated that integration. |

The table's user-hook paths remain supported for older direct integrations.
New native plugins package their hook definitions under `hooks/hooks.json`;
the client plugin manager owns registration/cache placement.

The opencode adapter exports both `server` and `setup` interfaces for the
documented OpenCode 1.18.29+ compatibility path and V2. V2 resolves the actual
session location rather than assuming the plugin instance's directory.
Agent-version, trust, or managed-policy restrictions can prevent hook execution;
ADR does not bypass those restrictions. Native Windows installation remains
unavailable in this preview.

Existing hook entries are preserved. Claude/Codex installation and removal
touch only ADR's pre/post/prompt entries. The opencode plugin uses a profile-bound
receipt; an existing foreign or edited file is not overwritten or removed.
Disconnect keeps a recoverable copy of ADR's plugin.

## Credential detection

Checks recognize common GitHub tokens, AWS access-key identifiers and
secret-key assignments, Google API/OAuth tokens, service-account markers,
and private-key headers. These are possible-credential findings, not remote
validation that a credential is active.

Direct file-tool checks examine bounded regular files before execution.
Supported post-tool adapters scan the returned content and substitute a
fixed, value-free vault instruction when a pattern matches. They do not send
the matched secret to the UI, audit stream, MCP, or a cloud scanning service.
This is model-result withholding, not deletion of the agent's own tool-event
logs. A harness can retain the original output locally before the hook
substitutes its response. Sensor capture remains unredacted. The model-bound
Context response is checked separately and withheld if it contains recognized
or saved values, exceeds the bounded check, or cannot be checked.
No automatic credential import, source-file deletion, or token rotation occurs.
Updated Claude Code/Codex packages also install `UserPromptSubmit`. Recognized
key formats, explicit password assignments and known saved values block that
submission. The user registers a value in the UI if needed, replaces it with
`$VARIABLE`, and resubmits. No automatic vault import or automatic resubmission
occurs. Other harnesses do not yet have ADR prompt blocking.

Known saved environment values are also checked in supported post-tool paths.
Recognizable shell references to saved variables direct the agent to
`adr_run_command`, already part of the same plugin; ordinary shell tools never gain the values merely by naming
them. Scripts whose variable use is not visible in the command line need an
explicit runner call. See [credential usage](CREDENTIALS.md).

Detection does not imply a provider-specific adapter. The API-only broker
supports bearer/API-key/Basic-auth GETs. The separate environment runner can
invoke CLIs or code using stored text variables; a dedicated SSH-agent or
credential-file adapter is not included.

Patterns cannot catch every credential, encoding, image, or indirect access.
Pre-read checks are subject to filesystem races; a post-tool check cannot undo
a completed tool's side effects. This is a cooperative control, not an OS sandbox.
Pausing file protection pauses its regular-file pattern checks. The prompt
guard and known saved-value output checks are separate; ADR's own control
files remain guarded.

## Owner decisions

File rules check supported direct file operations, recursive searches, and
literal file operands in simple `cat`, `head`, and `tail` commands. The bounded
shell recognizer supports common display/count flags, quoted filenames, the
tool's working directory, and one standard `sh`/`bash`/`zsh`/`dash` `-c` or
`-lc` wrapper. It does not interpret pipelines, compound commands,
substitutions, redirects, scripts, or arbitrary executables. Those retain the
chosen unclassified-command behavior.

File rules do not enable blanket command approvals. **Advanced: command approvals** offers
**Off (default)**, **Ask each time**, and **Block** for shell execution and
unrecognized tools. Known non-file coordination tools do not prompt. Turning
strict review off does not disable matching file rules, supported credential
checks, or the agent's own permissions.
An explicit command **Block** remains stronger than a file **Ask** rule.

Arbitrary commands and third-party tools are not a filesystem sandbox: they can
access files indirectly without supplying a path that ADR can check. Use strict
review or an OS sandbox where that coverage is required; an unprotected working
directory alone never proves which files a command will access.

Older previews' implicit Ask behavior migrates to Off. An explicitly saved Block
choice is preserved, as are file rules and subsequent explicit review choices.
App startup updates an already managed guardian to the current protocol; it does
not install, trust, enable, or re-enable any agent integration.

Claude's native Ask first remains native. Other adapters use a bounded ADR
dialog for an operation requiring approval; the complete bounded request is
shown, and **Deny** is the default. A missing app, an expired dialog, or a
full queue does not produce an allow. Up to eight requests, including the active
dialog, wait in FIFO order. Queue time counts toward each request's 90-second
deadline. Policy is checked again before showing a dialog and after the owner's
answer. Expired requests cannot become late approvals or stale popups.

The native guardian preserves closed, content-free failure reasons: protected
path, strict execution policy, owner denial, expiry, queue capacity, unavailable
app/policy, invalid request, and safety-check timeout. It never inserts raw tool
arguments or a free-form backend error into a harness response.

Vault permission is separate: users may explicitly authorize matching GETs
automatically when granting a connection access to selected accounts. The
grant cannot change the stored destination or obtain a vault-export operation.
Other agent-native MCP trust/approval settings can still apply.
