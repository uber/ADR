# Credentials as environment variables

Save a value in ADR, give it a variable name, and use it from any agent connected
through the ADR plugin. Local programs are allowed to receive the real credential.
The boundary is model submission: values should not be copied into prompts, tool
arguments, or returned results sent to an LLM provider.

This works with credentials you already have. There is no requirement to change
your accounts, issue different keys, or adopt a new authentication provider.

## Save a value

1. Open **Credential vault → Add credential**.
2. Enter a readable name and an **environment-variable name**. ADR suggests a
   name automatically; choose the name your program expects, such as
   `GH_TOKEN`, `MY_PASSWORD`, or `AWS_SECRET_ACCESS_KEY`.
3. Choose **Continue to secure window** and enter the actual value in the native
   ADR window. **Paste multiline value** accepts JSON, key text, or other
   multiline values.

Values are nonempty UTF-8 text, up to 16 KiB, without NUL characters. Process
control names such as `PATH`, `HOME`, `BASH_ENV`, `LD_*` and `DYLD_*` cannot be
used for credentials. The value must differ from its public label/variable name.

Secret entry goes into the native app's encrypted local vault. The web form and SQLite store
receive only the name, variable name, identifier, state and timestamps. There
is no raw-value retrieval API or plaintext headless fallback. Normal saves and
uses do not call Keychain and do not require recurring unlock prompts.

## Local storage and existing credentials

The native app keeps encrypted records and an automatically generated local key
inside the private ADR profile. Directories are owner-only and record/key files
use owner-only permissions. Authenticated encryption detects damaged or
substituted records. The key is stored on the same device: this is convenient
local storage, **not isolation from other code running as your OS user or theft
of the complete profile**.

For entries created by an earlier build, choose **Move to local vault**. ADR
copies the selected Keychain values inside the native host and verifies each
copy. macOS may require one final authorization for that read. Originals stay
in Keychain; migration never deletes them, changes aliases, or widens grants.
Failures for one entry do not discard successful copies.

If a save was interrupted, refresh storage. **Recover saved entry** verifies an
existing copy and reactivates the same ID without asking for the value again.
When no local copy exists, **Finish saving** or **Re-enter value** opens the
native value window for the same entry. ADR does not overwrite an existing copy
or generate a replacement key beside encrypted data.

Keep the local key and encrypted records together in backups. A missing key
cannot decrypt its old records. Corrupt, inaccessible, and busy storage have
different explanations in the UI; none silently falls back to Keychain.
Deleting a local entry does not revoke its upstream account/token or erase
retained Keychain originals and historical filesystem backups.

## One plugin for your installed agents

Choose **Connect installed agents** in Credential vault or File protection.
ADR detects the supported local CLIs and installs the same ADR integration for
Claude Code, Codex, opencode, and GitHub Copilot CLI in one action. Missing or
failed installations are reported separately; they are not shown as protected.
Restart the agents afterward and review their native plugin/hook trust prompts.

That one setup action includes history search, protection hooks, and automatic
use of all saved environment variables, including values added later. There are
no project, per-key, or separate vault-MCP forms. Saving a new value makes it
available immediately; there is no reconnect or per-use vault approval.

Your own file rules and optional command-approval policy still apply. The agent
supplies an absolute working directory for each command, so the same integration
works across projects. This is not an OS filesystem or network sandbox.

The upgrade replaces an existing plugin's history-only capability after a
successful installation. Previously issued read-only tokens are never widened
in place. Older manual vault/API-only connections keep their existing scopes.

The agent receives these tools:

| Tool | What it does |
| --- | --- |
| `adr_list_environment` | Lists all saved variable names and labels, never values |
| `adr_run_command` | Runs Bash with those variables and returns filtered output |
| `adr_status` | Shows the integration's capabilities |

The same MCP server also includes `adr_search_conversations`,
`adr_list_conversations`, and `adr_get_conversation`.

For example, ask:

> Run my Python program through ADR Vault using `$MY_PASSWORD`.

Inside `adr_run_command`, the variable works normally:

```bash
python3 app.py
```

```python
import os

password = os.environ["MY_PASSWORD"]
# Pass it to the client/library that needs it; do not print it.
```

Child programs inherit the supplied environment. JavaScript can use
`process.env.MY_PASSWORD`; Bash can use `$MY_PASSWORD`.

**Ordinary agent shell tools do not automatically inherit the vault.** Updated
hooks redirect recognizable uses of saved `$VARIABLE` names toward
`adr_run_command`. A script whose credential use is not visible in its command
line should be launched through that tool explicitly.

The plugin's bundled guide and tool instructions explain this routing to the
agent. Users do not need to copy a configuration or manage access-file paths.
`adr-desktop exec --access-file ...` remains available for older integrations.

## What happens during execution?

The Python core authorizes the connection, checks the working directory and file
policy, and passes credential identifiers to the native host. The native host
loads the saved local-vault values and starts `/bin/bash` with a command-local
environment. Shell startup files are not loaded. Values are not injected into
the full agent process or written to an `.env` file.

The native process captures stdout/stderr and filters literal and common
encoded forms of saved values **before** returning text to the harness.
Output protection includes other active environment/API credentials, while
injection remains limited to the requesting connection's permission.
Output is buffered, not streamed. Oversized or non-UTF-8 output is withheld;
truncation never returns a potentially secret-bearing prefix.

Commands are noninteractive, accept no stdin, have a default 30-second timeout
(maximum 60 seconds), and a combined 64 KiB output limit. Two executions may run
at once. Normal process-group cleanup runs on completion/timeout, and service
restart or app shutdown cancels active groups. Detached daemons are not a
supported way to retain credentials.
Up to 64 variables and 128 KiB of credential environment data can be supplied
to one native execution. An explicit file/command Ask rule may spend up to
80 seconds awaiting approval before its execution timeout starts.

The local execution audit stores status, exit code, and session identifiers when
available, **not commands, output, or credential values**. In **Recent credential
use**, a session ID links to its captured transcript under **Sessions**.
ADR matches the command's unique run receipt in an ADR tool result, not the
newest conversation, the connection name, or the working directory.

Updated Claude Code, Codex, and opencode post-tool hooks can report a session ID
before its log is captured. A reported ID alone is not enough to choose a
transcript: some harnesses report a parent session for subagent hooks. Links
appear after normal collection finds the matching tool result. Existing
captures are indexed too; originals and capture settings are unchanged.
Copied results in known forks/subagents resolve to their captured ancestor.
Missing or ambiguous matches stay unlinked. Older activity, stopped requests
without a receipt, and command-line use outside a captured agent session may
have no session ID. This activity does not prove which of the supplied variables
a program actually used.

Revocation stops new use and suppresses results from
revoked access. It cannot undo side effects of an already-started command.

This is compatibility with existing programs, not isolation from them.
An authorized program receives the raw value and may deliberately transform it,
write it to a file, fork a detached process, or transmit it. Output filtering
does not prevent every form of exfiltration or same-user process inspection.

## Pasting a credential into a prompt

Updated Claude Code and Codex integrations install a **UserPromptSubmit** check.
Update the integration from **File protection**, restart the agent, and complete
its hook-trust review. Merely rebuilding ADR does not install or trust new hooks.

The check looks for saved values, recognizable key formats, and explicit
password/key assignments. A match:

1. Blocks that submission.
2. Tells the user to open the vault and register the value if needed.
3. Asks them to replace it with `$VARIABLE` and submit again.

ADR does not automatically save a pasted value or resubmit the prompt. A
password with no recognizable format or context cannot always be distinguished
from ordinary text. Very short saved values require explicit credential context
or a whole-message match; ambiguity can cause missed detections or false positives.
Images, encoded attachments, clients without the hook, and unsupported hook
paths are not covered.

Only type/alias metadata is recorded in **Prompts stopped**. Submitted text
passes transiently through the local hook/core/native checker; it is not saved
in ADR's prompt-audit table. If checking cannot complete, the installed prompt
hook blocks rather than silently approving submission.

Saved environment values are also checked in supported post-tool paths. A
normal shell cannot obtain them just by echoing an alias; it must use the
authorized runner.

**Local history is a separate boundary.** The agent may retain the original
prompt or ordinary tool output locally even when submission/result delivery is
blocked. Sensor capture remains unredacted. Model-bound history responses are
checked separately and withheld if they contain a recognized or saved credential,
exceed the check's size bound, or cannot be checked. The local UI still shows
the original capture. This is not retroactive deletion or detection of every
unknown secret.

## Common credential formats

- **GitHub and other API tokens:** use the environment variable expected by the
  CLI or library.
- **AWS credentials:** save the access-key ID, secret key and optional session
  token under the standard variable names. They are available together in the
  command's environment. The invoked CLI/SDK handles its authentication protocol.
- **JSON credential documents:** save the JSON as text and let code read/parse
  that variable. A variable that expects a *file path* must not be given raw
  JSON. ADR does not yet create credential files automatically.
- **SSH/private-key text:** code can read it from an environment variable.
  Ordinary OpenSSH still expects a key file or signing agent; ADR does not yet
  provide a dedicated SSH-agent adapter.
- **Passwords:** programs can read the value from their environment. This is
  not browser autofill or an interactive-password/TTY adapter.

## Existing API-only credentials

The previous HTTPS broker remains available under **API-only credentials**.
It supports bearer tokens, header API keys, and Basic-auth passwords for
destination-bound GET requests. **Add API credential** retains its service URL,
header/username and path-scope form, including the GitHub preset.

Those entries and grants keep their original read-only permissions. They are
not silently converted into environment credentials or command-execution
permissions. Their tools remain `adr_list_credentials`, `adr_request_service`
and `adr_service_result`. They do not add AWS signing, service-account token
exchange, or general command execution to the HTTP broker.

See [hook support](HOOKS.md) and the [security model](SECURITY.md) for the
different boundaries of storage, execution, file checks and history sharing.
