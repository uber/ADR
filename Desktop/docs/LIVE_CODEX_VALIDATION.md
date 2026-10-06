# Live Codex integration check

Executed on October 2, 2026 with Codex CLI 0.159.2 on macOS. These were
model-driven sessions against an isolated ADR service, not only mocked plugin
commands. The service had two synthetic conversations, disposable files, no
real credentials, and no device capture or inventory collection.

## What was verified

- Codex's native marketplace-add and plugin-add commands accepted the generated
  local bundle. Its MCP server connected and exposed the four ADR Context tools.
- Codex initially marked the two fixture hooks as new and skipped them until
  individually reviewed and trusted in `/hooks`. Updating their definitions
  required review again. No blanket hook-trust bypass was used.
- The agent searched for a fixture-only marker, found both the seeded Claude
  and opencode conversations, and fetched both with `adr_get_conversation`.
  Their expected synthetic answers appeared in the final response.
- A normal file read completed. A literal read of a protected file was denied
  by the actual pre-tool hook and did not produce the blocked file's canary.
- A revoked test Context permission returned HTTP 401, including when the
  native plugin cache still held its old access-file path. After reinstalling
  the test plugin with the new grant, Context calls succeeded again.
- With the fixture daemon stopped, the agent could still read the public file;
  the protected read was denied from cached policy, the Ask-protected read was
  denied because no approval dialog was available, and `adr_status` reported
  that ADR was unavailable.
- An unprotected file containing a deliberately invalid, credential-shaped
  test value exercised the actual post-tool hook. ADR recorded a value-free
  GitHub-token finding and deny decision. The agent reported that it received
  the protection message instead of the file contents.
- Cleanup revoked every fixture permission. Native plugin-remove and
  marketplace-remove commands succeeded; readback confirmed that the test
  entries and plugin cache were absent and the pre-existing ADR integration
  remained enabled.

The initial live run exposed a real omission: shell `cat` operands were not
being checked against file rules. The fix adds bounded literal-read recognition
for `cat`, `head`, and `tail`. Regression tests also cover working directories,
quotes, symlinks, flags, BSD option parsing, literal tildes, comments, and the
priority of an explicit command Block over a file Ask rule.

## What the output check does—and does not—prove

The post-tool evidence consists of the native hook decision and the resulting
agent response. Provider-wire payloads were not inspected.

Codex's raw `exec --json` command-execution events still contained the original
synthetic value. Withholding the model-facing result is **not** retroactive
scrubbing of native tool logs or session history. ADR does not redact Sensor
capture, so explicitly shared Context history can also expose values retained
in those source logs.

The credential broker is different: it uses a Keychain-held value in the native
request path instead of giving that value to an ordinary agent tool. This test
does not claim automatic vault import, pasted-prompt rewriting, arbitrary
credential-provider support, or protection from every possible local program.

## Repeat with a disposable profile

From `Desktop/`, start the fixture:

```sh
uv run --no-sync python scripts/codex_live_fixture.py --install
```

`--install` explicitly uses Codex's native plugin manager for a uniquely named
test marketplace. Without it, the script only prepares the local package and
prints transient launch arguments. `--codex-command` accepts an installed
launcher when `codex` is not directly on the command path.

Use the printed command in a second terminal. Review only the fixture plugin's
pre/post hooks; leave other security hooks and authentication settings alone.
The launch overrides isolate any other ADR profile only for the test invocation.
Keep other conversations out of this disposable session.

Ask the agent to:

1. Search `ADR_SYNTHETIC_CONTEXT_NEEDLE`, then read the two matching conversations.
2. Run separate `cat public.txt` and `cat protected.txt` calls. The first should
   succeed and the second should be denied, without alternate access attempts.
3. Read `synthetic-token.txt` once. The model-facing result should be replaced
   by an ADR message; do not print or share raw native execution logs.

Stop the fixture with Ctrl-C. Issued permissions are revoked before native
uninstall is attempted; the script removes only its own plugin and marketplace.
If cleanup fails, it prints the exact test identifiers that require attention.
The private synthetic project/state remain local for inspection.

This does not replace the offline-hook unit tests, native-vault tests, or
agent-version compatibility checks. Claude, opencode, Copilot, and native
Windows/Linux execution were not live-validated by this Codex run.
