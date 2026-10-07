# ADR agent integration

**ADR Context is an agent capability, not a separate desktop destination.**
Its MCP tools search captured conversations across agents and projects on
the current endpoint. A dedicated human-facing Context UI is P2.

## P0: one ADR plugin for installed agents

The ADR integration combines:

- Protection hooks/plugin callbacks for file decisions and supported
  credential-output checks.
- UserPromptSubmit checks in updated Claude Code/Codex packages, blocking
  recognized pasted credentials and directing the user to the local vault UI.
- A single `adr` MCP server with conversation search and credential-backed
  command execution. History uses the local captured-session database and
  full-text index; commands use the native host and encrypted local vault.
- A short usage guide: use saved `$VARIABLE` names and run credential-dependent
  programs through `adr_run_command`. Local programs receive actual values;
  the model receives filtered results, never a raw-value retrieval tool.

The existing Sensor collection path remains the source of conversation data.
MCP and the existing Sessions view use the same backend search service. A
future Context UI will be another client of that service, not a separate
collection or search implementation.

## Connect

Keep ADR running and choose **Setup & settings → Protection → Connect installed agents**.
The top bar lists agents with configured hooks and links to this shared setup;
it does not claim that all hooks are loaded or every operation is protected.
Detailed connection status stays in setup, not on individual protection pages.
Local capture is independent and does not need an agent connection. The equivalent CLI is:

```sh
adr-desktop connect all --allow-agent-access
```

For a bundled app, use its `Contents/Resources/core/ADRCore` executable in
place of `adr-desktop`. The macOS app asks for native owner confirmation.
Headless development uses its existing private owner capability.

Setup covers all installed supported CLIs in one action. It authorizes searching
captured conversations across the device and using every saved environment
credential, including future additions, in local commands. It does not authorize
changing ADR policies. There is no per-project setup or per-credential selection.
File rules and explicit command-approval settings still apply.

The result reports configured, missing, and failed agents separately. Setup is
safe to repeat; it reuses existing active integration capabilities. After
installing another supported agent, run the same action again. Native trust
prompts and managed restrictions are not bypassed. A fresh agent session is
needed to load the new MCP tools.

No plugin or wider permission is enabled just by installing a new app build.
Old `--allow-device-context` setup for a single agent remains read-only.

## Packaging

- Claude Code: a local native plugin with `.claude-plugin/plugin.json`,
  `hooks/hooks.json`, and `.mcp.json`.
- Codex: a local native plugin with `.codex-plugin/plugin.json`,
  `hooks/hooks.json`, and `.mcp.json`.
- GitHub Copilot CLI: a local plugin with `plugin.json`, its pre-tool hooks,
  and `.mcp.json`.
- opencode: the local plugin registers protection callbacks and `adr`, using
  the V1 configuration hook or V2 MCP registry transform.

Claude/Codex/Copilot installation uses their own plugin managers and a
device-local catalog. No public marketplace is published. Generated bundles
are bound to one ADR profile and are not redistributable artifacts: they
contain local paths to capability files, never the bearer tokens themselves.
The open-source source code generates fresh bundles on each device.

An already-unified integration update reuses its capability rather than creating
duplicate grants. Upgrading a Context-only installation issues a new capability,
then revokes the old one on success. Failure revokes the new capability and
preserves the previous read-only scope for recovery. An existing read-only token
is never upgraded in place. Successfully installing the native plugin removes
older direct ADR hook entries to avoid duplicate callbacks. Other hook and
plugin entries are not removed.

## Agent tools

| Tool | Purpose |
| --- | --- |
| `adr_search_conversations` | Find matching conversations by keywords in messages, tool inputs, and results; optionally filter by source agent |
| `adr_list_conversations` | List captured conversations within the approved device scope |
| `adr_get_conversation` | Read a conversation using its `conversation_id`, with message pagination |
| `adr_status` | Inspect the connection's scope and capture state |
| `adr_list_environment` | List saved environment-variable names, never values |
| `adr_run_command` | Run a command with saved values injected locally; provide the command and absolute working directory |

Example request to an agent:

> Find the conversation where I investigated the OAuth refresh bug, including
> work I did with other agents, and summarize what we tried.

Search returns conversation identifiers and excerpts. The agent can then
read the relevant conversation. Model-bound history is checked for recognized
and saved credentials; affected or uncheckable results are withheld without
changing the original stored record. Captured content is untrusted source data,
not instructions to execute.

Older `adr_history` connections and their tool names remain supported.
Existing project-scoped connections retain their original limits. They are
not automatically upgraded to device-wide access.

## Disconnect and recovery

```sh
adr-desktop disconnect --harness codex
```

History and credential use are revoked before removing the plugin. Saved values
and file rules remain in place. If the agent's plugin
manager is unavailable, the permission remains revoked and setup is marked
for repair; ADR does not claim the plugin was removed. A failed fresh install
revokes its newly issued permission. Review a timed-out native plugin operation
before retrying.

Native installation is subject to the agent's version, trust settings, and
managed policies. A configured bundle is not proof that an already-running
session loaded it. See [hook support](HOOKS.md) for enforcement limits.
