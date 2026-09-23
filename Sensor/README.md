# ADR Sensor

**Agentic Detection & Response (ADR) Sensor** - Security observability for AI coding agents.

ADR Sensor is a Python library that collects telemetry from AI coding agents to enable security monitoring, threat detection, and observability. It parses logs from multiple AI agent platforms and normalizes them into a unified schema for downstream analysis.

> **Paper:** [ADR: An Agentic Detection System for Enterprise Agentic AI Security](https://arxiv.org/abs/2605.17380)  
> **Code:** [github.com/uber/ADR](https://github.com/uber/ADR)

## Supported AI Agents


| Agent                      | Source key       | Log Format                          | Platform               |
| -------------------------- | ---------------- | ----------------------------------- | ---------------------- |
| **Claude Code**            | `claude`         | JSONL (`~/.claude/projects/`)       | macOS, Linux, Windows  |
| **Cursor IDE**             | `cursor`         | SQLite (`state.vscdb`)              | macOS, Linux, Windows  |
| **Cline (Claude Dev)**     | `cline`          | JSON task files                     | macOS, Linux, Windows  |
| **Claude Desktop**         | `claude_desktop` | JSONL audit logs                    | macOS, Windows         |
| **OpenAI Codex CLI**       | `codex`          | JSONL + SQLite path catalogs        | macOS, Linux, Windows  |
| **GitHub Copilot CLI**     | `copilot`        | JSONL (`~/.copilot/session-state/`) | macOS, Linux, Windows  |
| **DeepSeek Harness**       | `dsh`            | JSONL/Zstandard (`~/.dsh/sessions/`) | macOS, Linux, Windows  |
| **Warp Terminal**          | `warp`           | SQLite (`warp.sqlite`)              | macOS, Windows         |
| **opencode**               | `opencode`       | SQLite (`opencode.db`) or JSON tree | macOS, Linux           |
| **Gemini CLI**             | `gemini`         | JSONL journals + legacy JSON chats | macOS, Linux, Windows  |

### Claude Code

The `claude` source reads transcripts recursively under `~/.claude/projects/`,
including [subagent transcripts](https://code.claude.com/docs/en/sub-agents#resume-subagents)
under `<project>/<sessionId>/subagents/agent-<agentId>.jsonl` and nested workflow
directories. Main sessions keep the `claude_<sessionId>` identity; subagents use
`claude_<sessionId>_agent_<agentId>` and include `parent_session_id` and `agent_id`
in `session_context` so their exports do not overwrite the parent conversation.

String and text-block messages are retained, including user text accompanying
tool results. Results are matched by tool-call ID. Malformed records are skipped
without discarding surrounding messages. Complete JSON objects concatenated on
one physical line and NUL padding between objects are accepted; incomplete tails
are skipped without joining physical lines or repairing text inside a message.

Each event includes `raw_log_path`, a stable conversation-start `timestamp`, and
`session_context.last_event_at` and `event_count` for incremental updates. A file
without any valid timestamp uses its modification time. `--save-sessions` updates
the saved snapshot when a tool completes or a conversation resumes, even within
the same timestamp second. All recorded branches are retained in file order.

The default lookback is 14 days by file modification time. Existing limits still
apply: top-level tool argument strings and tool results are truncated at 1,000
characters; non-text content blocks and separately spilled tool-output files are
not imported. Contract tests use synthetic transcripts and do not launch Claude.

### Claude Desktop Agent Mode

The `claude_desktop` source covers Claude Desktop's local agent mode (released as
Claude Cowork), on both macOS and Windows. Two kinds of session are captured:

- **Interactive sessions** — `.../local-agent-mode-sessions/<user>/<org>/local_<uuid>/audit.jsonl`
- **Dispatch sessions** (delegated background agents) — `.../<user>/<org>/agent/local_ditto_<uuid>/audit.jsonl`

Both emit `source: "claude_desktop"`. Dispatch sessions get a distinct
`claude_desktop_dispatch_` session-id prefix and an `is_dispatch: true` flag in
`session_context`, so detection rules can treat unattended runs differently from
interactive ones. Interactive session ids are unchanged.

### OpenAI Codex CLI

The Codex parser reads JSONL rollout files from `$CODEX_HOME/sessions/`. It also
opens every `$CODEX_HOME/state_*.sqlite` catalog in read-only mode and supplements
filesystem discovery with rollout paths from compatible `threads` tables. A table
must have `id` and `rollout_path` columns; `updated_at` and `updated_at_ms` are
optional. Relative rollout paths are resolved from `CODEX_HOME`, and only existing
regular `.jsonl` files are accepted. Catalog and filesystem paths are deduplicated.

If `CODEX_HOME` is unset or empty, it defaults to `~/.codex`. Rollouts use a 14-day
lookback by default. Filtering uses the newer of the file modification time and any
valid catalog update timestamp, so a recently updated catalog entry can retain an
older file. Corrupt, locked, or incompatible catalogs are skipped without affecting
files found under `sessions/`; malformed timestamps fall back to file modification
time. Pass `max_age_days` to `CodexParser` or `AgentObserver` to customize the
lookback; values less than or equal to zero disable age filtering for `CodexParser`.

### GitHub Copilot CLI

The `copilot` source reads each GitHub Copilot CLI session's `events.jsonl` and
optional `workspace.yaml` and `vscode.metadata.json` files. Copilot CLI uses the
same home-relative configuration directory on every supported operating system;
it does not use `Library/Application Support` or `AppData` for session history:

| Operating system | Default session directory |
| ---------------- | ------------------------- |
| macOS            | `/Users/<user>/.copilot/session-state/` |
| Linux            | `/home/<user>/.copilot/session-state/` |
| Windows          | `%USERPROFILE%\.copilot\session-state\` (typically `C:\Users\<user>\.copilot\session-state\`) |

Set `COPILOT_HOME` for both Copilot CLI and ADR Sensor when the CLI configuration
directory has been moved; the Sensor then reads `$COPILOT_HOME/session-state/`.
Copilot CLI's legacy `--config-dir` option is deprecated in favor of this
environment variable. These locations and the override are defined by the
[Copilot CLI configuration directory reference](https://docs.github.com/copilot/reference/copilot-cli-reference/cli-config-dir-reference).

The parser applies a 14-day lookback using each `events.jsonl` modification time.
Use `--all-history` to include older sessions. This source covers GitHub Copilot
CLI session state only; it does not read the separate storage used by the VS Code
Copilot Chat extension.

### opencode

[opencode](https://github.com/sst/opencode) uses the XDG layout on every platform,
so its data directory is `~/.local/share/opencode` on both Linux and macOS
(`$XDG_DATA_HOME` and `$OPENCODE_DB` are honored when set). Both storage backends
are read:

- **SQLite** (current releases) — `opencode.db`, or `opencode-<channel>.db` on
  non-stable channels. Opened read-only so a running opencode process is never disturbed.
- **JSON file tree** (older releases) — a `storage/` directory of per-session,
  per-message and per-part JSON files, in both the project-scoped and legacy layouts.

MCP tools are namespaced by opencode as `<server>_<tool>`, so any tool that is not a
known built-in and contains an underscore is recorded as `tool_type: "mcp_tool"` with
its `server_name` populated.

### DeepSeek Harness

The `dsh` source reads current DeepSeek Harness v3 session logs from
`$DSH_HOME/sessions/`, or `~/.dsh/sessions/` when `DSH_HOME` is unset. DSH uses
Zstandard-compressed logs by default; uncompressed JSONL v3 logs are also
supported. When migrations leave several generations in one session directory,
the parser follows DSH and considers only the highest generation. A session is
ingested only when that generation is v3, so historical or future formats are
not silently interpreted with the wrong schema.

Tool arguments and results, PTC sub-dispatches, failure status, approvals,
provider/model context, sandbox mode, permission preset, typed message content,
and recorded token usage are normalized into the Sensor schema. Structured tool
result content, metadata, and compaction replacement provenance are retained in
`session_context`. Tool names do not carry a universal MCP server identity, so
the parser does not guess one.
The standard 14-day file lookback applies; use `--all-history` to include older
sessions. Storage and event behavior were
checked against DSH's pinned
[JSONL persistence contract](https://github.com/deepseek-ai/deepseek-harness/blob/c291e7961a515f6d7af9304e7fd1d257929aef26/packages/session/session-persistence-jsonl/README.md)
and [v3 event declarations](https://github.com/deepseek-ai/deepseek-harness/blob/c291e7961a515f6d7af9304e7fd1d257929aef26/packages/core/session/src/types.ts).

```bash
adr-sensor --source dsh
```


### Gemini CLI

The `gemini` source reads current `chats/**/*.jsonl` journals and legacy
`chats/*.json` conversation snapshots. It captures user/assistant text, tool
arguments and results, recorded status and approval requests, model and token
usage, and nested subagent sessions. Start timestamps remain stable when sessions
resume; `--save-sessions` refreshes changed snapshots in place.

| Host | Default scan root (per-user home) |
| ---- | -------------------------------- |
| macOS / Linux | `~/.gemini/tmp/` |
| Windows | `%USERPROFILE%\.gemini\tmp\` |
| macOS Seatbelt sandbox | `~/.cache/.gemini/tmp/` (also scanned on macOS) |

`GEMINI_CLI_HOME` overrides the **parent home directory**, so the path becomes
`$GEMINI_CLI_HOME/.gemini/tmp`, not `$GEMINI_CLI_HOME/tmp`. Project directories
can be hashes or readable identifiers. Project paths come from `.project_root`
or `projects.json`; a project hash alone is not a filesystem path. A custom
acquired root can be supplied through `GeminiParser(base_path=Path("/capture/tmp"))`.
WSL/container sessions belong to their own filesystem and home.

ADR consolidates repeated journal messages by ID, so tool progress updates do
not duplicate messages or token totals. Earlier activity survives rewind and
checkpoint records. `session_context.history_scope` is `all_recorded_branches`;
this is recorded activity, not a reconstruction of only the model's current
context. Source message metadata, typed content, tool IDs, and recorded thought
summaries remain in `session_context`. The parser adds no redaction or truncation;
upstream output limits and deleted files cannot be recovered. Unknown or malformed
records do not abort other sessions, and malformed-record counts are reported.

Only CLI chat records are covered. Prompt-only `logs.json`, editor chat storage,
shell history, unsaved sessions, and files outside these roots are not collected.
The default lookback is 14 days by file modification time; `--all-history`
includes older files. Explicit `mcp_`/qualified tool names identify MCP calls;
server attribution is left empty when the recorded name is ambiguous.

```bash
uv run adr-sensor --source gemini --no-save
uv run adr-sensor --source gemini --save-sessions --all-history
```

Contracts verified against upstream
[record types](https://github.com/google-gemini/gemini-cli/blob/9c1b0a610534d6f8120964cf2672c07807d8fc90/packages/core/src/services/chatRecordingTypes.ts),
[journal writer](https://github.com/google-gemini/gemini-cli/blob/9c1b0a610534d6f8120964cf2672c07807d8fc90/packages/core/src/services/chatRecordingService.ts),
[storage paths](https://github.com/google-gemini/gemini-cli/blob/9c1b0a610534d6f8120964cf2672c07807d8fc90/packages/core/src/config/storage.ts),
and [supported platforms](https://geminicli.com/docs/get-started/installation/).
Tests use synthetic records matching these contracts and run on all three hosts;
they do not require a Gemini account.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        AI Agent Logs                            │
│         Claude, Cursor, Cline, Codex, Copilot CLI, Warp         │
│       Claude Desktop, opencode, Gemini CLI, DeepSeek Harness      │
└───────────────────────────────┬─────────────────────────────────┘
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Source-Specific Parsers                      │
│                  (Each implements BaseParser)                   │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Unified Schema (AgentEvent)                   │
│      session_id │ timestamp │ chat_history │ tools │ model      │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    AgentObserver (Orchestrator)                 │
│              Ingest → Filter → Display → Export                 │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                 ┌────┴────┐
                 ▼         ▼
           JSON/JSONL   OTLP Logs
              Files        │
                           ▼
                    Collector / SIEM
```

## Quick Start

### Installation

Tagged releases are installed from [PyPI](https://pypi.org/project/adr-sensor/):

```bash
pip install adr-sensor
```

Install the optional OpenTelemetry dependencies when OTLP log export is needed:

```bash
pip install "adr-sensor[otel]"
```

Or install from source:

```bash
git clone https://github.com/uber/ADR
cd ADR/Sensor
pip install .
```

### CLI Usage

```bash
# Ingest from all supported agents
adr-sensor

# Ingest from a specific source
adr-sensor --source claude
adr-sensor --source cursor
adr-sensor --source codex
adr-sensor --source copilot
adr-sensor --source dsh
adr-sensor --source claude_desktop
adr-sensor --source opencode
adr-sensor --source gemini

# Save individual session files (incremental)
adr-sensor --save-sessions

# Export as JSONL
adr-sensor --output-format jsonl

# Include all history (not just last 2 weeks)
adr-sensor --all-history

# Custom output directory
adr-sensor --output-dir ./my-output

# Export the same records to an OTLP/HTTP logs endpoint
adr-sensor --otel-config ./opentelemetry-config.json

# Export to OTLP without also writing JSON files
adr-sensor --no-save --otel-config ./opentelemetry-config.json
```

Sources whose agent only runs on some operating systems are skipped automatically
on other platforms — `--source all` on Linux will not attempt `claude_desktop`, for example.

### Python API

```python
from adr_sensor import AgentObserver

# Create observer
observer = AgentObserver()

# Ingest from all sources
events, configs = observer.ingest_all()

# Or from a specific source
events, configs = observer.ingest_all(source_filter="claude")

# Display summary
observer.display_summary(events, configs)

# Save to file
observer.save_to_file(events, configs, output_format="json")

# Analyze events
for event in events:
    print(f"Source: {event.source}, Session: {event.session_id}")
    print(f"Messages: {len(event.chat_history)}")

    for msg in event.chat_history:
        if msg.tools:
            for tool in msg.tools:
                print(f"  Tool: {tool.tool_name} ({tool.tool_type})")
                print(f"  Args: {tool.arguments}")
```

### OpenTelemetry Logs Export

OpenTelemetry export is disabled by default. The Sensor only initializes an
OTLP exporter when `--otel-config` points to a JSON configuration file. Without
that argument, CLI and file-export behavior are unchanged and no OpenTelemetry
logs are sent.

Start from [`examples/opentelemetry-config.json`](examples/opentelemetry-config.json):

```json
{
  "endpoint": "http://localhost:4318/v1/logs",
  "service_name": "adr-sensor",
  "headers": {},
  "timeout_seconds": 10,
  "flush_timeout_seconds": 30
}
```

`endpoint` must be the complete OTLP/HTTP logs URL, including `/v1/logs` when
required by the receiver. `headers` can contain authentication headers. An
optional `certificate_file` names a PEM certificate bundle; relative paths are
resolved from the configuration file's directory.

Each `AgentEvent` is sent as an `adr.agent.session` OpenTelemetry LogRecord. Its
body is the complete dictionary returned by `AgentEvent.get_non_null_fields()`,
the same content written to JSON/JSONL today. The OpenTelemetry exporter applies
no redaction or field projection, so prompts, responses, tool arguments, tool
results, usernames, hostnames, and local paths can be transmitted. Any
normalization already performed by a source parser still applies.

System-configuration records are sent as `adr.system.configuration` logs on each
run. Sensor health logs are also sent on every run, even when all session snapshots
are already acknowledged. With `--save-sessions`, successful session delivery is tracked independently
of local session files. A failed export is retried on the next run, even when the
local JSON already exists. A session is skipped only when its complete normalized
payload was successfully exported to the same destination configuration. Changes
to tool results, destination settings, or configured authentication headers cause
a resend. The checkpoint also accounts for effective OTLP environment headers and
mTLS client certificate/key paths. It does not read credential files: after
changing certificate or key contents in place, remove the destination's checkpoint
to resend sessions. Dynamic HTTP credential-provider plugins
(`OTEL_PYTHON_EXPORTER_OTLP_HTTP_CREDENTIAL_PROVIDER` and its `LOGS` variant)
are unsupported and cause an explicit error; use configured headers or mTLS.

Delivery checkpoints are hidden `.adr-otel-delivery.<hash>.json` files in the
session output directory. They contain only hashes, including a destination hash
that accounts for authentication headers; they do not store raw URLs, credentials,
session identifiers, or payloads. Missing, unreadable, or corrupt checkpoints cause
sessions to be retried. The checkpoint is replaced atomically only after flush and
shutdown succeed; a checkpoint write failure exits with an error. `--no-save`
disables checkpoint reads and writes. Without `--save-sessions`, every run exports
all collected sessions.

The one-shot Sensor process drains bounded batches and reconciles submitted and
successfully exported counts before reporting success, so a full SDK queue cannot
silently drop records. HTTP success is also checked for an OTLP acknowledgement:
partial rejection or a malformed response fails delivery and leaves the affected
run unacknowledged. Resolve persistent collector rejection before rerunning: OTLP
does not identify individual rejected records, so retrying can resend accepted
records too. Export or checkpoint failures exit with a nonzero status.
Delivery is at least once: a collector may receive data before a timeout, process
interruption, or checkpoint write failure, so retries can duplicate records.
Checkpointing only covers sessions that are collected again on a later run; it is
not a persistent payload queue. Consumers can use `adr.event.uuid` and a full
payload digest to identify repeated snapshots, since a session UUID alone does not
necessarily change when tool results change.

Use an OpenTelemetry Collector when vendor-specific routing, transformation,
retry, or persistent queuing is needed.

### Sensor health and parser diagnostics

Every ingestion run writes a content-free summary for each attempted source,
including runs that produce no sessions. `diagnostics.jsonl` contains all summaries;
`error.log` contains only `partial` and `failed` summaries. Both live under
`--output-dir` (default `./output`), even when `--save-sessions` uses its separate
default cache directory or `--no-save` suppresses captured session files. Each log
rotates at 1 MiB with two backups. Use one active sensor process per output directory
to avoid concurrent rotation races. Diagnostic write failures produce a fixed stderr
warning and do not discard captured sessions.

The versioned `adr.sensor.health` schema contains timestamp, sensor version, source,
stage, status, fixed reason codes, and aggregate counts. For example:

```json
{"schema_version":1,"event":"adr.sensor.health","timestamp":"2026-01-01T00:00:00.000+00:00","sensor_version":"0.0.0","source":"claude","stage":"parse","status":"partial","suspected_schema_drift":false,"counts":{"events_returned":2,"events_emitted":2,"events_filtered":0},"reasons":{"record_decode_error":1}}
```

Statuses distinguish successful capture (`ok`), no meaningful output (`empty`),
absent input (`no_input`), usable output with observed errors (`partial`), and
errors without usable output (`failed`). Age filtering and an incomplete live
tail are expected skips, not errors. `suspected_schema_drift` is a triage hint for
explicitly unsupported record/content/schema shapes, not proof of an upstream
format change. Generic corruption is reported separately.

All ten parsers report observed recovery failures, but coverage is not exhaustive:
some optional metadata/timestamp fallbacks, unknown record kinds, and compressed
DSH tail recovery are not classified. Counts describe observed recovery operations,
not necessarily unique damaged records. A healthy summary does not prove complete
capture; a missing summary also cannot distinguish an idle endpoint from a sensor
that never ran. Schedule runs and monitor last-seen health externally.

With `--otel-config`, health is also sent as OTLP logs (`adr.event.type=sensor_health`),
including when there are no session records. Health errors use WARN severity;
expected skips use INFO. No OTLP exporter is created without that argument. A failed
export is recorded locally because a broken destination cannot receive its own alert.
`--fail-on-error` exits nonzero after preserving available capture when an observed
parse/save/diagnostic failure occurs; by default these partial failures are reported
without changing the existing continue-on-error behavior. OTLP failures remain nonzero.
When `--resource` is enabled, `resource.log` also marks partial runs unsuccessful.

New structured diagnostics never include prompts, tool arguments/results, paths,
session IDs, exception messages, or tracebacks. This is a separate operational
schema, **not redaction of captured telemetry**. Legacy console previews/errors and
older entries already present in `error.log` are not sanitized by this change.

## Output Schema

### AgentEvent

Each parsed session produces an `AgentEvent` with the following structure:

```json
{
  "uuid": "sha256-hash",
  "timestamp": "2025-06-15T10:30:00+00:00",
  "source": "claude",
  "session_id": "claude_abc123",
  "hostname": "my-laptop",
  "username": "developer",
  "model": "claude-sonnet-4-20250514",
  "project_path": "/home/user/my-project",
  "chat_history": [
    {
      "role": "user",
      "content": "Help me fix this bug",
      "tools": [],
      "sequence_id": "msg_0"
    },
    {
      "role": "assistant",
      "content": "Let me look at the code.",
      "tools": [
        {
          "tool_name": "read_file",
          "tool_type": "tool_use",
          "arguments": {"path": "main.py"},
          "result": "def hello(): ...",
          "status": "success"
        }
      ],
      "sequence_id": "msg_1"
    }
  ]
}
```

Tool arguments and results can contain source code, credentials, or other sensitive
content copied from the local environment. Treat sensor output as sensitive data and
review it before sharing.

### `session_context`

Parsers that can recover session-level configuration attach it under
`session_context`. This is the agent's own view of what it was allowed to do, which
is often more useful for detection than the conversation itself. Claude Desktop
agent mode populates the richest version:

```json
{
  "session_context": {
    "title": "Config review",
    "is_dispatch": true,
    "session_type": "dispatch",
    "cli_session_id": "cli-99",
    "memory_enabled": true,
    "skills_enabled": false,
    "plugins_enabled": true,
    "available_slash_commands": ["review", "deploy"],
    "init": {
      "tools": ["Bash", "Read"],
      "mcp_servers": [{"name": "github"}],
      "permission_mode": "acceptEdits",
      "model": "claude-sonnet-4",
      "claude_code_version": "2.1.0",
      "plugins": ["reviewer"],
      "skills": ["pdf"]
    }
  }
}
```

### `token_usage`

Parsers may attach normalized per-turn and cumulative token counters to an
`AgentEvent`. Only counters reported as nonnegative integers are included:

```json
{
  "token_usage": {
    "last_turn": {
      "input_tokens": 120,
      "cached_input_tokens": 80,
      "output_tokens": 30,
      "reasoning_output_tokens": 10,
      "total_tokens": 150
    },
    "cumulative": {
      "input_tokens": 420,
      "cached_input_tokens": 200,
      "cache_write_input_tokens": 40,
      "output_tokens": 90,
      "reasoning_output_tokens": 25,
      "total_tokens": 510
    },
    "model_context_window": 128000
  }
}
```

## Adding a New Parser

ADR Sensor is designed to be extensible. To add support for a new AI agent:

1. Create a new parser in `adr_sensor/parsers/`:

```python
from pathlib import Path

from adr_sensor.parsers.base_parser import BaseParser
from adr_sensor.schemas.agent_event_schema import AgentEvent, ChatMessage, ToolUsage


class MyAgentParser(BaseParser):
    def __init__(self, max_age_days: int = 14):
        self.base_path = Path.home() / ".my-agent/logs"
        self.max_age_days = max_age_days

    def parse_all(self) -> list[AgentEvent]:
        entries = []
        # Parse your agent's log files and convert them to AgentEvent objects
        return entries
```

2. Export it from `adr_sensor/parsers/__init__.py`, then register it in
   `adr_sensor/observer.py` by constructing it as `self.<source>_parser` and adding
   the source key to `AgentObserver.SOURCES`:

```python
class AgentObserver:
    SOURCES = (
        ...,
        ("my_agent", "My Agent"),
    )

    def __init__(self, ...):
        ...
        self.my_agent_parser = MyAgentParser()
```

`ingest_all()` walks `SOURCES` and looks the parser up as `self.<source>_parser`, so
no per-source branch is needed. If the agent only exists on some operating systems,
add it to `PLATFORM_RESTRICTED_SOURCES` and it will be skipped elsewhere. The CLI
builds its `--source` choices from `SOURCES`, so it picks the new agent up for free.

3. Add tests in `tests/`.

## Environment

### Runtime support

| | |
| --------------- | ------------------------------------------- |
| Python          | 3.9, 3.10, 3.11, 3.12, 3.13                 |
| Operating system| macOS, Linux, Windows                       |
| Dependencies    | `tabulate`, `zstandard`; OpenTelemetry is an optional `otel` extra |

Which sources yield data depends on the host OS and on which agents are installed;
see the platform column in [Supported AI Agents](#supported-ai-agents). Sources that
cannot run on the current platform are skipped rather than failing.

### Environment variables

| Variable          | Read by                    | Effect                                                            |
| ----------------- | -------------------------- | ----------------------------------------------------------------- |
| `CODEX_HOME`      | Codex parser               | Codex data root containing `sessions/` and optional `state_*.sqlite` catalogs (default `~/.codex`) |
| `COPILOT_HOME`    | Copilot parser             | Copilot CLI data root containing `session-state/` (default `~/.copilot`) |
| `GEMINI_CLI_HOME` | Gemini parser              | Parent home containing `.gemini/tmp/`; on macOS also `.cache/.gemini/tmp/` |
| `DSH_HOME`         | DeepSeek Harness parser    | Harness data root containing `sessions/` (default `~/.dsh`) |
| `XDG_CACHE_HOME`  | `AgentObserver`            | Base for `--save-sessions` output (`$XDG_CACHE_HOME/adr_sensor`, default `~/.cache/adr_sensor`) |
| `XDG_DATA_HOME`   | opencode parser            | Overrides the opencode data directory (default `~/.local/share/opencode`) |
| `OPENCODE_DB`     | opencode parser            | Overrides the opencode SQLite filename or path (`:memory:` is ignored) |
| `APPDATA`         | Cursor, Cline, Claude Desktop parsers | Windows roaming app-data root. Consulted first so redirected/roaming profiles resolve correctly (default `~/AppData/Roaming`) |
| `LOCALAPPDATA`    | Warp parser                | Windows local app-data root, same redirected-profile handling (default `~/AppData/Local`) |

Each source is isolated during ingestion. See
[Sensor health and parser diagnostics](#sensor-health-and-parser-diagnostics) for
structured logs, partial-failure exit behavior, and monitoring limitations.

## Security Use Cases

ADR Sensor enables detection of:

- **Suspicious tool usage** - Unusual MCP tools, unauthorized file access, credential exfiltration
- **Prompt injection** - Malicious content injected into agent conversations
- **Supply chain risks** - Malicious MCP server configurations, suspicious packages
- **Data exfiltration** - Sensitive data accessed or transmitted by agents
- **Anomalous behavior** - Activity outside normal patterns, burst tool usage

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run tests with coverage
pytest tests/ -v --cov=adr_sensor

# Lint
ruff check adr_sensor/
ruff format adr_sensor/
```

## Project Structure

```
adr-sensor/
├── adr_sensor/
│   ├── __init__.py          # Package exports
│   ├── cli.py               # CLI entry point
│   ├── observer.py          # AgentObserver orchestrator
│   ├── exporters/
│   │   ├── config.py        # OTLP/HTTP JSON configuration
│   │   └── opentelemetry.py # OpenTelemetry Logs exporter
│   ├── parsers/
│   │   ├── base_parser.py   # Abstract base class
│   │   ├── claude_parser.py
│   │   ├── cursor_parser.py
│   │   ├── cline_parser.py
│   │   ├── claude_desktop_parser.py
│   │   ├── codex_parser.py
│   │   ├── copilot_parser.py
│   │   ├── dsh_parser.py
│   │   ├── gemini_parser.py
│   │   ├── opencode_parser.py
│   │   └── warp_parser.py
│   ├── schemas/
│   │   ├── agent_event_schema.py    # AgentEvent, ChatMessage, ToolUsage
│   │   └── system_config_schema.py  # SystemConfiguration
│   └── utils/
│       ├── string_utils.py
│       └── timestamp_utils.py
├── tests/
├── examples/
│   └── opentelemetry-config.json
├── CONTRIBUTING.md
├── LICENSE
├── pyproject.toml
└── README.md
```

## License

Apache License 2.0. See the [Sensor license](https://github.com/uber/ADR/blob/main/Sensor/LICENSE) for details.

## Contributing

We welcome contributions! See the [Sensor contribution guide](https://github.com/uber/ADR/blob/main/Sensor/CONTRIBUTING.md) for guidelines.

Maintainers can publish tagged releases by following the [release guide](https://github.com/uber/ADR/blob/main/docs/RELEASING.md).

Especially welcome:

- New parsers for additional AI agents
- Detection rules and analysis patterns
- Documentation improvements
- Bug reports and fixes
