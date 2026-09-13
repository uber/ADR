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
| **Warp Terminal**          | `warp`           | SQLite (`warp.sqlite`)              | macOS, Windows         |
| **opencode**               | `opencode`       | SQLite (`opencode.db`) or JSON tree | macOS, Linux           |
| **Pi coding agent**        | `pi`             | JSONL (`~/.pi/agent/sessions/`)     | macOS, Linux, Windows  |

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


### Pi coding agent

The `pi` source reads Pi's persisted session JSONL files, including legacy v1
linear sessions and v2/v3 tree-structured sessions. It captures conversations,
tool calls with full recorded arguments and results, tool failures, and user-run
shell commands. No content redaction or additional truncation is applied.

| Operating system | Default session directory |
| ---------------- | ------------------------- |
| macOS            | `/Users/<user>/.pi/agent/sessions/` |
| Linux            | `/home/<user>/.pi/agent/sessions/` |
| Windows          | `%USERPROFILE%\.pi\agent\sessions\` |

Pi supports native Windows with Git Bash by default; its optional PowerShell tool
does not change session storage. ADR Sensor only reads the JSONL and does not
need either shell. Session directories are searched recursively. Set
`PI_CODING_AGENT_DIR` for both processes if Pi's agent directory was moved, or
`PI_CODING_AGENT_SESSION_DIR` to override the entire sessions root. If Pi is
started with `--session-dir`, set the same root through
`PI_CODING_AGENT_SESSION_DIR` for ADR Sensor, or pass `base_path` to `PiParser`.
An explicit parser `base_path` takes precedence over environment variables.

The export is a forensic history of **all branches recorded in the file**, not
just the active model context. Tool results are matched to calls on their own
ancestor path, so reused call IDs on sibling branches are not mixed. If several
results refer to a shared ancestor call, its first result stays on the invocation
and additional results appear as `tool` messages, with `tool_call_entry_id` in
their metadata. Orphan results are preserved without inventing invocations.
User shell commands have role `user`, not `assistant`.

`session_context.entries` retains entry IDs/parents, typed content (including
recorded thinking and images), provider/model details, stop reasons, full tool
result details, extension entries, labels, branch summaries, and compactions.
`token_usage.cumulative` sums recorded assistant, nested-tool, compaction, and
branch-summary usage. Raw usage and cost records remain in entry metadata.
Custom extension tools are reported as function calls: the session format does
not establish a universal MCP server identity, so the parser does not guess one.

The default lookback is 14 days by file modification time; `--all-history`
disables it. Resumed sessions update existing `--save-sessions` exports rather
than producing duplicate files. Malformed JSONL rows are skipped and counted;
unsupported future session versions are skipped explicitly. There is no capture
for `--no-session`/in-memory runs, deleted files, or content Pi itself never wrote.
Pi can truncate shell output before persistence; the parser preserves its
`truncated`/`fullOutputPath` metadata but does not follow external output files.
This source does not collect global settings, credentials, or a tool inventory.

Storage, format, and platform behavior were checked against Pi's
[session-format reference](https://github.com/earendil-works/pi/blob/71dca871bc80b6bc97be37f0ca3189399d651fff/packages/coding-agent/docs/session-format.md),
[directory configuration](https://github.com/earendil-works/pi/blob/71dca871bc80b6bc97be37f0ca3189399d651fff/packages/coding-agent/src/config.ts),
[session manager](https://github.com/earendil-works/pi/blob/71dca871bc80b6bc97be37f0ca3189399d651fff/packages/coding-agent/src/core/session-manager.ts),
and [Windows guide](https://github.com/earendil-works/pi/blob/71dca871bc80b6bc97be37f0ca3189399d651fff/packages/coding-agent/docs/windows.md).
CI exercises contract fixtures on native macOS, Linux, and Windows; these tests
do not run authenticated Pi model sessions.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        AI Agent Logs                            │
│         Claude, Cursor, Cline, Codex, Copilot CLI, Warp         │
│                  Claude Desktop, opencode, Pi                    │
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
                      ┌───────┴───────┐
                      ▼               ▼
                JSON/JSONL      Your Detection
                 Export          Pipeline / SIEM
```

## Quick Start

### Installation

Tagged releases are installed from [PyPI](https://pypi.org/project/adr-sensor/):

```bash
pip install adr-sensor
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
adr-sensor --source claude_desktop
adr-sensor --source opencode
adr-sensor --source pi

# Save individual session files (incremental)
adr-sensor --save-sessions

# Export as JSONL
adr-sensor --output-format jsonl

# Include all history (not just last 2 weeks)
adr-sensor --all-history

# Custom output directory
adr-sensor --output-dir ./my-output
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
| Dependencies    | `tabulate` (runtime only — no native deps)  |

Which sources yield data depends on the host OS and on which agents are installed;
see the platform column in [Supported AI Agents](#supported-ai-agents). Sources that
cannot run on the current platform are skipped rather than failing.

### Environment variables

| Variable          | Read by                    | Effect                                                            |
| ----------------- | -------------------------- | ----------------------------------------------------------------- |
| `CODEX_HOME`      | Codex parser               | Codex data root containing `sessions/` and optional `state_*.sqlite` catalogs (default `~/.codex`) |
| `COPILOT_HOME`    | Copilot parser             | Copilot CLI data root containing `session-state/` (default `~/.copilot`) |
| `XDG_CACHE_HOME`  | `AgentObserver`            | Base for `--save-sessions` output (`$XDG_CACHE_HOME/adr_sensor`, default `~/.cache/adr_sensor`) |
| `XDG_DATA_HOME`   | opencode parser            | Overrides the opencode data directory (default `~/.local/share/opencode`) |
| `OPENCODE_DB`     | opencode parser            | Overrides the opencode SQLite filename or path (`:memory:` is ignored) |
| `PI_CODING_AGENT_DIR` | Pi parser              | Agent directory containing `sessions/` (default `~/.pi/agent`) |
| `PI_CODING_AGENT_SESSION_DIR` | Pi parser      | Sessions root; takes precedence over `PI_CODING_AGENT_DIR` |
| `APPDATA`         | Cursor, Cline, Claude Desktop parsers | Windows roaming app-data root. Consulted first so redirected/roaming profiles resolve correctly (default `~/AppData/Roaming`) |
| `LOCALAPPDATA`    | Warp parser                | Windows local app-data root, same redirected-profile handling (default `~/AppData/Local`) |

Errors during ingestion never abort the run: each source is isolated, and failures
are appended as single-line JSON records to `error.log` in the output directory.

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
│   ├── parsers/
│   │   ├── base_parser.py   # Abstract base class
│   │   ├── claude_parser.py
│   │   ├── cursor_parser.py
│   │   ├── cline_parser.py
│   │   ├── claude_desktop_parser.py
│   │   ├── codex_parser.py
│   │   ├── copilot_parser.py
│   │   ├── opencode_parser.py
│   │   ├── pi_parser.py
│   │   └── warp_parser.py
│   ├── schemas/
│   │   ├── agent_event_schema.py    # AgentEvent, ChatMessage, ToolUsage
│   │   └── system_config_schema.py  # SystemConfiguration
│   └── utils/
│       ├── string_utils.py
│       └── timestamp_utils.py
├── tests/
├── examples/
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
