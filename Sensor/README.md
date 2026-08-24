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
| **Warp Terminal**          | `warp`           | SQLite (`warp.sqlite`)              | macOS, Windows         |
| **opencode**               | `opencode`       | SQLite (`opencode.db`) or JSON tree | macOS, Linux           |

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


## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        AI Agent Logs                            │
│ Claude Code │ Cursor │ Cline │ Codex │ Warp │ Desktop │ opencode│
└──────┬──────┴───┬────┴───┬───┴───┬───┴──┬───┴───┬────┴─────┬────┘
       │          │        │       │      │       │          │
       ▼          ▼        ▼       ▼      ▼       ▼          ▼
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
adr-sensor --source claude_desktop
adr-sensor --source opencode

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
| `XDG_CACHE_HOME`  | `AgentObserver`            | Base for `--save-sessions` output (`$XDG_CACHE_HOME/adr_sensor`, default `~/.cache/adr_sensor`) |
| `XDG_DATA_HOME`   | opencode parser            | Overrides the opencode data directory (default `~/.local/share/opencode`) |
| `OPENCODE_DB`     | opencode parser            | Overrides the opencode SQLite filename or path (`:memory:` is ignored) |
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
