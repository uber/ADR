# Contributing to ADR Sensor

Thank you for your interest in contributing to ADR Sensor! This guide will help you get started.

## Getting Started

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/ADR.git
   cd ADR/Sensor
   ```
3. Install in development mode:
   ```bash
   pip install -e ".[dev]"
   ```
4. Run tests to verify:
   ```bash
   pytest tests/ -v
   ```

## Development Workflow

1. Create a branch for your change:
   ```bash
   git checkout -b feature/my-new-parser
   ```
2. Make your changes
3. Run tests and linting:
   ```bash
   pytest tests/ -v
   ruff check adr_sensor/
   ruff format adr_sensor/
   ```
4. Commit and push
5. Open a Pull Request

## Adding a New Parser

This is the most common contribution. To add support for a new AI agent:

### Step 1: Create the Parser

Create `adr_sensor/parsers/my_agent_parser.py`:

```python
from pathlib import Path
from typing import List

from ..parsers.base_parser import BaseParser
from ..schemas.agent_event_schema import AgentEvent, ChatMessage, ToolUsage

class MyAgentParser(BaseParser):
    """Parser for MyAgent logs."""

    def __init__(self):
        # Set the path where your agent stores its logs
        self.base_path = Path.home() / ".my-agent/logs"

    def parse_all(self) -> List[AgentEvent]:
        """Parse all available MyAgent logs."""
        entries = []

        if not self.base_path.exists():
            print(f"[MY_AGENT] No logs found at {self.base_path}")
            return entries

        # Your parsing logic here
        # Convert logs into AgentEvent objects

        return entries
```

### Step 2: Register in Observer

Export the parser from `adr_sensor/parsers/__init__.py`, then register it in
`adr_sensor/observer.py`:

```python
from .parsers.my_agent_parser import MyAgentParser


class AgentObserver:
    SOURCES = (
        ...,
        ("my_agent", "MyAgent"),  # (source key, display label)
    )

    def __init__(self, ...):
        ...
        # The parser must be named <source key>_parser
        self.my_agent_parser = MyAgentParser()
```

`ingest_all()` iterates `SOURCES` and resolves each parser as
`self.<source>_parser`, so no per-source branch is needed — it handles the
`has_meaningful_content()` filter, error isolation and `error.log` reporting for you.

If the agent only exists on some operating systems, add it to
`PLATFORM_RESTRICTED_SOURCES` so it is skipped elsewhere instead of failing:

```python
PLATFORM_RESTRICTED_SOURCES = {
    "claude_desktop": ("Darwin", "Windows"),
    "my_agent": ("Darwin",),
}
```

### Step 3: Add CLI Source

Nothing to do — `adr_sensor/cli.py` builds its `--source` choices from
`AgentObserver.SOURCES`. Add an example line to the CLI epilog if the new source
needs explanation.

Source keys are part of the Sensor's public contract — downstream detection
pipelines filter on them. Treat renaming one as a breaking change and avoid it;
prefer adding a new key alongside the existing one.

### Step 4: Write Tests

Add test cases to `tests/test_parsers.py` (or `tests/test_my_agent_parser.py` for a
larger parser) covering:
- Parsing valid log files
- Handling missing directories
- Handling malformed data
- Age filtering, if the parser supports `max_age_days`
- Edge cases

## Code Style

- Follow PEP 8
- Use type hints
- Use `ruff` for formatting and linting
- Keep parsers self-contained (each parser should handle its own errors)

## Testing Guidelines

- All new code must have tests
- Tests should not depend on real log files existing on the machine
- Use `tmp_path` fixture for file-based tests
- Use mocks for external dependencies

## Reporting Issues

When reporting bugs, please include:
- Python version
- Operating system
- Steps to reproduce
- Error messages or unexpected output

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
