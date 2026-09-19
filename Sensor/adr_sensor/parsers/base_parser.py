"""
Base parser interface for ADR Sensor.

All parsers should inherit from BaseParser and implement the parse_all() method.
This enables easy extension with new AI agent log formats.
"""

from abc import ABC, abstractmethod
from typing import Dict, List

from ..schemas.agent_event_schema import AgentEvent


class BaseParser(ABC):
    """Abstract base class for all ADR parsers.

    To add support for a new AI agent, create a new parser class that inherits
    from BaseParser and implements the parse_all() method.

    Example:
        class MyAgentParser(BaseParser):
            def parse_all(self) -> List[AgentEvent]:
                # Parse logs from your agent and return AgentEvent objects
                ...
    """

    # Closed vocabulary keeps diagnostic size bounded and prevents input content
    # (paths, exception messages, record types, or credentials) becoming labels.
    EXPECTED_DIAGNOSTIC_CODES = frozenset({"input_missing", "file_age_skipped", "incomplete_record"})
    DIAGNOSTIC_CODES = EXPECTED_DIAGNOSTIC_CODES | frozenset(
        {
            "file_read_error",
            "file_stat_error",
            "record_decode_error",
            "record_shape_error",
            "unsupported_record_type",
            "unsupported_schema",
            "unsupported_content_block",
            "invalid_timestamp",
            "session_build_error",
            "database_error",
            "parser_error",
        }
    )

    def reset_diagnostics(self) -> None:
        """Start a new observation window without changing captured telemetry."""
        self._diagnostics: Dict[str, int] = {}

    def record_diagnostic(self, code: str, count: int = 1) -> None:
        """Count an expected skip or recovery using a fixed, content-free code."""
        if not isinstance(code, str) or code not in self.DIAGNOSTIC_CODES:
            raise ValueError("unknown parser diagnostic code")
        if isinstance(count, bool) or not isinstance(count, int) or count < 1:
            raise ValueError("parser diagnostic count must be a positive integer")
        # Existing parser constructors do not need to call super().__init__().
        if not hasattr(self, "_diagnostics"):
            self.reset_diagnostics()
        self._diagnostics[code] = min(self._diagnostics.get(code, 0) + count, 2**63 - 1)

    def get_diagnostics(self) -> Dict[str, int]:
        """Return a snapshot; callers cannot mutate the parser's counters."""
        return dict(getattr(self, "_diagnostics", {}))

    @abstractmethod
    def parse_all(self) -> List[AgentEvent]:
        """Parse all available logs and return a list of AgentEvent objects.

        Returns:
            List of AgentEvent objects representing parsed telemetry data.
        """
        ...
