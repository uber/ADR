#!/usr/bin/env python3
"""
ADR Sensor Demo - Shows how to use the ADR Sensor library programmatically.

This demo creates sample data and demonstrates the core API.
Run with: python examples/demo.py
"""

from datetime import datetime, timezone

from adr_sensor import AgentEvent, AgentObserver, ChatMessage, ToolUsage


def create_sample_events():
    """Create sample AgentEvent objects for demonstration."""
    events = []

    # Sample 1: Claude Code session with tool usage
    claude_event = AgentEvent(
        timestamp=datetime(2025, 6, 15, 10, 30, 0, tzinfo=timezone.utc),
        source="claude",
        session_id="claude_demo_session_1",
        project_path="/home/user/my-project",
        model="claude-sonnet-4-20250514",
        hostname="demo-laptop",
        username="developer",
        chat_history=[
            ChatMessage(
                role="user",
                content="Can you help me find and fix the bug in auth.py?",
                sequence_id="msg_0",
            ),
            ChatMessage(
                role="assistant",
                content="I'll read the file to understand the issue.",
                tools=[
                    ToolUsage(
                        tool_name="read_file",
                        tool_type="tool_use",
                        arguments={"path": "auth.py"},
                        result="def authenticate(user, password):\n    return True  # BUG: no validation",
                        status="success",
                    )
                ],
                sequence_id="msg_1",
            ),
            ChatMessage(
                role="assistant",
                content="I found the bug! The authenticate function always returns True.",
                tools=[
                    ToolUsage(
                        tool_name="write_file",
                        tool_type="tool_use",
                        arguments={"path": "auth.py", "content": "def authenticate(user, pw): ..."},
                        status="success",
                    )
                ],
                sequence_id="msg_2",
            ),
        ],
    )
    events.append(claude_event)

    # Sample 2: Cursor IDE session
    cursor_event = AgentEvent(
        timestamp=datetime(2025, 6, 15, 11, 0, 0, tzinfo=timezone.utc),
        source="cursor",
        session_id="cursor_demo_session_2",
        hostname="demo-laptop",
        username="developer",
        chat_history=[
            ChatMessage(role="user", content="Explain what this function does", sequence_id="seq_0"),
            ChatMessage(
                role="assistant",
                content="This function handles user authentication by...",
                sequence_id="seq_1",
            ),
        ],
    )
    events.append(cursor_event)

    # Sample 3: Codex CLI with terminal commands
    codex_event = AgentEvent(
        timestamp=datetime(2025, 6, 15, 11, 30, 0, tzinfo=timezone.utc),
        source="codex",
        session_id="codex_demo_session_3",
        model="o3-mini",
        hostname="demo-laptop",
        username="developer",
        chat_history=[
            ChatMessage(role="user", content="Run the test suite", sequence_id="msg_0"),
            ChatMessage(
                role="assistant",
                content="Running tests...",
                tools=[
                    ToolUsage(
                        tool_name="shell",
                        tool_type="function_call",
                        arguments={"command": "pytest tests/ -v"},
                        result="5 passed, 0 failed",
                        status="success",
                    )
                ],
                sequence_id="msg_1",
            ),
        ],
    )
    events.append(codex_event)

    # Sample 4: opencode session calling an MCP tool
    opencode_event = AgentEvent(
        timestamp=datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc),
        source="opencode",
        session_id="opencode_demo_session_4",
        project_path="/home/user/my-project",
        model="claude-sonnet-4-20250514",
        user_id="anthropic opencode/1.17.14",
        hostname="demo-laptop",
        username="developer",
        chat_history=[
            ChatMessage(role="user", content="File an issue for the auth bug", sequence_id="msg_0"),
            ChatMessage(
                role="assistant",
                content="Filing it now.",
                tools=[
                    ToolUsage(
                        # opencode namespaces MCP tools as <server>_<tool>
                        tool_name="github_create_issue",
                        tool_type="mcp_tool",
                        server_name="github",
                        arguments={"title": "authenticate() never validates the password"},
                        result="Created issue #42",
                        status="success",
                    )
                ],
                sequence_id="msg_1",
            ),
        ],
    )
    events.append(opencode_event)

    # Sample 5: Claude Desktop Dispatch session (delegated background agent)
    claude_desktop_event = AgentEvent(
        timestamp=datetime(2025, 6, 15, 12, 30, 0, tzinfo=timezone.utc),
        source="claude_desktop",
        session_id="claude_desktop_dispatch_demo_session_5",
        project_path="/home/user/my-project",
        model="claude-sonnet-4-20250514",
        hostname="demo-laptop",
        username="developer",
        session_context={
            "title": "Nightly dependency audit",
            "is_dispatch": True,
            "session_type": "dispatch",
            "init": {
                "tools": ["Bash", "Read"],
                "mcp_servers": [{"name": "github"}],
                "permission_mode": "acceptEdits",
            },
        },
        chat_history=[
            ChatMessage(role="user", content="Audit our dependencies for CVEs", sequence_id="msg_0"),
            ChatMessage(
                role="assistant",
                content="Running the audit.",
                tools=[
                    ToolUsage(
                        tool_name="Bash",
                        tool_type="tool_use",
                        arguments={"command": "pip-audit"},
                        result="No known vulnerabilities found",
                        status="success",
                    )
                ],
                sequence_id="msg_1",
            ),
        ],
    )
    events.append(claude_desktop_event)

    return events


def main():
    print("=" * 60)
    print("  ADR Sensor Demo")
    print("=" * 60)
    print()

    # Create sample events
    events = create_sample_events()
    print(f"Created {len(events)} sample events\n")

    # Display summaries
    print("Event Summaries:")
    print("-" * 60)
    for event in events:
        print(f"  {event.get_summary()}")
    print()

    # Show detailed view of first event
    print("Detailed View (first event):")
    print("-" * 60)
    event = events[0]
    print(f"  Source: {event.source}")
    print(f"  Session: {event.session_id}")
    print(f"  UUID: {event.uuid[:16]}...")
    print(f"  Model: {event.model}")
    print(f"  Messages: {len(event.chat_history)}")
    print(f"  Has tools: {event.has_tool_usage()}")
    print()

    # Show tool usage analysis
    print("Tool Usage Analysis:")
    print("-" * 60)
    for event in events:
        for msg in event.chat_history:
            if msg.tools:
                for tool in msg.tools:
                    print(f"  [{event.source}] {tool.tool_name} ({tool.tool_type}) -> {tool.status}")
    print()

    # Use the observer to display a summary table
    print("Observer Summary Table:")
    print("-" * 60)
    observer = AgentObserver()
    observer.display_summary(events, [])

    # Export to JSON
    print("\nJSON export (first event):")
    print("-" * 60)
    import json
    fields = events[0].get_non_null_fields()
    # Show truncated output
    json_str = json.dumps(fields, indent=2)
    lines = json_str.split("\n")
    for line in lines[:20]:
        print(f"  {line}")
    if len(lines) > 20:
        print(f"  ... ({len(lines) - 20} more lines)")

    print()
    print("=" * 60)
    print("  Demo complete! Run 'adr-sensor' to scan your actual agent logs.")
    print("=" * 60)


if __name__ == "__main__":
    main()
