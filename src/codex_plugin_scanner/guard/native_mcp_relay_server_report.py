"""Report an MCP server's catalog for the native MCP relay.

The native relay runs a session's MCP server only when the resident has a
report of that server's catalog and the catalog offers no tool whose calls
the proxy decides itself: a shell-named tool, a tool declaring a command
argument (including one declared behind a schema reference or combinator), or
a Composio tool. Any other session runs under this proxy, which
reports the whole catalog once it has it, so the server's later sessions can
run under the relay.

The report only steers which launcher later sessions run. It carries no
verdict, and the resident still decides or refuses every relayed call, so a
lost report only keeps the server under the proxy. It is sent best effort
from a background thread and never delays or fails the host's ``tools/list``.
"""

from __future__ import annotations

import threading
from collections.abc import Sequence
from pathlib import Path

from .native_execution import _resident_request

MCP_RELAY_SERVER_REPORT_FEATURE = "mcp-relay-server-report-v1"
_OPERATION = "mcp_relay_server_report"
_RESULT_SCHEMA = "guard-mcp-relay-server-report-result.v1"
_TIMEOUT_SECONDS = 2.0
# The harnesses whose MCP proxy the relay replaces.
_RELAY_HARNESSES = frozenset({"codex", "copilot", "cursor", "opencode"})


def report_mcp_relay_server(
    *,
    guard_home: Path,
    harness: str,
    server_name: str,
    source_scope: str,
    config_path: str,
    server_id: str | None,
    identity_hash: str,
    tools: Sequence[dict[str, object]],
) -> threading.Thread | None:
    """Send the report in the background; ``None`` when nothing is sent."""

    if harness not in _RELAY_HARNESSES:
        return None
    request: dict[str, object] = {
        "guard_home": str(guard_home),
        "server": {
            "harness": harness,
            "server_name": server_name,
            "source_scope": source_scope,
            "config_path": config_path,
            "server_id": server_id,
            "identity_hash": identity_hash,
        },
        "tools": [dict(tool) for tool in tools],
    }
    thread = threading.Thread(
        target=_send,
        args=(guard_home, request),
        name="guard-mcp-relay-server-report",
        daemon=True,
    )
    thread.start()
    return thread


def _send(guard_home: Path, request: dict[str, object]) -> None:
    try:
        _resident_request(
            operation=_OPERATION,
            request=request,
            guard_home=guard_home,
            timeout_seconds=_TIMEOUT_SECONDS,
            required_feature=MCP_RELAY_SERVER_REPORT_FEATURE,
            response_schema=_RESULT_SCHEMA,
            record_success=False,
            record_resilience=False,
        )
    except Exception:
        # A lost report keeps the server under the proxy.
        return
