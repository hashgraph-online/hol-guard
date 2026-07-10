"""GuardMCPServer: local stdio MCP server for guard-mcp.v1.

Wraps FastMCP with sync call_tool/list_tools methods for testability.
The stdio entry point keeps stdout protocol-only; diagnostics go to stderr.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from .tools import execute_fetch, execute_get_guard_status, execute_search

logger = logging.getLogger(__name__)

_TOOL_DEFINITIONS = [
    {
        "name": "search",
        "description": (
            "Search local Guard receipts and inventory. Returns at most 20 "
            "sanitized results. The query matches artifact names, harness "
            "names, and policy decisions."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Free-text search query.",
                },
            },
            "required": ["query"],
        },
    },
    {
        "name": "fetch",
        "description": (
            "Fetch a single Guard receipt or inventory item by its opaque "
            "namespaced ID. Returns at most 32 KiB of sanitized text."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "id": {
                    "type": "string",
                    "description": "Opaque namespaced ID (receipt:, artifact:, inventory:, device:).",
                },
            },
            "required": ["id"],
        },
    },
    {
        "name": "get_guard_status",
        "description": ("Report whether local Guard data is available and how fresh it is. Takes no input."),
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
]


def _create_annotations() -> Any:
    from mcp import types

    return types.ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )


class GuardMCPServer:
    """Local MCP server implementing guard-mcp.v1 over stdio.

    Provides synchronous call_tool/list_tools for direct testing and
    a run_stdio() method for protocol-level stdio transport.
    """

    def __init__(self, guard_home: Path) -> None:
        self.guard_home = guard_home
        self._store: Any = None

    @property
    def store(self) -> Any:
        if self._store is None:
            from codex_plugin_scanner.guard.store import GuardStore

            self._store = GuardStore(self.guard_home)
        return self._store

    def list_tools(self) -> list[Any]:
        from typing import cast

        from mcp import types

        annotations = _create_annotations()
        return [
            types.Tool(
                name=str(td["name"]),
                description=str(td["description"]),
                inputSchema=cast(dict[str, Any], td["inputSchema"]),
                annotations=annotations,
            )
            for td in _TOOL_DEFINITIONS
        ]

    def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        from mcp import types

        store = self.store
        if name == "search":
            query = str(arguments.get("query", ""))
            text = execute_search(store, query)
        elif name == "fetch":
            item_id = str(arguments.get("id", ""))
            text = execute_fetch(store, item_id)
        elif name == "get_guard_status":
            text = execute_get_guard_status(store)
        else:
            text = json.dumps({"error": f"Unknown tool: {name}"})
        return types.TextContent(type="text", text=text)

    def run_stdio(self) -> int:
        """Run the MCP server over stdio transport."""
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("hol-guard")
        annotations = _create_annotations()

        search_desc = _TOOL_DEFINITIONS[0]["description"]
        fetch_desc = _TOOL_DEFINITIONS[1]["description"]
        status_desc = _TOOL_DEFINITIONS[2]["description"]

        @mcp.tool(
            name="search",
            description=str(search_desc),
            annotations=annotations,
        )
        def search(query: str) -> str:
            return execute_search(self.store, query)

        @mcp.tool(
            name="fetch",
            description=str(fetch_desc),
            annotations=annotations,
        )
        def fetch(id: str) -> str:  # noqa: A002
            return execute_fetch(self.store, id)

        @mcp.tool(
            name="get_guard_status",
            description=str(status_desc),
            annotations=annotations,
        )
        def get_guard_status() -> str:
            return execute_get_guard_status(self.store)

        mcp.run(transport="stdio")
        return 0
