"""GuardMCPServer: local stdio MCP server for guard-mcp.v1.

Wraps FastMCP with sync call_tool/list_tools methods for testability.
The stdio entry point keeps stdout protocol-only; diagnostics go to stderr.
"""

from __future__ import annotations

import contextlib
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .registry import (
    ToolDefinition,
    build_tool_registry,
    get_tool_definition,
    parse_loopback_origin,
)
from .tools import execute_fetch, execute_get_guard_status, execute_search

logger = logging.getLogger(__name__)

_ORIGINAL_TOOL_DESCRIPTIONS: dict[str, str] = {
    "search": (
        "Search local Guard receipts and inventory. Returns at most 20 "
        "sanitized results. The query matches artifact names, harness "
        "names, and policy decisions."
    ),
    "fetch": (
        "Fetch a single Guard receipt or inventory item by its opaque "
        "namespaced ID. Returns at most 32 KiB of sanitized text."
    ),
    "get_guard_status": ("Report whether local Guard data is available and how fresh it is. Takes no input."),
}


def _create_annotations(read_only: bool = True, destructive: bool = False) -> Any:
    from mcp import types

    return types.ToolAnnotations(
        readOnlyHint=read_only,
        destructiveHint=destructive,
        idempotentHint=True,
        openWorldHint=False,
    )


class GuardMCPServer:
    """Local MCP server implementing guard-mcp.v1 over stdio.

    Provides synchronous call_tool/list_tools for direct testing and
    a run_stdio() method for protocol-level stdio transport.

    All tool definitions come from the typed registry in ``registry.py``.
    A new tool cannot appear in one surface and disappear from another.
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

        tools: list[Any] = []
        for td in build_tool_registry():
            description = _ORIGINAL_TOOL_DESCRIPTIONS.get(td.name, td.description)
            annotations = _create_annotations(
                read_only=td.annotations.read_only,
                destructive=td.annotations.destructive,
            )
            tools.append(
                types.Tool(
                    name=td.name,
                    description=description,
                    inputSchema=cast(dict[str, Any], td.input_schema),
                    annotations=annotations,
                )
            )
        return tools

    def call_tool(self, name: str, arguments: dict[str, object]) -> Any:
        from mcp import types

        td = get_tool_definition(name)
        if td is None:
            from .tools import _envelope

            text = _envelope({"ok": False, "error": {"code": "unknown_tool", "message": f"Unknown tool: {name}"}})
            return types.TextContent(type="text", text=text)

        store = self.store
        if name == "search":
            query = str(arguments.get("query", ""))
            text = execute_search(store, query)
        elif name == "fetch":
            item_id = str(arguments.get("id", ""))
            text = execute_fetch(store, item_id)
        elif name == "get_guard_status":
            text = execute_get_guard_status(store)
        elif name == "validate_policy":
            from .policy_tools import execute_validate_policy

            text = execute_validate_policy(store, arguments)
        elif name == "create_policy":
            from .policy_tools import execute_create_policy

            approval_url_builder = self._build_approval_url_builder()
            text = execute_create_policy(
                store,
                arguments,
                approval_url_builder=approval_url_builder,
            )
        elif name == "get_policy_creation":
            from .policy_tools import execute_get_policy_creation

            text = execute_get_policy_creation(store, arguments)
        else:
            from .tools import _envelope

            text = _envelope({"ok": False, "error": {"code": "unknown_tool", "message": f"Unknown tool: {name}"}})
        return types.TextContent(type="text", text=text)

    def _build_approval_url_builder(self) -> Callable[[str], str | None] | None:
        """Build a function that derives the trusted loopback approval URL.

        The origin is derived from trusted Guard daemon configuration, never
        from the tool caller.  Reads the approval-center locator from the
        daemon manager (no daemon.server import) and validates the loopback
        origin via the pure registry parser.
        """
        try:
            from ..daemon.manager import read_approval_center_locator
        except Exception:
            return None

        def _build(request_id: str) -> str | None:
            try:
                locator = read_approval_center_locator(self.guard_home)
                if locator is None:
                    return None
                origin = parse_loopback_origin(locator.approval_url_base)
                if origin is None:
                    return None
                return f"{origin}/requests/{request_id}"
            except Exception:
                logger.warning("Failed to build approval URL for request %s", request_id, exc_info=True)
                return None

        return _build

    def run_stdio(self) -> int:
        """Run the MCP server over stdio transport."""
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("hol-guard")

        for td in build_tool_registry():
            description = _ORIGINAL_TOOL_DESCRIPTIONS.get(td.name, td.description)
            annotations = _create_annotations(
                read_only=td.annotations.read_only,
                destructive=td.annotations.destructive,
            )
            self._register_fastmcp_tool(mcp, td, description, annotations)

        mcp.run(transport="stdio")
        return 0

    def _register_fastmcp_tool(
        self,
        mcp: Any,
        td: ToolDefinition,
        description: str,
        annotations: Any,
    ) -> None:
        """Register one tool with FastMCP, preserving per-tool annotations."""
        store = self.store

        if td.name == "search":

            @mcp.tool(name="search", description=description, annotations=annotations)
            def search(query: str) -> str:
                return execute_search(store, query)

        elif td.name == "fetch":

            @mcp.tool(name="fetch", description=description, annotations=annotations)
            def fetch(id: str) -> str:  # noqa: A002
                return execute_fetch(store, id)

        elif td.name == "get_guard_status":

            @mcp.tool(name="get_guard_status", description=description, annotations=annotations)
            def get_guard_status() -> str:
                return execute_get_guard_status(store)

        elif td.name == "validate_policy":
            from .policy_tools import execute_validate_policy

            @mcp.tool(name="validate_policy", description=description, annotations=annotations)
            def validate_policy(policyYaml: str, mode: str = "merge") -> str:  # noqa: N803
                return execute_validate_policy(store, {"policyYaml": policyYaml, "mode": mode})

        elif td.name == "create_policy":
            from mcp.server.fastmcp import Context
            from mcp.server.session import ServerSession

            from .policy_tools import execute_create_policy

            approval_url_builder = self._build_approval_url_builder()

            @mcp.tool(name="create_policy", description=description, annotations=annotations)
            async def create_policy(
                policyYaml: str,  # noqa: N803
                mode: str,
                candidateDigest: str,  # noqa: N803
                expectedCurrentDigest: str | None,  # noqa: N803
                idempotencyKey: str,  # noqa: N803
                ctx: Context[ServerSession, object, object],
            ) -> str:
                arguments: dict[str, object] = {
                    "policyYaml": policyYaml,
                    "mode": mode,
                    "candidateDigest": candidateDigest,
                    "expectedCurrentDigest": expectedCurrentDigest,
                    "idempotencyKey": idempotencyKey,
                }

                def _url_builder(request_id: str) -> str | None:
                    if approval_url_builder is not None:
                        url = approval_url_builder(request_id)
                        if url is not None:
                            return url
                    return None

                result_text = execute_create_policy(
                    store,
                    arguments,
                    approval_url_builder=_url_builder,
                )

                import json

                result: object = json.loads(result_text)
                if isinstance(result, dict) and result.get("status") == "pending":
                    approval_url = result.get("approvalUrl")
                    request_id = result.get("requestId")
                    if isinstance(approval_url, str) and isinstance(request_id, str):
                        with contextlib.suppress(Exception):
                            await ctx.elicit_url(
                                url=approval_url,
                                message=(
                                    "Guard policy creation requires human approval. "
                                    "Open this URL to review and approve the pending policy request."
                                ),
                                elicitation_id=request_id,
                            )
                return result_text

        elif td.name == "get_policy_creation":
            from .policy_tools import execute_get_policy_creation

            @mcp.tool(name="get_policy_creation", description=description, annotations=annotations)
            def get_policy_creation(requestId: str) -> str:  # noqa: N803
                return execute_get_policy_creation(store, {"requestId": requestId})


__all__ = ["GuardMCPServer"]
