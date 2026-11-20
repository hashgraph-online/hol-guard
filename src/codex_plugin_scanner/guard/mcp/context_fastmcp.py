"""Typed FastMCP transport adapters for the native context registry."""

from __future__ import annotations

import asyncio
import contextlib
from typing import Any

from mcp.server.fastmcp import Context
from mcp.server.session import ServerSession

from ..native_context_agent import NativeContextAgent
from .context_tools import execute


def register(mcp: Any, agent: NativeContextAgent, name: str, description: str, annotations: Any) -> None:
    async def call(arguments: dict[str, object], ctx: Any) -> str:
        result = await asyncio.to_thread(execute, agent, name, arguments)
        with contextlib.suppress(Exception):
            await ctx.session.send_tool_list_changed()
        return result

    options = dict(name=name, description=description, annotations=annotations, structured_output=False)
    if name == "get_context_status":

        @mcp.tool(**options)
        async def status(ctx: Context[ServerSession, object, object]) -> str:
            return await call({}, ctx)
    elif name == "get_guard_context":

        @mcp.tool(**options)
        async def query(query: str, ctx: Context[ServerSession, object, object]) -> str:
            return await call({"query": query}, ctx)
    elif name == "explain_guard_context":

        @mcp.tool(**options)
        async def explanation(snapshot_id: str, ctx: Context[ServerSession, object, object]) -> str:
            return await call({"snapshot_id": snapshot_id}, ctx)
    elif name == "explain_guard_action":

        @mcp.tool(**options)
        async def action(
            decision_id: str, ctx: Context[ServerSession, object, object], snapshot_id: str | None = None
        ) -> str:
            arguments: dict[str, object] = {"decision_id": decision_id}
            if snapshot_id is not None:
                arguments["snapshot_id"] = snapshot_id
            return await call(arguments, ctx)
    elif name == "propose_guard_context_note":

        @mcp.tool(**options)
        async def propose(
            snapshot_id: str, request_key: str, text: str, ctx: Context[ServerSession, object, object]
        ) -> str:
            return await call({"snapshot_id": snapshot_id, "request_key": request_key, "text": text}, ctx)
    else:

        @mcp.tool(**options)
        async def proposal(request_key: str, ctx: Context[ServerSession, object, object]) -> str:
            return await call({"request_key": request_key}, ctx)
