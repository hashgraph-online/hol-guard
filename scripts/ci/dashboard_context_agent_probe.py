"""Real MCP client for browser pairing acceptance; no operator authority."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path


async def probe(guard_home: Path) -> None:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    server = StdioServerParameters(
        command=sys.executable,
        args=["-B", str(Path(__file__).resolve()), "--guard-home", str(guard_home), "--server"],
        env=os.environ.copy(),
    )
    async with stdio_client(server) as (read, write), ClientSession(read, write) as client:
        initialized = await client.initialize()
        while line := await asyncio.to_thread(sys.stdin.readline):
            request = json.loads(line)
            if request["method"] == "list":
                result = {
                    "tools": [tool.name for tool in (await client.list_tools()).tools],
                    "list_changed": initialized.capabilities.tools.listChanged,
                }
            else:
                response = await client.call_tool(request["method"], request.get("arguments", {}))
                if response.isError:
                    raise RuntimeError("MCP protocol returned an error")
                result = json.loads(response.content[0].text)
            # Only public MCP results cross this pipe. The server retains its
            # native credential privately; neither client nor browser gets it.
            print(json.dumps({"id": request["id"], "result": result}), flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--guard-home", type=Path, required=True)
    parser.add_argument("--server", action="store_true")
    arguments = parser.parse_args()
    if arguments.server:
        from codex_plugin_scanner.guard.mcp.server import GuardMCPServer

        raise SystemExit(GuardMCPServer(arguments.guard_home).run_stdio())
    asyncio.run(probe(arguments.guard_home))


if __name__ == "__main__":
    main()
