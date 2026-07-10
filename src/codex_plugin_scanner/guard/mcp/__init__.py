"""HOL Guard local MCP server implementing guard-mcp.v1.

Modules:
- schemas: contract constants, ID namespaces, output envelopes
- sanitizers: default-deny field sanitization per result kind
- adapters: bridge GuardStore queries to MCP-safe result dicts
- tools: search, fetch, get_guard_status implementations
- server: GuardMCPServer wrapping FastMCP, stdio entry point
"""

from __future__ import annotations

__all__: list[str] = []
