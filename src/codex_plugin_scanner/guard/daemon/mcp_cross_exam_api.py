"""Read-only dashboard route for local MCP Cross Exam audit summaries."""

from __future__ import annotations

from typing import Any, Final, Protocol, cast

from ...integrations.mcp_cross_exam import load_mcp_cross_exam_results

RESULTS_PATH: Final = "/v1/mcp-cross-exam/results"


class McpCrossExamHandler(Protocol):
    server: Any

    def _write_json(self, payload: dict[str, object], *, status: int = 200) -> None: ...


def handle_mcp_cross_exam_get(request_handler: object, path: str) -> bool:
    if path != RESULTS_PATH:
        return False
    handler = cast(McpCrossExamHandler, request_handler)
    handler._write_json(load_mcp_cross_exam_results(handler.server.store.guard_home))
    return True
