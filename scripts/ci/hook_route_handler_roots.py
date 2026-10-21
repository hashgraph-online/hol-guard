"""The native hook handlers the resident's route can name.

The pipeline reaches them through a table, which a call-graph walk cannot
follow, so each gate that walks calls from the hook entry points starts one
walk at every handler listed here as well.
"""

from __future__ import annotations

from typing import Final

_CLI = "src/codex_plugin_scanner/guard/cli"
_HANDLERS = f"{_CLI}/commands_hook_native_route_handlers.py"

ROUTE_HANDLER_ROOTS: Final[tuple[tuple[str, str], ...]] = (
    (f"{_CLI}/commands_hook_native_pipeline.py", "_artifact_flow"),
    (f"{_CLI}/commands_hook_native_route.py", "run_route_plan"),
    *(
        (_HANDLERS, name)
        for name in (
            "passthrough",
            "claude_guard_question",
            "native_edge",
            "edge_unavailable",
            "containment",
            "copilot_pretool",
            "copilot_permission_request",
            "runtime_artifact",
            "claude_permission_request",
            "claude_permission_prompt",
            "claude_stop",
            "generic_flow",
        )
    ),
)
