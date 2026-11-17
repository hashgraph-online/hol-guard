"""HTTP framing for Swarm; native code owns discovery and lifecycle."""

from __future__ import annotations

from typing import Any

from ..native_swarm import SwarmError, execute

WRITE_PATHS = {
    "/v1/swarm/launch": "launch",
    "/v1/swarm/action": "direct",
    "/v1/swarm/events": "events",
}


def respond(handler: Any, action: str = "snapshot", payload: dict[str, Any] | None = None) -> None:
    try:
        result = execute(action, payload or {}, guard_home=handler.server.store.guard_home)
    except SwarmError as error:
        status = 503
        if error.code in {"swarm_stale", "swarm_request_conflict", "swarm_expired"}:
            status = 409
        elif error.code in {
            "swarm_cli_missing",
            "swarm_workspace_invalid",
            "swarm_run_limit",
            "swarm_request_limit",
            "swarm_unknown_run",
            "swarm_action_unavailable",
            "swarm_launch_invalid",
            "swarm_action_invalid",
        }:
            status = 400
        handler._write_json({"error": error.code}, status=status, extra_headers={"Cache-Control": "no-store"})
        return
    except (OSError, ValueError, RuntimeError):
        handler._write_json({"error": "swarm_unavailable"}, status=503)
        return
    handler._write_json(result, extra_headers={"Cache-Control": "no-store"})
