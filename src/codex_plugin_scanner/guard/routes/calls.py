"""Daemon POST routes whose handlers run unchanged behind ``desktop library-call``.

The handlers here write their reply through a request handler. The native
daemon owns the socket, the caller check and the body read, so the call hands
each handler a recorder in place of the request handler and returns the one
reply it wrote: ``{"status": int, "body": {...}, "no_store": bool}``.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from ..approval_gate import ApprovalGateError
from ..store import GuardStore

_NO_STORE = {"Cache-Control": "no-store"}


class RouteReplyError(Exception):
    """A handler wrote no reply, two replies, or a header the daemon cannot send."""


class _Recorder:
    """Stands in for the daemon's request handler and keeps the reply it writes."""

    def __init__(self, store: GuardStore) -> None:
        self.server = SimpleNamespace(store=store)
        self._reply: dict[str, object] | None = None

    def _write_json(
        self,
        payload: dict[str, Any],
        *,
        status: int = 200,
        extra_headers: Mapping[str, str] | None = None,
    ) -> None:
        if self._reply is not None:
            raise RouteReplyError("second_reply")
        headers = dict(extra_headers or {})
        if headers not in ({}, _NO_STORE):
            raise RouteReplyError("unsupported_headers")
        self._reply = {"status": status, "body": dict(payload), "no_store": headers == _NO_STORE}

    def _write_approval_gate_error(self, error: ApprovalGateError, *, resolved: bool | None = None) -> None:
        payload = error.to_payload()
        if resolved is not None:
            payload["resolved"] = resolved
        self._write_json(payload, status=error.status)

    def _header_token_is_valid(self, *, payload: dict[str, object] | None = None) -> bool:
        # The native daemon checked the caller before it ran this call.
        del payload
        return True

    def reply(self) -> dict[str, object]:
        if self._reply is None:
            raise RouteReplyError("no_reply")
        return self._reply


def _arguments(args: Mapping[str, Any]) -> tuple[str, dict[str, object]]:
    path = args.get("path")
    payload = args.get("payload")
    if not isinstance(path, str) or not isinstance(payload, dict):
        from ..library_calls import LibraryCallError

        raise LibraryCallError("invalid_arguments")
    return path, payload


def _path_parts(path: str) -> list[str]:
    return [part for part in path.split("/") if part]


def handler_post(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Runs the handler the daemon dispatches ``POST path`` to."""

    from ..adapters.base import HarnessContext
    from ..harness_version_api import WRITE_PATHS as HARNESS_VERSION_WRITE_PATHS
    from ..harness_version_api import handle_harness_version_write
    from ..library_calls import LibraryCallError
    from .context_assistance_http import WRITE_PATHS as CONTEXT_ASSISTANCE_WRITE_PATHS
    from .context_assistance_http import respond as respond_context_assistance
    from .mcp_policy_decisions import handle_mcp_policy_decision
    from .workspace_assessment_api import handle_workspace_assessment_post

    path, payload = _arguments(args)
    recorder = _Recorder(store)
    parts = _path_parts(path)
    if path in {"/v1/swarm/launch", "/v1/swarm/action", "/v1/swarm/events"}:
        from ..native_swarm import SwarmError, execute

        action = {
            "/v1/swarm/launch": "launch",
            "/v1/swarm/action": "direct",
            "/v1/swarm/events": "events",
        }[path]
        try:
            result = execute(action, payload, guard_home=store.guard_home)
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
            recorder._write_json({"error": error.code}, status=status, extra_headers=_NO_STORE)
        except (OSError, ValueError, RuntimeError):
            recorder._write_json({"error": "swarm_unavailable"}, status=503)
        else:
            recorder._write_json(result, extra_headers=_NO_STORE)
    elif path in CONTEXT_ASSISTANCE_WRITE_PATHS:
        respond_context_assistance(recorder, CONTEXT_ASSISTANCE_WRITE_PATHS[path], payload)
    elif path in HARNESS_VERSION_WRITE_PATHS:
        context = HarnessContext(home_dir=Path.home().resolve(), workspace_dir=None, guard_home=store.guard_home)
        handle_harness_version_write(recorder, path, payload, context)
    elif len(parts) == 5 and parts[:3] == ["v1", "mcp-policy", "requests"] and parts[4] == "decision":
        handle_mcp_policy_decision(recorder, parts[3], payload)
    elif not handle_workspace_assessment_post(recorder, path, payload):
        raise LibraryCallError("invalid_arguments")
    return recorder.reply()


def handler_get(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Runs the handler the daemon dispatches ``GET path?query`` to."""

    from ..library_calls import LibraryCallError
    from .context_assistance_http import READ_PATHS as CONTEXT_ASSISTANCE_READ_PATHS
    from .context_assistance_http import respond as respond_context_assistance
    from .workspace_assessment_api import handle_workspace_assessment_get

    path = args.get("path")
    query = args.get("query", "")
    if not isinstance(path, str) or not isinstance(query, str):
        raise LibraryCallError("invalid_arguments")
    recorder = _Recorder(store)
    if path == "/v1/swarm":
        from ..native_swarm import SwarmError, execute

        try:
            recorder._write_json(execute("snapshot", {}, guard_home=store.guard_home), extra_headers=_NO_STORE)
        except SwarmError as error:
            recorder._write_json({"error": error.code}, status=503, extra_headers=_NO_STORE)
        except (OSError, ValueError, RuntimeError):
            recorder._write_json({"error": "swarm_unavailable"}, status=503)
    elif path in CONTEXT_ASSISTANCE_READ_PATHS:
        respond_context_assistance(recorder, CONTEXT_ASSISTANCE_READ_PATHS[path])
    elif path == "/v1/policy/cloud-exception-requests":
        _cloud_exception_request_list(recorder, store)
    elif not handle_workspace_assessment_get(recorder, path, query):
        raise LibraryCallError("invalid_arguments")
    return recorder.reply()


def _cloud_exception_request_list(recorder: _Recorder, store: GuardStore) -> None:
    from ..cloud_exception_requests import CloudExceptionRequestError, fetch_cloud_exception_requests

    try:
        result = fetch_cloud_exception_requests(store)
    except CloudExceptionRequestError as error:
        message = str(error).strip() or "Unable to load Guard Cloud exception requests."
        recorder._write_json({"error": "cloud_exception_request_list_failed", "message": message}, status=error.status)
        return
    except Exception as error:
        message = str(error).strip() or "Unable to load Guard Cloud exception requests."
        recorder._write_json({"error": "cloud_exception_request_list_failed", "message": message}, status=502)
        return
    recorder._write_json(result)


HANDLER_CALLS = {"route.handler_post": handler_post, "route.handler_get": handler_get}
