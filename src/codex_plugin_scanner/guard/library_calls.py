"""Guard library calls the native daemon makes through ``desktop library-call``.

The native daemon owns every route. Work that still lives in the Python
library (approval resolution, scope contracts, continuations) is reached
through one call per request: the daemon writes ``{"call": name, "args": {}}``
to standard input and reads ``{"ok": value}`` or ``{"error": {...}}`` back.
Errors carry the exception class name and the fields the route needs to
write its answer; the daemon owns status codes and response bodies.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .control_route_calls import ROUTE_CALLS
from .extension_control_host import EXTENSION_CONTROL_CALLS
from .routes.calls import HANDLER_CALLS
from .routes.catalog_calls import CATALOG_CALLS
from .routes.control_host import CONTROL_HOST_CALLS
from .routes.hook_host import HOOK_HOST_CALLS
from .routes.policy_sync_call import POLICY_SYNC_CALLS
from .routes.reads import READ_CALLS
from .routes.repair_calls import REPAIR_CALLS
from .routes.service_calls import SERVICE_CALLS
from .routes.settings_calls import SETTINGS_CALLS
from .store import GuardStore
from .workers.ticks import WORKER_CALLS

LibraryCall = Callable[[GuardStore, Mapping[str, Any]], object]


class LibraryCallError(Exception):
    """A call the registry cannot run: unknown name or malformed arguments."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _text(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _error_payload(error: BaseException) -> dict[str, object]:
    from .approval_gate import ApprovalGateError
    from .approval_scope_support import IneligibleApprovalScopeError, StaleApprovalScopeContractError
    from .approvals import ApprovalRequestNotFoundError
    from .native_approval_scope import ApprovalScopeUnavailableError
    from .trusted_local_tools import LocalToolGrantUnavailableError

    payload: dict[str, object] = {"type": type(error).__name__, "message": str(error), "kind": "unexpected"}
    if isinstance(error, ApprovalGateError):
        payload.update(kind="approval_gate", payload=error.to_payload(), status=error.status)
    elif isinstance(error, ApprovalRequestNotFoundError):
        payload["kind"] = "not_found"
    elif isinstance(error, StaleApprovalScopeContractError):
        payload.update(kind="stale_scope_contract", contract=error.contract.to_dict())
    elif isinstance(error, IneligibleApprovalScopeError):
        payload.update(
            kind="ineligible_scope",
            contract=error.contract.to_dict(),
            action=error.action,
            requested_scope=error.requested_scope,
        )
    elif isinstance(error, ApprovalScopeUnavailableError):
        payload["kind"] = "scope_unavailable"
    elif isinstance(error, LocalToolGrantUnavailableError):
        payload["kind"] = "local_tool_grant_unavailable"
    elif isinstance(error, LibraryCallError):
        payload["kind"] = "library_call"
    elif isinstance(error, ValueError):
        payload["kind"] = "value"
    return payload


def _optional_bool(value: object) -> bool:
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes", "on"}:
            return True
        if normalized in {"false", "0", "no", "off", ""}:
            return False
    raise ValueError("invalid boolean value")


def _persist_policy(payload: Mapping[str, object]) -> bool | None:
    """``persist_policy`` (or the older ``remember``): true or unset."""

    for key in ("persist_policy", "remember"):
        if key in payload:
            return True if _optional_bool(payload.get(key)) else None
    return None


def _idempotent_body(request: dict[str, object], selection: Any) -> dict[str, object]:
    from .approval_scope_support import request_scope_contract_payload

    return {
        "resolved": True,
        "idempotent": True,
        "resolved_request": request,
        "requested_scope": selection.requested_scope,
        "applied_scope": selection.applied_scope,
        **request_scope_contract_payload(request),
    }


def _select(store: GuardStore, request: dict[str, object], args: Mapping[str, Any]) -> Any:
    from .approval_scope_selection import resolve_request_scope_selection

    return resolve_request_scope_selection(
        request,
        action=args["action"],
        requested_scope=args["scope"],
        contract_version=_text(args.get("scope_contract_version")),
        contract_digest=_text(args.get("scope_contract_digest")),
        guard_home=store.guard_home,
    )


def _resolved_replay(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """The answer for a request another caller resolved first."""

    request = store.get_approval_request(args["request_id"])
    if isinstance(request, dict):
        selection = _select(store, request, args)
        if request.get("resolution_action") == args["action"] and request.get("resolution_scope") == (
            selection.applied_scope
        ):
            return {"idempotent": _idempotent_body(request, selection)}
    return {"already_resolved": True}


def _approval_resolve(store: GuardStore, args: Mapping[str, Any]) -> object:
    """Resolve one pending request the way the approve and block routes do.

    Returns ``{"idempotent": body}`` for a repeat of the decision already
    recorded, ``{"already_resolved": true}`` for a different one, or
    ``{"updated": result}`` with the continuation applied.
    """

    from .approval_gate import input_from_mapping
    from .approvals import ApprovalRequestAlreadyResolvedError, apply_approval_resolution
    from .continuation_runtime_local import apply_local_approval_continuation

    request_id = args["request_id"]
    action = args["action"]
    payload = args.get("payload")
    if not isinstance(request_id, str) or action not in {"allow", "block"} or not isinstance(payload, dict):
        raise LibraryCallError("invalid_arguments")
    existing = store.get_approval_request(request_id)
    if isinstance(existing, dict):
        selection = _select(store, existing, args)
        if existing.get("status") != "pending":
            if existing.get("resolution_action") == action and existing.get("resolution_scope") == (
                selection.applied_scope
            ):
                return {"idempotent": _idempotent_body(existing, selection)}
            return _resolved_replay(store, args)
    persist_policy = _persist_policy(payload)
    try:
        updated = apply_approval_resolution(
            store=store,
            request_id=request_id,
            action=action,
            scope=args["scope"],
            workspace=_text(payload.get("workspace")),
            reason=_text(payload.get("reason")),
            return_queue_result=True,
            resolve_scope_matches=bool(args.get("resolve_scope_matches", True)),
            approval_gate_input=input_from_mapping(payload),
            persist_policy=persist_policy,
            scope_contract_version=_text(args.get("scope_contract_version")),
            scope_contract_digest=_text(args.get("scope_contract_digest")),
            mcp_grant_target=payload.get("mcp_grant_target"),
            mcp_grant_duration=payload.get("mcp_grant_duration"),
            local_tool_grant_target=payload.get("local_tool_grant_target"),
            local_tool_grant_duration=payload.get("local_tool_grant_duration"),
        )
    except ApprovalRequestAlreadyResolvedError:
        return _resolved_replay(store, args)
    item = updated.get("item")
    item_harness = str(item.get("harness", "")) if isinstance(item, dict) else ""
    store.add_event(
        "approval_resolved",
        {"request_id": request_id, "action": action, "scope": args["scope"], "harness": item_harness},
        _now(),
    )
    harness = item_harness or str(updated.get("harness", ""))
    copy_table = args.get("copy")
    copy = copy_table.get(harness) if isinstance(copy_table, dict) else None
    if not isinstance(copy, dict):
        copy = copy_table.get("") if isinstance(copy_table, dict) else None
    if not isinstance(copy, dict) or not all(isinstance(copy.get(key), str) for key in ("title", "body")):
        raise LibraryCallError("invalid_arguments")
    updated, copy = apply_local_approval_continuation(
        store=store,
        updated=updated,
        request_id=request_id,
        action=action,
        harness=harness,
        copy={"title": copy["title"], "body": copy["body"]},
        now=_now,
    )
    updated["copy"] = copy
    updated["retry_hint"] = copy["body"]
    return {"updated": updated}


REGISTRY: dict[str, LibraryCall] = {
    "approval.resolve": _approval_resolve,
    **ROUTE_CALLS,
    **HANDLER_CALLS,
    **SERVICE_CALLS,
    **SETTINGS_CALLS,
    **POLICY_SYNC_CALLS,
    **CONTROL_HOST_CALLS,
    **HOOK_HOST_CALLS,
    **READ_CALLS,
    **REPAIR_CALLS,
    **WORKER_CALLS,
    **EXTENSION_CONTROL_CALLS,
    **CATALOG_CALLS,
}


def run_library_call(guard_home: Path, request: bytes) -> dict[str, object]:
    """Run the call ``request`` names and encode its result or error."""

    try:
        decoded = json.loads(request.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"error": {"type": "LibraryCallError", "message": "invalid_request", "kind": "library_call"}}
    if not isinstance(decoded, dict):
        return {"error": {"type": "LibraryCallError", "message": "invalid_request", "kind": "library_call"}}
    name = decoded.get("call")
    call = REGISTRY.get(name) if isinstance(name, str) else None
    args = decoded.get("args")
    if call is None or not isinstance(args, dict):
        return {"error": {"type": "LibraryCallError", "message": "unknown_call", "kind": "library_call"}}
    try:
        return {"ok": call(GuardStore(guard_home), args)}
    except KeyError:
        return {"error": {"type": "LibraryCallError", "message": "invalid_arguments", "kind": "library_call"}}
    except Exception as error:
        return {"error": _error_payload(error)}


__all__ = ["REGISTRY", "LibraryCallError", "run_library_call"]
