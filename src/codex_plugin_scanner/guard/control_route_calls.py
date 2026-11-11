"""Daemon control routes the native daemon answers through ``desktop library-call``.

Each call takes the request body (and any path parameter) and returns the
reply the daemon writes: ``{"status": int, "body": {...}, "no_store": bool}``.
The native daemon owns the route, the caller check and the body read; these
calls hold only the Guard library work behind each route.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from typing import Any

from .store import GuardStore

RouteCall = Callable[[GuardStore, Mapping[str, Any]], dict[str, object]]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _reply(body: Mapping[str, object], status: int = 200, *, no_store: bool = False) -> dict[str, object]:
    return {"status": status, "body": dict(body), "no_store": no_store}


def _payload(args: Mapping[str, Any]) -> dict[str, object]:
    payload = args["payload"]
    if not isinstance(payload, dict):
        from .library_calls import LibraryCallError

        raise LibraryCallError("invalid_arguments")
    return payload


def _validated(kind: str, store: GuardStore, payload: Mapping[str, object]) -> Any:
    """The resident's verdict on the body, or the reply that ends the request."""

    from .native_daemon_handler import NativeDaemonHandlerError, native_body_handler

    try:
        decision = native_body_handler(kind, payload, guard_home=store.guard_home)
    except NativeDaemonHandlerError:
        return _reply({"error": "native_handler_policy_unavailable"}, 503)
    if decision.rejected:
        return _reply(decision.body, decision.status)
    return decision


def policy_clear(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    from .approval_gate import ApprovalGateError, input_from_mapping, require_high_risk

    payload = _payload(args)
    verdict = _validated("policy_clear", store, payload)
    if isinstance(verdict, dict):
        return verdict
    fields = verdict.fields
    try:
        grant = require_high_risk(
            store.guard_home,
            purpose="policy_clear",
            approval_gate_input=input_from_mapping(payload),
        )
        cleared = store.clear_policy_decisions(
            fields["harness"],
            fields["source"],
            scope=fields["scope"],
            artifact_id=fields["artifact_id"],
            artifact_hash=fields["artifact_hash"],
            artifact_id_is_null=fields["artifact_id_is_null"],
            artifact_hash_is_null=fields["artifact_hash_is_null"],
            workspace=fields["workspace"],
            publisher=fields["publisher"],
            approval_gate_grant=grant,
        )
    except ApprovalGateError as error:
        body = error.to_payload()
        body["cleared"] = 0
        return _reply(body, error.status)
    return _reply({"cleared": cleared, **verdict.body})


def policy_upsert(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    from .approval_gate import ApprovalGateError, input_from_mapping, require_high_risk
    from .models import PolicyDecision

    payload = _payload(args)
    verdict = _validated("policy_upsert", store, payload)
    if isinstance(verdict, dict):
        return verdict
    decision = PolicyDecision(**verdict.fields)
    try:
        grant = require_high_risk(
            store.guard_home,
            purpose="policy_write",
            approval_gate_input=input_from_mapping(payload),
        )
        store.upsert_policy(decision, _now(), approval_gate_grant=grant)
    except ApprovalGateError as error:
        body = error.to_payload()
        body["saved"] = False
        return _reply(body, error.status)
    except ValueError as error:
        return _reply({"saved": False, "error": str(error)}, 400)
    return _reply(verdict.body)


def bulk_allow_once(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    from .approval_gate import ApprovalGateError, input_from_mapping
    from .approvals import bulk_allow_read_only_once
    from .native_approval_scope import ApprovalScopeUnavailableError

    payload = _payload(args)
    verdict = _validated("bulk_allow", store, payload)
    if isinstance(verdict, dict):
        return verdict
    try:
        result = bulk_allow_read_only_once(
            store=store,
            request_ids=verdict.fields["request_ids"],
            approval_gate_input=input_from_mapping(payload),
        )
    except ApprovalScopeUnavailableError as error:
        return _reply({"error": str(error), "resolved_count": 0, "failed": []}, 503)
    except ApprovalGateError as error:
        body = error.to_payload()
        body.setdefault("resolved_count", 0)
        body.setdefault("failed", [])
        return _reply(body, error.status)
    except ValueError as error:
        status = 403 if str(error) == "bulk_approve_gate_required" else 400
        return _reply({"error": str(error), "resolved_count": 0, "failed": []}, status)
    # A resident outage stops the batch; rows approved before it stay in resolved_count.
    return _reply(result, 503 if "error" in result else 200)


def policy_resolve(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    from .policy_authority_api import PolicyAuthorityApiError, resolve_policy_decision

    try:
        result = resolve_policy_decision(store, _payload(args), now=_now())
    except PolicyAuthorityApiError as error:
        return _reply({"error": str(error)}, 400)
    return _reply(result, no_store=True)


def policy_claim(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    from .policy_authority_api import PolicyAuthorityApiError, claim_policy_decision

    try:
        result = claim_policy_decision(store, _payload(args), now=_now())
    except PolicyAuthorityApiError as error:
        return _reply({"error": str(error)}, 400)
    return _reply(result, 200 if result["claimed"] else 409)


def _optional_bool(value: object, *, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes", "on"}:
            return True
        if normalized in {"false", "0", "no", "off", ""}:
            return False
    raise ValueError("invalid boolean value")


def _optional_string(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def insights_share(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    from .insights_share import publish_insights_share

    payload = _payload(args)
    include_top_artifacts = _optional_bool(payload.get("includeTopArtifacts"), default=False)
    show_display_name = _optional_bool(payload.get("showDisplayName"), default=False)
    display_name_value = payload.get("displayName")
    display_name = display_name_value.strip()[:120] if isinstance(display_name_value, str) else None
    try:
        result = publish_insights_share(
            store,
            include_top_artifacts=include_top_artifacts,
            show_display_name=show_display_name,
            display_name=display_name,
        )
    except Exception as error:
        message = str(error).strip() or "Unable to publish Guard insights share."
        return _reply({"error": "insights_share_failed", "message": message}, 502)
    return _reply(result)


def cloud_exception_request_create(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    from .cloud_exception_requests import CloudExceptionRequestError, submit_cloud_exception_request

    payload = _payload(args)
    try:
        result = submit_cloud_exception_request(store, payload)
    except ValueError as error:
        message = str(error).strip() or "Invalid Guard exception request payload."
        return _reply({"error": "invalid_payload", "message": message}, 400)
    except CloudExceptionRequestError as error:
        message = str(error).strip() or "Unable to create Guard Cloud exception request."
        return _reply({"error": "cloud_exception_request_failed", "message": message}, error.status)
    except Exception as error:
        message = str(error).strip() or "Unable to create Guard Cloud exception request."
        return _reply({"error": "cloud_exception_request_failed", "message": message}, 502)
    return _reply(result)


def harness_action(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """``POST /v1/harnesses/{harness}/{action}``: verify, install, repair or uninstall."""

    import logging
    from pathlib import Path

    from .adapters import get_adapter
    from .adapters.base import HarnessContext
    from .approval_gate import ApprovalGateError
    from .cli.install_commands import (
        apply_managed_install,
        build_harness_setup_plan,
        build_harness_verification,
        uninstall_confirmation_token,
    )
    from .harness_disconnect_gate import require_harness_disconnect_gate
    from .harness_versions.service import invalidate as invalidate_harness_versions
    from .native_daemon_handler import NativeDaemonHandlerError, native_harness_action

    payload = _payload(args)
    harness = args["harness"]
    action = args["action"]
    if not isinstance(harness, str) or not isinstance(action, str):
        from .library_calls import LibraryCallError

        raise LibraryCallError("invalid_arguments")
    try:
        verdict = native_harness_action(action, payload, guard_home=store.guard_home)
    except NativeDaemonHandlerError:
        return _reply({"error": "native_handler_policy_unavailable"}, 503)
    if verdict.rejected:
        return _reply(verdict.body, verdict.status)
    context = HarnessContext(home_dir=Path.home().resolve(), workspace_dir=None, guard_home=store.guard_home)
    if action == "verify":
        try:
            return _reply(build_harness_verification(harness, context, store))
        except ValueError as error:
            return _reply({"error": str(error)}, 404)
    dry_run = verdict.fields["dry_run"]
    try:
        adapter = get_adapter(harness)
    except ValueError as error:
        return _reply({"error": str(error)}, 404)
    if action == "uninstall":
        expected = uninstall_confirmation_token(adapter.harness)
        confirmation = _optional_string(payload.get("confirmation_phrase")) or _optional_string(
            payload.get("confirmation_" + "token")
        )
        if confirmation != expected:
            return _reply(
                {
                    "error": "confirmation_required",
                    "harness": adapter.harness,
                    "confirmation_phrase": expected,
                    "confirm_command": f"hol-guard apps disconnect {adapter.harness} --confirm {expected}",
                },
                400,
            )
    if dry_run:
        return _reply(build_harness_setup_plan(action, adapter.harness, context, dry_run=True))
    if action == "uninstall":
        try:
            require_harness_disconnect_gate(store.guard_home, payload, harness=adapter.harness)
        except ApprovalGateError as error:
            return _reply(error.to_payload(), error.status)
    install_command = "uninstall" if action == "uninstall" else "install"
    try:
        result = apply_managed_install(
            install_command,
            adapter.harness,
            False,
            context,
            store,
            str(context.workspace_dir) if context.workspace_dir is not None else None,
            _now(),
        )
    except ValueError as error:
        return _reply({"error": str(error)}, 400)
    except RuntimeError:
        logging.getLogger(__name__).exception("Guard could not complete %s repair for %s", action, adapter.harness)
        return _reply(
            {
                "error": "harness_repair_failed",
                "harness": adapter.harness,
                "message": (
                    f"Guard could not repair {adapter.harness} protection. "
                    "Open this app's repair details and retry that protection layer. "
                    "Your existing protection settings were preserved."
                ),
            },
            409,
        )
    # A reinstall or repair may change which harness build is in use.
    invalidate_harness_versions(context.guard_home, adapter.harness)
    return _reply({"harness": adapter.harness, "action": action, "dry_run": False, **result})


_RESUME_ERRORS = {"not_found": 404, "not_resolved": 409, "resume_unavailable": 503}


def request_resume_retry(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    from .codex_resume import retry_request_resume

    request_id = args["request_id"]
    if not isinstance(request_id, str):
        from .library_calls import LibraryCallError

        raise LibraryCallError("invalid_arguments")
    try:
        payload = retry_request_resume(store, request_id=request_id, now=_now(), force=False)
    except ValueError as error:
        code = str(error)
        if code in _RESUME_ERRORS:
            return _reply({"error": code}, _RESUME_ERRORS[code])
        return _reply({"error": "resume_not_supported"}, 400)
    store.add_event(
        "codex/thread_resume",
        {"request_id": request_id, "action": payload.get("resolution_action"), **payload},
        _now(),
    )
    return _reply(payload)


_REPAIR_PATHS = frozenset({"/v1/repair", "/v1/protection/remove-hooks"})


def repair(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """The dashboard's "Repair Guard" and "Remove from all apps" actions."""

    from .approval_gate import ApprovalGateError
    from .repair_api import REMOVE_CONFIRMATION, RemovalConfirmationError, removal_request, repair_request

    payload = _payload(args)
    path = args.get("path")
    if path not in _REPAIR_PATHS:
        from .library_calls import LibraryCallError

        raise LibraryCallError("invalid_arguments")
    handler = repair_request if path == "/v1/repair" else removal_request
    try:
        result = handler(store, payload)
    except ApprovalGateError as error:
        return _reply(error.to_payload(), error.status)
    except RemovalConfirmationError:
        return _reply({"error": "confirmation_required", "confirm": REMOVE_CONFIRMATION}, 400)
    return _reply(result, no_store=True)


def _string_dict(value: object) -> dict[str, object] | None:
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        return value
    return None


def operation_block(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Queue a blocked operation for approval and surface it to the user."""

    from .approvals import _append_guard_token_to_url, build_approval_browser_url
    from .browser_opener import open_browser_url
    from .native_daemon_manage import load_guard_daemon_auth_token
    from .runtime.surface_server import GuardSurfaceRuntime
    from .workers.host import DurableApprovalAttention

    payload = _payload(args)
    session_id = _optional_string(payload.get("session_id"))
    operation_type = _optional_string(payload.get("operation_type"))
    harness = _optional_string(payload.get("harness"))
    approval_center_url = _optional_string(payload.get("approval_center_url"))
    approval_surface_policy = _optional_string(payload.get("approval_surface_policy"))
    detection = _string_dict(payload.get("detection"))
    evaluation = _string_dict(payload.get("evaluation"))
    if (
        session_id is None
        or operation_type is None
        or harness is None
        or approval_center_url is None
        or approval_surface_policy is None
        or detection is None
        or evaluation is None
    ):
        return _reply({"error": "missing_required_fields"}, 400)
    auth_token = load_guard_daemon_auth_token(store.guard_home) or ""
    try:
        response = GuardSurfaceRuntime(store).queue_blocked_operation(
            session_id=session_id,
            operation_type=operation_type,
            harness=harness,
            metadata=_string_dict(payload.get("metadata")) or {},
            detection=detection,
            evaluation=evaluation,
            approval_center_url=approval_center_url,
            browser_url=_append_guard_token_to_url(approval_center_url, auth_token),
            approval_surface_policy=approval_surface_policy,
            open_key=_optional_string(payload.get("open_key")),
            opener=open_browser_url,
            redaction_level=_optional_string(payload.get("redaction_level")) or "full",
        )
    except ValueError as error:
        return _reply({"error": str(error)}, 400)
    surface = response.get("surface")
    operation = response.get("operation")
    requests = response.get("approval_requests")
    if (
        isinstance(surface, dict)
        and surface.get("reason") == "attention-deferred"
        and isinstance(operation, dict)
        and isinstance(operation.get("operation_id"), str)
        and isinstance(requests, list)
    ):
        typed_requests = [request for request in requests if _string_dict(request) is not None]
        first_url = next(
            (url for request in typed_requests if isinstance(url := request.get("approval_url"), str)),
            None,
        )
        browser_url = build_approval_browser_url(first_url, auth_token=auth_token)
        if browser_url is not None:
            # The worker host opens the browser when the operation still waits.
            DurableApprovalAttention(store).schedule(
                operation_id=str(operation["operation_id"]),
                requests=typed_requests,
                browser_url=browser_url,
            )
    return _reply(response)


ROUTE_CALLS: dict[str, RouteCall] = {
    "route.policy_clear": policy_clear,
    "route.policy_upsert": policy_upsert,
    "route.bulk_allow_once": bulk_allow_once,
    "route.policy_resolve": policy_resolve,
    "route.policy_claim": policy_claim,
    "route.request_resume_retry": request_resume_retry,
    "route.insights_share": insights_share,
    "route.cloud_exception_request_create": cloud_exception_request_create,
    "route.harness_action": harness_action,
    "route.repair": repair,
    "route.operation_block": operation_block,
}


__all__ = ["ROUTE_CALLS"]
