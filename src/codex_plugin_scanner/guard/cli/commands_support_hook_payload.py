"""Guard CLI helper definitions."""

# pyright: reportImportCycles=false

# fmt: off
# ruff: noqa: E402, F403, F405, I001

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING


def _coalesce_string(*values: object | None) -> str:
    """Return the first non-empty display value during circular CLI imports."""

    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "unknown-artifact"


def _canonical_harness_name(value: str) -> str:
    """Resolve harness aliases lazily to avoid the CLI support import cycle."""

    from .commands_support_runtime_resolution import _canonical_harness_name as resolve

    return resolve(value)


def _managed_install_for(store: GuardStore, harness: str) -> dict[str, object] | None:
    """Resolve managed-install state lazily to avoid the CLI support import cycle."""

    from .commands_support_runtime_resolution import _managed_install_for as resolve

    return resolve(store, harness)


def _hook_event_name(payload: dict[str, object]) -> str | None:
    """Read hook event names lazily to avoid the CLI support import cycle."""

    from .commands_support_runtime_artifacts import _hook_event_name as resolve

    return resolve(payload)


def _write_json_line(payload: dict[str, object], *, output_stream: TextIO | None = None) -> None:
    """Resolve hook output lazily without reintroducing the prompt import cycle."""

    from .commands_support_prompts import _write_json_line as resolve

    resolve(payload, output_stream=output_stream)

if TYPE_CHECKING:
    from ..store import GuardStore
    from ._commands_shared import _GUARD_CLIENT_VERSION, _HOOK_DAEMON_UNREACHABLE_REASON_MARKER, _now
    from .commands_support_interaction import _attach_primary_approval_link, _preferred_approval_review_url
    from .commands_support_runtime_policy import _approval_delivery_payload, _localize_pending_approval_copy
    from .commands_support_runtime_artifacts import _optional_string


from ._commands_shared import *
from .commands_parser_helpers import *
from ..browser_opener import open_browser_url
from .commands_support_hook_payload_loader import (
    _first_hook_tool_call,
    _load_hook_payload as _load_hook_payload_impl,
    _normalize_hook_argument_value,
    _normalize_hook_arguments,
    _normalize_hook_payload,
)


def _load_hook_payload(
    event_file: str | None,
    *,
    input_text: str | None = None,
    harness: str | None = None,
    normalize: bool = True,
) -> dict[str, object]:
    """Keep the legacy CLI facade while the loader owns raw input handling."""

    payload = _load_hook_payload_impl(
        event_file,
        input_text=input_text,
        harness=harness,
        normalize=False,
    )
    if normalize:
        from ..runtime.hook_payload_reference import hydrate_hook_payload_reference
        payload = hydrate_hook_payload_reference(payload)
        return _normalize_hook_payload(payload, harness=harness)
    return payload

def _emit_native_hook_response(
    *,
    harness: str,
    policy_action: str,
    reason: str,
    event_name: str = "PreToolUse",
    additional_context: str | None = None,
    system_message: str | None = None,
    output_stream: TextIO | None = None,
) -> None:
    payload: dict[str, object] = {}
    if isinstance(system_message, str) and system_message.strip():
        payload["systemMessage"] = system_message.strip()
    if event_name == "UserPromptSubmit":
        if policy_action in {"review", "require-reapproval", "sandbox-required", "block"} and not additional_context:
            payload["decision"] = "block"
            payload["reason"] = reason
            if _canonical_harness_name(harness) == "codex":
                payload["continue"] = False
                payload["stopReason"] = reason
                payload["hookSpecificOutput"] = {
                    "hookEventName": event_name,
                    "additionalContext": reason,
                }
        elif additional_context:
            payload["hookSpecificOutput"] = {
                "hookEventName": event_name,
                "additionalContext": additional_context,
            }
        elif _canonical_harness_name(harness) in {"claude-code", "codex"}:
            payload["hookSpecificOutput"] = {"hookEventName": event_name}
        if payload:
            _write_json_line(payload, output_stream=output_stream)
        return
    if event_name in {"Notification", "PermissionRequest"}:
        if event_name == "PermissionRequest" and policy_action in {"block", "sandbox-required"}:
            decision: dict[str, object] = {
                "behavior": "deny",
                "message": additional_context or reason,
            }
            if _canonical_harness_name(harness) != "codex":
                decision["interrupt"] = False
            payload["hookSpecificOutput"] = {
                "hookEventName": event_name,
                "decision": decision,
            }
            _write_json_line(payload, output_stream=output_stream)
            return
        if event_name == "PermissionRequest" and _canonical_harness_name(harness) == "codex":
            if policy_action in {"review", "require-reapproval"}:
                payload["systemMessage"] = (
                    "HOL Guard is reviewing this Codex approval request. Codex will show its normal approval prompt; "
                    "choose allow only if you trust the exact tool action."
                )
            if payload:
                _write_json_line(payload, output_stream=output_stream)
            return
        if event_name == "PermissionRequest" and _canonical_harness_name(harness) == "claude-code":
            message = system_message or reason
            if message:
                payload["systemMessage"] = message
            if additional_context:
                payload["hookSpecificOutput"] = {
                    "hookEventName": event_name,
                    "additionalContext": additional_context,
                }
            elif message:
                payload["hookSpecificOutput"] = {"hookEventName": event_name}
            if payload:
                _write_json_line(payload, output_stream=output_stream)
            return
        if additional_context:
            payload["hookSpecificOutput"] = {
                "hookEventName": event_name,
                "additionalContext": additional_context,
            }
        if payload:
            _write_json_line(payload, output_stream=output_stream)
        return
    if event_name == "PostToolUse" and policy_action in {"review", "require-reapproval", "sandbox-required", "block"}:
        payload.update({"decision": "block", "reason": reason, "continue": True, "stopReason": reason})
        _write_json_line(payload, output_stream=output_stream)
        return
    permission_decision = _native_hook_permission_decision(policy_action, harness=harness)
    if harness == "codex" and event_name == "PreToolUse" and permission_decision is None:
        return
    hook_specific_output: dict[str, object] = {"hookEventName": event_name}
    if permission_decision is not None:
        hook_specific_output["permissionDecision"] = permission_decision
        if permission_decision != "allow" or _HOOK_DAEMON_UNREACHABLE_REASON_MARKER in reason.lower():
            hook_specific_output["permissionDecisionReason"] = reason
    payload["hookSpecificOutput"] = hook_specific_output
    _write_json_line(
        _hermes_native_or_payload(harness, policy_action, reason, payload),
        output_stream=output_stream,
    )

def _hermes_native_or_payload(
    harness: str,
    policy_action: str,
    reason: str,
    payload: dict[str, object],
) -> dict[str, object]:
    if _canonical_harness_name(harness) != "hermes":
        return payload
    from ..adapters.hermes_runtime_hooks import hermes_native_decision
    return hermes_native_decision(policy_action=policy_action, reason=reason)


def _emit_native_hook_block_stderr(reason: str) -> None:
    print(reason, file=sys.stderr)

def _emit_native_hook_notification_stderr(reason: str) -> None:
    print(reason, file=sys.stderr)

def _native_hook_permission_decision(policy_action: str, *, harness: str) -> str | None:
    canonical = _canonical_harness_name(harness)
    if policy_action in {"block", "sandbox-required"}:
        return "deny"
    if policy_action in {"review", "require-reapproval"}:
        if canonical in {"codex", "kimi", "grok", "zcode"}:
            return "deny"
        return "ask"
    if canonical == "codex":
        return None
    return "allow"

def _copilot_hook_permission_decision(policy_action: str) -> str:
    if policy_action in {"review", "require-reapproval", "sandbox-required", "block"}:
        return "deny"
    return "allow"


def _object_list(value: object | None) -> list[object]:
    if isinstance(value, list):
        return value
    return []


def _mapping_list(value: object | None) -> list[Mapping[str, object]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, Mapping)]

def _apply_approval_wait_fields(
    payload: dict[str, object],
    *,
    args: argparse.Namespace,
    store: GuardStore,
    config: GuardConfig,
    queued: list[dict[str, object]],
    approval_flow: dict[str, object],
    managed_install: dict[str, object] | None,
    should_wait_for_approvals: bool,
    approval_center_url: str,
    on_operation_status: Callable[[str], None] | None = None,
) -> dict[str, object]:
    """Populate approval delivery/wait fields and review hints for queued approvals."""

    payload["approval_delivery"] = _approval_delivery_payload(args.harness, managed_install=managed_install)
    _localize_pending_approval_copy(payload, harness=args.harness)
    if str(approval_flow["tier"]) != "native-or-center" or not should_wait_for_approvals:
        payload["approval_wait"] = {
            "resolved": False,
            "pending_request_ids": [str(item["request_id"]) for item in queued if "request_id" in item],
            "items": [],
        }
        return payload
    wait_result = wait_for_approval_requests(
        store=store,
        request_ids=[str(item["request_id"]) for item in queued if "request_id" in item],
        timeout_seconds=config.approval_wait_timeout_seconds,
    )
    payload["approval_wait"] = wait_result
    if bool(wait_result.get("resolved")):
        resolved_items = _mapping_list(wait_result.get("items"))
        payload["blocked"] = any(str(item.get("resolution_action")) == "block" for item in resolved_items)
        if on_operation_status is not None:
            with suppress(RuntimeError):
                on_operation_status("blocked" if bool(payload["blocked"]) else "completed")
        if not bool(payload["blocked"]):
            payload["review_hint"] = "Approval received. Guard is resuming the harness launch."
    else:
        pending_request_ids = _object_list(wait_result.get("pending_request_ids"))
        if on_operation_status is not None:
            with suppress(RuntimeError):
                on_operation_status("waiting_on_approval")
        payload["review_hint"] = (
            f"Approval is still pending in the Guard approval center at {approval_center_url}. Resolve request "
            f"{', '.join(str(item) for item in pending_request_ids)}."
        )
    return payload


def _apply_blocked_operation_payload(
    response_payload: dict[str, object],
    blocked_operation: Mapping[str, object],
    *,
    args: argparse.Namespace,
    approval_center_url: str,
) -> list[dict[str, object]]:
    """Fold a queued daemon operation and primary approval link into a hook response."""

    operation = blocked_operation.get("operation")
    if not isinstance(operation, dict):
        operation = {}
    queued = blocked_operation.get("approval_requests")
    if not isinstance(queued, list):
        queued = []
    operation_id = _optional_string(operation.get("operation_id"))
    if operation_id is not None:
        response_payload["operation_id"] = operation_id
    response_payload["operation"] = operation
    approval_request_ids = operation.get("approval_request_ids")
    if isinstance(approval_request_ids, list):
        response_payload["approval_request_ids"] = approval_request_ids
    response_payload["approval_requests"] = queued
    _attach_primary_approval_link(
        response_payload,
        harness=_optional_string(args.harness) or args.harness,
        approval_center_url=approval_center_url,
    )
    return queued


def _headless_approval_resolver(
    *,
    args: argparse.Namespace,
    context: HarnessContext,
    store: GuardStore,
    config,
):
    should_wait_for_approvals = not bool(getattr(args, "json", False))

    def resolve(detection, payload):
        if evaluation_has_terminal_policy_action(payload):
            return payload
        managed_install = _managed_install_for(store, args.harness)
        approval_flow = approval_prompt_flow(args.harness, managed_install=managed_install)
        approval_center_url = schedule_guard_daemon_ensure(
            context.guard_home,
            home_dir=context.home_dir,
        )

        def apply_approval_wait(
            payload: dict[str, object],
            *,
            queued: list[dict[str, object]],
            on_operation_status: Callable[[str], None] | None = None,
        ) -> dict[str, object]:
            return _apply_approval_wait_fields(
                payload,
                args=args,
                store=store,
                config=config,
                queued=queued,
                approval_flow=approval_flow,
                managed_install=managed_install,
                should_wait_for_approvals=should_wait_for_approvals,
                approval_center_url=approval_center_url,
                on_operation_status=on_operation_status,
            )

        def resolve_from_local_queue():
            queued = queue_blocked_approvals(
                redaction_level=config.receipt_redaction_level,
                detection=detection,
                evaluation=payload,
                store=store,
                approval_center_url=approval_center_url,
                now=_now(),
            )
            payload["approval_requests"] = queued
            _attach_primary_approval_link(
                payload,
                harness=args.harness,
                approval_center_url=approval_center_url,
            )
            payload["approval_center_url"] = approval_center_url
            payload["review_hint"] = approval_center_hint(
                context=context,
                harness=args.harness,
                approval_center_url=approval_center_url,
                queued=queued,
                review_url=_preferred_approval_review_url(payload, harness=args.harness),
            )
            return apply_approval_wait(payload, queued=queued)

        try:
            daemon_client = load_guard_surface_daemon_client(context.guard_home)
        except RuntimeError:
            return resolve_from_local_queue()
        try:
            session = daemon_client.start_session(
                harness=args.harness,
                surface="cli",
                workspace=str(context.workspace_dir) if context.workspace_dir is not None else None,
                client_name="hol-guard",
                client_title="HOL Guard CLI",
                client_version=_GUARD_CLIENT_VERSION,
                capabilities=["approval-resolution", "receipt-view"],
            )
            blocked_operation = daemon_client.queue_blocked_operation(
                session_id=str(session["session_id"]),
                operation_type="run",
                harness=args.harness,
                metadata={"command": f"hol-guard run {args.harness}"},
                detection=detection.to_dict(),
                evaluation=payload,
                approval_center_url=approval_center_url,
                approval_surface_policy=_approval_surface_policy_for_flow(
                    config.approval_surface_policy,
                    approval_flow,
                ),
                open_key=None,
                redaction_level=config.receipt_redaction_level,
            )
        except RuntimeError:
            return resolve_from_local_queue()
        operation = blocked_operation["operation"] if isinstance(blocked_operation.get("operation"), dict) else {}
        queued = (
            blocked_operation["approval_requests"]
            if isinstance(blocked_operation.get("approval_requests"), list)
            else []
        )
        payload["session_id"] = str(session["session_id"])
        payload["operation_id"] = str(operation["operation_id"])
        payload["approval_requests"] = queued
        _attach_primary_approval_link(
            payload,
            harness=args.harness,
            approval_center_url=approval_center_url,
        )
        payload["approval_center_url"] = approval_center_url
        payload["review_hint"] = approval_center_hint(
            context=context,
            harness=args.harness,
            approval_center_url=approval_center_url,
            queued=queued,
            managed_install=managed_install,
            review_url=_preferred_approval_review_url(payload, harness=args.harness),
        )
        def _record_operation_status(status: str) -> None:
            extra_kwargs: dict[str, object] = {}
            if status == "waiting_on_approval":
                extra_kwargs["approval_request_ids"] = [
                    str(item["request_id"]) for item in queued if "request_id" in item
                ]
            daemon_client.update_operation_status(
                operation_id=str(operation["operation_id"]),
                status=status,
                **extra_kwargs,
            )

        return apply_approval_wait(payload, queued=queued, on_operation_status=_record_operation_status)

    return resolve

def _open_approval_center(
    approval_center_url: str,
    *,
    store: GuardStore,
    config: GuardConfig,
    open_key: str | None = None,
    force_open: bool = False,
) -> dict[str, object]:
    surface_runtime = GuardSurfaceRuntime(store)
    auth_token = load_guard_daemon_auth_token(store.guard_home)
    browser_url = _approval_center_browser_url(approval_center_url, auth_token)
    open_result = surface_runtime.ensure_surface(
        surface="approval-center",
        approval_center_url=approval_center_url,
        browser_url=browser_url,
        approval_surface_policy=config.approval_surface_policy,
        open_key=open_key or approval_center_url,
        force_open=force_open,
        opener=open_browser_url,
    )
    open_result["browser_url"] = _public_approval_center_url(browser_url) or approval_center_url
    return open_result

def _approval_center_browser_url(approval_center_url: str, auth_token: str | None) -> str | None:
    if auth_token is None:
        return None
    return _browser_url_with_guard_params(approval_center_url, auth_token=auth_token, surface="approval-center")

def _browser_url_with_guard_params(
    url: str,
    *,
    auth_token: str,
    surface: str,
    daemon_url: str | None = None,
) -> str:
    parsed = urllib.parse.urlparse(url)
    fragment_pairs = [
        (key, value)
        for key, value in urllib.parse.parse_qsl(parsed.fragment, keep_blank_values=True)
        if key not in {"guard-token", "guardDaemon"}
    ]
    if daemon_url:
        fragment_pairs.append(("guardDaemon", daemon_url))
    fragment_pairs.append(
        (
            "guard-token",
            build_local_dashboard_session_token(auth_token=auth_token, surface=surface),
        )
    )
    return urllib.parse.urlunparse(parsed._replace(fragment=urllib.parse.urlencode(fragment_pairs)))

def _public_approval_center_url(browser_url: str | None) -> str | None:
    if browser_url is None:
        return None
    parsed = urllib.parse.urlparse(browser_url)
    fragment_pairs = [
        (key, value)
        for key, value in urllib.parse.parse_qsl(parsed.fragment, keep_blank_values=True)
        if key != "guard-token"
    ]
    return urllib.parse.urlunparse(parsed._replace(fragment=urllib.parse.urlencode(fragment_pairs)))

def _approval_surface_policy_for_flow(config_policy: str, approval_flow: dict[str, object]) -> str:
    if approval_flow.get("tier") != "approval-center":
        return "notify-only"
    if approval_flow.get("auto_open_browser") is False:
        return "never-auto-open"
    return config_policy

_ACTION_ENVELOPE_HARNESSES = frozenset(
    {
        "codex", "cline", "claude-code", "opencode", "copilot", "gemini", "hermes",
        "openclaw", "cursor", "grok", "kimi", "pi", "omp", "zcode",
    }
)

def _hook_action_envelope(
    *,
    harness: str,
    payload: dict[str, object],
    home_dir: Path,
    workspace: Path | None,
) -> GuardActionEnvelope | None:
    canonical_harness = _canonical_harness_name(harness)
    if canonical_harness not in _ACTION_ENVELOPE_HARNESSES:
        return None
    return normalize_harness_payload(
        canonical_harness,
        _hook_event_name(payload) or "PreToolUse",
        payload,
        workspace=workspace,
        home_dir=home_dir,
    )

def _action_envelope_json(envelope: GuardActionEnvelope | None) -> dict[str, object] | None:
    return envelope.to_dict() if envelope is not None else None

__all__ = [
    "_ACTION_ENVELOPE_HARNESSES", "_action_envelope_json", "_apply_approval_wait_fields",
    "_apply_blocked_operation_payload", "_approval_center_browser_url",
    "_approval_surface_policy_for_flow", "_browser_url_with_guard_params", "_coalesce_string",
    "_copilot_hook_permission_decision", "_emit_native_hook_block_stderr",
    "_emit_native_hook_notification_stderr", "_emit_native_hook_response", "_first_hook_tool_call",
    "_headless_approval_resolver", "_hook_action_envelope", "_load_hook_payload",
    "_native_hook_permission_decision", "_normalize_hook_argument_value", "_normalize_hook_arguments",
    "_normalize_hook_payload", "_open_approval_center", "_public_approval_center_url",
]
