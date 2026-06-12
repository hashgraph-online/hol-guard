"""Guard CLI helper definitions."""

# fmt: off
# ruff: noqa: F403, F405, I001

from __future__ import annotations

from ._commands_shared import *
from .commands_parser_helpers import *
from ..adapters.kimi_hooks import normalize_kimi_prompt

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
        if policy_action in {"block", "sandbox-required", "require-reapproval"} and not additional_context:
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
            if policy_action == "require-reapproval":
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
    if event_name == "PostToolUse" and policy_action in {"block", "sandbox-required", "require-reapproval"}:
        payload["decision"] = "block"
        payload["reason"] = reason
        payload["continue"] = False
        payload["stopReason"] = reason
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
    _write_json_line(payload, output_stream=output_stream)

def _emit_native_hook_block_stderr(reason: str) -> None:
    print(reason, file=sys.stderr)

def _emit_native_hook_notification_stderr(reason: str) -> None:
    print(reason, file=sys.stderr)

def _native_hook_permission_decision(policy_action: str, *, harness: str) -> str | None:
    canonical = _canonical_harness_name(harness)
    if policy_action in {"block", "sandbox-required"}:
        return "deny"
    if policy_action == "require-reapproval":
        if canonical in {"codex", "kimi"}:
            return "deny"
        return "ask"
    if canonical == "codex":
        return None
    return "allow"

def _copilot_hook_permission_decision(policy_action: str) -> str:
    if policy_action in {"block", "sandbox-required", "require-reapproval"}:
        return "deny"
    return "allow"

def _headless_approval_resolver(
    *,
    args: argparse.Namespace,
    context: HarnessContext,
    store: GuardStore,
    config,
):
    should_wait_for_approvals = not bool(getattr(args, "json", False))

    def resolve(detection, payload):
        managed_install = _managed_install_for(store, args.harness)
        approval_flow = approval_prompt_flow(args.harness, managed_install=managed_install)
        approval_center_url = ensure_guard_daemon(context.guard_home)
        try:
            daemon_client = load_guard_surface_daemon_client(context.guard_home)
        except RuntimeError:
            queued = queue_blocked_approvals(
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
                resolved_items = [item for item in wait_result.get("items", []) if isinstance(item, dict)]
                payload["blocked"] = any(str(item.get("resolution_action")) == "block" for item in resolved_items)
                if not payload["blocked"]:
                    payload["blocked"] = False
                    payload["review_hint"] = "Approval received. Guard is resuming the harness launch."
            else:
                payload["review_hint"] = (
                    f"Approval is still pending in the Guard approval center at {approval_center_url}. Resolve request "
                    f"{', '.join(str(item) for item in wait_result.get('pending_request_ids', []))}."
                )
            return payload
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
        )
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
            resolved_items = [item for item in wait_result.get("items", []) if isinstance(item, dict)]
            payload["blocked"] = any(str(item.get("resolution_action")) == "block" for item in resolved_items)
            if not payload["blocked"]:
                payload["blocked"] = False
                daemon_client.update_operation_status(
                    operation_id=str(operation["operation_id"]),
                    status="completed",
                )
                payload["review_hint"] = "Approval received. Guard is resuming the harness launch."
            else:
                daemon_client.update_operation_status(
                    operation_id=str(operation["operation_id"]),
                    status="blocked",
                )
        else:
            daemon_client.update_operation_status(
                operation_id=str(operation["operation_id"]),
                status="waiting_on_approval",
                approval_request_ids=[str(item["request_id"]) for item in queued if "request_id" in item],
            )
            payload["review_hint"] = (
                f"Approval is still pending in the Guard approval center at {approval_center_url}. Resolve request "
                f"{', '.join(str(item) for item in wait_result.get('pending_request_ids', []))}."
            )
        return payload

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
        opener=webbrowser.open,
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
    if approval_flow.get("prompt_channel") == "native-fallback":
        return "never-auto-open"
    return config_policy

def _load_hook_payload(
    event_file: str | None,
    *,
    input_text: str | None = None,
    harness: str | None = None,
) -> dict[str, object]:
    if event_file:
        payload = json.loads(Path(event_file).read_text(encoding="utf-8"))
        return _normalize_hook_payload(payload, harness=harness) if isinstance(payload, dict) else {}
    raw = input_text.strip() if isinstance(input_text, str) else sys.stdin.read().strip()
    if not raw:
        return {}
    payload = json.loads(raw)
    return _normalize_hook_payload(payload, harness=harness) if isinstance(payload, dict) else {}

_ACTION_ENVELOPE_HARNESSES = frozenset(
    {"codex", "claude-code", "opencode", "copilot", "gemini", "hermes", "openclaw", "cursor"}
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

def _normalize_hook_payload(
    payload: dict[str, object],
    *,
    harness: str | None = None,
) -> dict[str, object]:
    normalized = dict(payload)
    for source_key, target_key in (
        ("artifactId", "artifact_id"),
        ("artifactHash", "artifact_hash"),
        ("artifactName", "artifact_name"),
        ("changedCapabilities", "changed_capabilities"),
        ("hookEventName", "hook_event_name"),
        ("hookName", "hook_name"),
        ("policyAction", "policy_action"),
        ("sourceScope", "source_scope"),
        ("toolName", "tool_name"),
        ("userOverride", "user_override"),
    ):
        if target_key not in normalized and source_key in payload:
            normalized[target_key] = payload[source_key]
    if "tool_name" not in normalized or "tool_input" not in normalized:
        tool_name, tool_input = _first_hook_tool_call(
            payload.get("toolCalls"),
            expected_tool_name=normalized.get("tool_name"),
        )
        if "tool_name" not in normalized and tool_name is not None:
            normalized["tool_name"] = tool_name
        if "tool_input" not in normalized and tool_input is not None:
            normalized["tool_input"] = tool_input
    arguments = _normalize_hook_arguments(
        normalized.get("tool_input"),
        normalized.get("arguments"),
        payload.get("toolArgs"),
        payload.get("toolInput"),
    )
    if arguments is not None:
        normalized["tool_input"] = arguments
        normalized["arguments"] = arguments
    if harness is not None and _canonical_harness_name(harness) == "kimi":
        normalized["prompt"] = normalize_kimi_prompt(normalized.get("prompt"))
    return normalized

def _normalize_hook_arguments(*values: object | None) -> object | None:
    for value in values:
        normalized = _normalize_hook_argument_value(value)
        if normalized is not None:
            return normalized
    return None

def _normalize_hook_argument_value(value: object | None) -> object | None:
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return None
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            return stripped
        if isinstance(parsed, (dict, list, str)):
            return parsed
        return stripped
    return value

def _first_hook_tool_call(
    value: object | None,
    *,
    expected_tool_name: object | None = None,
) -> tuple[str | None, object | None]:
    if not isinstance(value, list):
        return None, None
    normalized_expected_tool_name = expected_tool_name.strip() if isinstance(expected_tool_name, str) else None
    fallback_tool_call: tuple[str, object | None] | None = None
    for item in value:
        if not isinstance(item, dict):
            continue
        tool_name = item.get("name")
        tool_input = _normalize_hook_argument_value(item.get("args"))
        if isinstance(tool_name, str) and tool_name.strip():
            stripped_tool_name = tool_name.strip()
            if fallback_tool_call is None:
                fallback_tool_call = (stripped_tool_name, tool_input)
            if normalized_expected_tool_name is None or stripped_tool_name == normalized_expected_tool_name:
                return stripped_tool_name, tool_input
    if fallback_tool_call is not None:
        return fallback_tool_call
    return None, None

def _coalesce_string(*values: object | None) -> str:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "unknown-artifact"

__all__ = [
    "_ACTION_ENVELOPE_HARNESSES", "_action_envelope_json", "_approval_center_browser_url",
    "_approval_surface_policy_for_flow", "_browser_url_with_guard_params", "_coalesce_string",
    "_copilot_hook_permission_decision", "_emit_native_hook_block_stderr",
    "_emit_native_hook_notification_stderr", "_emit_native_hook_response", "_first_hook_tool_call",
    "_headless_approval_resolver", "_hook_action_envelope", "_load_hook_payload",
    "_native_hook_permission_decision", "_normalize_hook_argument_value", "_normalize_hook_arguments",
    "_normalize_hook_payload", "_open_approval_center", "_public_approval_center_url",
]
