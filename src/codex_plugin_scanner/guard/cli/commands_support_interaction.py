"""Guard CLI helper definitions."""

# fmt: off
# ruff: noqa: F403, F405

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING

from ..runtime.approval_context import approval_context_tokens_validation_reason

if TYPE_CHECKING:
    from ._commands_shared import _CODEX_BROWSER_APPROVAL_WAIT_MAX_SECONDS, _hook_command_text, _now


from ._commands_shared import *
from .commands_parser_helpers import *


def _runtime_artifacts_module():
    return importlib.import_module(".commands_support_runtime_artifacts", __package__)


def _hook_state_module():
    return importlib.import_module(".commands_support_hook_state", __package__)


def _runtime_resolution_module():
    return importlib.import_module(".commands_support_runtime_resolution", __package__)


def _optional_string(value: object | None) -> str | None:
    return _runtime_artifacts_module()._optional_string(value)


def _set_codex_browser_operation_status(
    response_payload: dict[str, object],
    daemon_client: object | None,
    status: str,
) -> None:
    operation = response_payload.get("operation")
    if isinstance(operation, dict):
        operation["status"] = status
    response_payload["operation_status"] = status
    _hook_state_module()._update_codex_browser_operation_status(response_payload, daemon_client, status)


def _canonical_harness_name(value: str) -> str:
    return _runtime_resolution_module()._canonical_harness_name(value)

def _run_apps_command(
    args: argparse.Namespace,
    context: HarnessContext,
    store: GuardStore,
    workspace: str | None,
) -> int:
    apps_command = getattr(args, "apps_command", None)
    if apps_command is None:
        _emit(
            "apps",
            {
                "generated_at": _now(),
                "items": list_harness_setup_items(context, store),
            },
            getattr(args, "json", False),
        )
        return 0

    harness = str(getattr(args, "harness", "")).strip()
    if not harness:
        print("guard apps requires a harness.", file=sys.stderr)
        return 2
    if apps_command == "test":
        try:
            payload = build_harness_verification(harness, context, store, surface=getattr(args, "surface", None))
        except ValueError as error:
            print(str(error), file=sys.stderr)
            return 2
        _emit("apps", payload, getattr(args, "json", False))
        return 0

    if apps_command in {"connect", "repair"} and bool(getattr(args, "dry_run", False)):
        try:
            payload = build_harness_setup_plan(
                apps_command,
                harness,
                context,
                dry_run=True,
                surface=getattr(args, "surface", None),
            )
        except ValueError as error:
            print(str(error), file=sys.stderr)
            return 2
        _emit("apps", payload, getattr(args, "json", False))
        return 0

    if apps_command == "disconnect":
        try:
            canonical_harness = get_adapter(harness).harness
        except ValueError as error:
            print(str(error), file=sys.stderr)
            return 2
        expected_confirmation = uninstall_confirmation_token(canonical_harness)
        if getattr(args, "confirm", None) != expected_confirmation:
            payload: dict[str, object] = {
                "error": "confirmation_required",
                "harness": canonical_harness,
                "confirmation_phrase": expected_confirmation,
                "confirm_command": _apps_disconnect_confirm_command(
                    canonical_harness,
                    expected_confirmation,
                    surface=getattr(args, "surface", None),
                ),
            }
            _emit("apps", payload, getattr(args, "json", False))
            return 2

    install_command = "uninstall" if apps_command == "disconnect" else "install"
    try:
        payload = apply_managed_install(
            install_command,
            harness,
            False,
            context,
            store,
            workspace,
            _now(),
            surface=getattr(args, "surface", None),
        )
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 2
    payload["action"] = apps_command
    if apps_command in {"connect", "repair"}:
        managed_install = payload.get("managed_install")
        canonical_harness = (
            str(managed_install.get("harness"))
            if isinstance(managed_install, dict) and managed_install.get("harness")
            else harness
        )
        try:
            payload["cloud_app"] = _open_guard_cloud_app(
                harness=canonical_harness,
                guard_home=context.guard_home,
                opener=webbrowser.open,
            )
        except (RuntimeError, OSError) as error:
            payload["cloud_app"] = _guard_cloud_app_error_payload(
                harness=canonical_harness,
                error=str(error),
            )
    _emit("apps", payload, getattr(args, "json", False))
    return 0

def _apps_disconnect_confirm_command(harness: str, confirmation_phrase: str, *, surface: str | None) -> str:
    surface_args = f" --surface {surface}" if surface in {"editor", "cli"} else ""
    return f"hol-guard apps disconnect {harness}{surface_args} --confirm {confirmation_phrase}"

def _open_guard_cloud_app(
    *,
    harness: str,
    guard_home: Path,
    opener: GuardBrowserOpener,
) -> dict[str, object]:
    daemon_url = ensure_guard_daemon(guard_home)
    public_url, browser_url = _guard_cloud_app_urls(
        harness=harness,
    )
    browser_opened = bool(browser_url and opener(browser_url))
    payload: dict[str, object] = {
        "app_url": public_url,
        "browser_opened": browser_opened,
        "daemon_url": daemon_url,
        "status": "opened" if browser_opened else "manual_open_required",
    }
    if not browser_opened:
        payload["next_action"] = {
            "label": f"Run hol-guard apps connect {harness}",
            "reason": "Browser did not open automatically and the local token is never printed.",
            "target": f"hol-guard apps connect {harness}",
        }
    return payload

def _guard_cloud_app_error_payload(*, harness: str, error: str) -> dict[str, object]:
    public_url, _browser_url = _guard_cloud_app_urls(
        harness=harness,
    )
    return {
        "app_url": public_url,
        "browser_opened": False,
        "daemon_url": None,
        "error": error,
        "next_action": {
            "label": f"Run hol-guard apps connect {harness}",
            "reason": "Local Guard daemon did not start, so Cloud cannot connect from the browser yet.",
            "target": f"hol-guard apps connect {harness}",
        },
        "status": "daemon_unavailable",
    }

def _guard_cloud_app_urls(
    *,
    harness: str,
) -> tuple[str, str]:
    safe_harness = urllib.parse.quote(harness.strip() or "codex", safe="")
    parsed = urllib.parse.urlparse(f"{DEFAULT_GUARD_APPS_URL}/{safe_harness}")
    public_url = urllib.parse.urlunparse(parsed._replace(fragment=""))
    # OAuth app connect must not hand local daemon URLs or dashboard tokens to Cloud.
    return public_url, public_url

def _build_cisco_scan_options(mode: str) -> ScanOptions:
    return ScanOptions(cisco_skill_scan=mode, cisco_mcp_scan=mode)

def _resolve_cisco_scan_options(mode: str) -> ScanOptions | None:
    if mode == "auto":
        return None
    return _build_cisco_scan_options(mode)

def _run_consumer_scan_with_mode(
    target: Path,
    *,
    intended_harness: str | None = None,
    cisco_mode: str,
) -> dict[str, object]:
    options = _resolve_cisco_scan_options(cisco_mode)
    if options is None:
        return run_consumer_scan(target, intended_harness=intended_harness)
    return run_consumer_scan(target, intended_harness=intended_harness, options=options)

def _policy_write_needs_approval_gate(store: GuardStore, *, action: str, scope: str) -> bool:
    if not _policy_write_requires_approval_gate(store, action=action, scope=scope):
        return False
    gate = approval_gate_public_config(store.guard_home)
    if scope == "global":
        return True
    if gate.cooldown_active and not gate.totp_enabled:
        return False
    if action == "allow":
        return True
    return gate.strict_all_decisions

def _policy_write_requires_approval_gate(store: GuardStore, *, action: str, scope: str) -> bool:
    gate = approval_gate_public_config(store.guard_home)
    if not gate.enabled:
        return False
    if action == "allow" or scope == "global":
        return True
    return gate.strict_all_decisions

def _record_harness_usage_for_hook(
    *,
    store: GuardStore,
    action_envelope: GuardActionEnvelope | None,
    payload: Mapping[str, object],
    policy_action: str | None,
) -> None:
    usage_payload = dict(payload)
    if isinstance(policy_action, str) and policy_action:
        usage_payload["policy_action"] = policy_action
    record_harness_usage_events(
        store=store,
        action=action_envelope,
        raw_payload=usage_payload,
        occurred_at=_now(),
    )

def _emit(command: str, payload: dict[str, object], as_json: bool) -> None:
    from .render import emit_guard_payload

    emit_guard_payload(command, payload, as_json)

def _should_emit_copilot_hook_response(args: argparse.Namespace) -> bool:
    return args.harness == "copilot" and not getattr(args, "json", False)

def _should_emit_native_hook_response(args: argparse.Namespace) -> bool:
    return (
        _canonical_harness_name(args.harness) in {"claude-code", "codex", "kimi", "grok", "pi", "zcode"}
        and not getattr(args, "json", False)
    )

def _should_emit_claude_native_pretooluse_notice(
    args: argparse.Namespace,
    *,
    event_name: str,
    policy_action: str,
) -> bool:
    return (
        _canonical_harness_name(args.harness) == "claude-code"
        and not getattr(args, "json", False)
        and event_name == "PreToolUse"
        and policy_action in {"review", "require-reapproval"}
    )

def _should_emit_native_hook_json_response(
    args: argparse.Namespace,
    *,
    event_name: str,
    output_stream: TextIO | None,
) -> bool:
    harness = _canonical_harness_name(args.harness)
    if harness == "codex" and getattr(args, "json", False) and event_name == "UserPromptSubmit":
        return True
    return (
        harness in {"claude-code", "codex"}
        and getattr(args, "json", False)
        and output_stream is not None
        and (
            event_name in {"PreToolUse", "Notification"}
            or (harness == "claude-code" and event_name == "UserPromptSubmit")
        )
    )

def _should_emit_native_hook_exit_block(args: argparse.Namespace, *, event_name: str, policy_action: str) -> bool:
    # Codex v0.133 logs non-zero PreToolUse hooks as failed but still executes
    # the tool. Blocking must be communicated through the JSON hook response.
    canonical = _canonical_harness_name(args.harness)
    if canonical in {"kimi", "grok", "pi", "zcode"} and event_name in {"PreToolUse", "UserPromptSubmit"}:
        return policy_action in {"review", "require-reapproval", "sandbox-required", "block"}
    return False

def _codex_browser_approval_decision(
    *,
    args: argparse.Namespace,
    event_name: str,
    policy_action: str,
    response_payload: dict[str, object],
    store: GuardStore,
    config: GuardConfig,
    daemon_client: object | None = None,
    expected_artifact_hash: str | None = None,
    fresh_context_provider: Callable[[], Mapping[str, object] | None] | None = None,
) -> str | None:
    if not _codex_can_use_browser_approval(args=args, event_name=event_name, policy_action=policy_action):
        return None
    if event_name == "PreToolUse" and not _codex_pretooluse_live_wait_candidate(response_payload):
        return None
    approval_requests = response_payload.get("approval_requests")
    if not isinstance(approval_requests, list):
        return None
    request_ids = [
        item["request_id"]
        for item in approval_requests
        if isinstance(item, dict) and isinstance(item.get("request_id"), str)
    ]
    if not request_ids:
        return None
    wait_timeout_seconds = _codex_browser_wait_timeout_seconds(
        event_name=event_name,
        configured_timeout=config.approval_wait_timeout_seconds,
    )
    if wait_timeout_seconds <= 0:
        return None
    if event_name == "PreToolUse":
        _open_codex_live_approval(response_payload, guard_home=store.guard_home)
    wait_result = wait_for_approval_requests(
        store=store,
        request_ids=request_ids,
        timeout_seconds=wait_timeout_seconds,
    )
    response_payload["approval_wait"] = wait_result
    if not bool(wait_result.get("resolved")):
        _set_codex_browser_operation_status(response_payload, daemon_client, "approval_wait_timeout")
        response_payload["review_hint"] = (
            "Approval is still pending in HOL Guard. Approve it in the browser, then retry the same Codex action."
        )
        return None
    wait_items = wait_result.get("items")
    resolved_items = [item for item in (wait_items if isinstance(wait_items, list) else []) if isinstance(item, dict)]
    if any(str(item.get("resolution_action")) == "block" for item in resolved_items):
        _set_codex_browser_operation_status(response_payload, daemon_client, "blocked")
        _record_codex_live_hook_continuation(
            response_payload=response_payload,
            store=store,
            request_ids=request_ids,
            action="block",
        )
        response_payload["review_hint"] = "Browser decision saved. HOL Guard kept this Codex action blocked."
        return "block"
    fresh_artifact_id: str | None = None
    fresh_artifact_hash = expected_artifact_hash
    fresh_current_action: str | None = None
    fresh_authoritative_action: str | None = None
    fresh_terminal_action: str | None = None
    exact_validation_failure: str | None = None
    if fresh_context_provider is None:
        exact_validation_failure = "fresh_context_unavailable"
    else:
        try:
            fresh_context = fresh_context_provider()
        except Exception:
            fresh_context = None
        if not isinstance(fresh_context, Mapping):
            exact_validation_failure = "fresh_context_unavailable"
        else:
            fresh_artifact_id = _optional_string(fresh_context.get("artifact_id"))
            fresh_artifact_hash = _optional_string(fresh_context.get("artifact_hash"))
            fresh_current_action = _optional_string(fresh_context.get("current_action"))
            fresh_authoritative_action = _optional_string(
                fresh_context.get("authoritative_action")
            )
            if fresh_authoritative_action in {"block", "sandbox-required"}:
                fresh_terminal_action = fresh_authoritative_action
            elif fresh_current_action in {"block", "sandbox-required"}:
                fresh_terminal_action = fresh_current_action
            if fresh_artifact_id is None or fresh_artifact_hash is None:
                exact_validation_failure = "fresh_context_incomplete"
            elif fresh_current_action in {"block", "sandbox-required"}:
                exact_validation_failure = "current_policy_became_terminal"
            elif fresh_current_action not in {"allow", "warn", "review", "require-reapproval"}:
                exact_validation_failure = "fresh_current_action_unrecognized"
    if exact_validation_failure is None:
        exact_validation_failure = _codex_browser_exact_resolution_failure(
            response_payload=response_payload,
            store=store,
            request_ids=request_ids,
            resolved_items=resolved_items,
            expected_artifact_hash=fresh_artifact_hash,
            expected_artifact_id=fresh_artifact_id,
        )
    if (
        exact_validation_failure is None
        and fresh_context_provider is not None
        and fresh_authoritative_action != "allow"
    ):
        # The exact browser decision is evidence, not the launch authority.
        # Re-evaluation must have successfully applied (and, for one-shot
        # rows, atomically claimed) that evidence.  A renewed review or a
        # concurrent saved block must never be overwritten by this waiter.
        exact_validation_failure = "fresh_authoritative_action_not_allowed"
    if exact_validation_failure is not None:
        terminal_action = fresh_terminal_action or "block"
        response_payload["approval_requests"] = resolved_items
        _set_codex_browser_operation_status(response_payload, daemon_client, "blocked")
        _record_codex_live_hook_continuation(
            response_payload=response_payload,
            store=store,
            request_ids=request_ids,
            action=terminal_action,
        )
        response_payload["browser_resolution_validation"] = exact_validation_failure
        if terminal_action == "sandbox-required":
            response_payload["review_hint"] = (
                "HOL Guard rejected the browser approval because current policy now requires a sandbox. "
                "This Codex action was not resumed."
            )
        else:
            response_payload["review_hint"] = (
                "HOL Guard rejected the browser approval because it did not match the exact current request. "
                "This Codex action remains blocked."
            )
        return terminal_action
    response_payload["approval_requests"] = resolved_items
    _set_codex_browser_operation_status(response_payload, daemon_client, "completed")
    _record_codex_live_hook_continuation(
        response_payload=response_payload,
        store=store,
        request_ids=request_ids,
        action="allow",
    )
    response_payload["browser_resolution_request_id"] = request_ids[0]
    response_payload["review_hint"] = "Approval received in HOL Guard. Codex is resuming this action."
    return "allow"


def _codex_browser_exact_resolution_failure(
    *,
    response_payload: Mapping[str, object],
    store: GuardStore,
    request_ids: list[str],
    resolved_items: list[dict[str, object]],
    expected_artifact_hash: str | None,
    expected_artifact_id: str | None = None,
) -> str | None:
    resolved_by_id = {
        str(item.get("request_id")): item
        for item in resolved_items
        if isinstance(item.get("request_id"), str)
    }
    current_artifact_hash = expected_artifact_hash
    if current_artifact_hash is None:
        current_artifact_hash = _optional_string(response_payload.get("artifact_hash"))
    current_artifact_id = expected_artifact_id or _optional_string(response_payload.get("artifact_id"))
    if current_artifact_hash is None:
        return "missing_current_approval_context"
    for request_id in request_ids:
        resolved_item = resolved_by_id.get(request_id)
        stored_item = store.get_approval_request(request_id)
        item = dict(stored_item) if isinstance(stored_item, Mapping) else None
        if resolved_item is not None:
            item = {**(item or {}), **resolved_item}
        if item is None:
            return "missing_resolved_request"
        if str(item.get("resolution_action")) != "allow":
            return "non_allow_resolution"
        if str(item.get("policy_action")) not in {"review", "require-reapproval"}:
            return "terminal_request_is_not_approvable"
        if current_artifact_id is not None and str(item.get("artifact_id")) != current_artifact_id:
            return "approval_artifact_changed"
        if approval_context_tokens_validation_reason(
            item.get("artifact_hash"),
            current_artifact_hash,
        ) is not None:
            return "approval_context_changed"
    return None


def _record_codex_live_hook_continuation(
    *,
    response_payload: dict[str, object],
    store: GuardStore,
    request_ids: list[str],
    action: str,
) -> None:
    status = "resumed" if action == "allow" else "blocked"
    sandbox_required = action == "sandbox-required"
    continuation: dict[str, object] = {
        "status": status,
        "resolution_action": action,
        "strategy": "live-hook",
    }
    response_payload["continuation"] = continuation
    response_payload["codex_resume"] = dict(continuation)
    now = _now()
    for request_id in request_ids:
        resume = store.get_request_resume(request_id)
        if not isinstance(resume, Mapping):
            continue
        attempt_count = resume.get("attempt_count")
        store.update_request_resume(
            request_id=request_id,
            resolution_action=action,
            strategy=(
                str(resume.get("strategy"))
                if isinstance(resume.get("strategy"), str)
                else "live-hook"
            ),
            supported=(
                bool(resume.get("supported"))
                if resume.get("supported") is not None
                else action == "allow"
            ),
            status=status,
            reason=(
                "live_hook_completed"
                if action == "allow"
                else "sandbox_required_not_resumed"
                if sandbox_required
                else "blocked_not_resumed"
            ),
            message=(
                "The original Codex hook consumed the exact browser approval and resumed the action."
                if action == "allow"
                else "Current HOL Guard policy requires a sandbox; the original Codex action was not resumed."
                if sandbox_required
                else "HOL Guard kept the original Codex action blocked."
            ),
            last_error=None,
            attempt_count=int(attempt_count) if isinstance(attempt_count, int) else 0,
            last_attempt_at=now,
            sent_at=(
                str(resume.get("sent_at"))
                if isinstance(resume.get("sent_at"), str)
                else None
            ),
            now=now,
        )

def _codex_can_use_browser_approval(args: argparse.Namespace, *, event_name: str, policy_action: str) -> bool:
    return (
        _canonical_harness_name(args.harness) == "codex"
        and not getattr(args, "json", False)
        and event_name in {"PreToolUse", "PostToolUse", "UserPromptSubmit"}
        and policy_action in {"review", "require-reapproval"}
    )

def _codex_hook_waits_for_browser_approval(
    args: argparse.Namespace,
    *,
    event_name: str,
    policy_action: str,
    payload: Mapping[str, object] | None = None,
) -> bool:
    if not _codex_can_use_browser_approval(args=args, event_name=event_name, policy_action=policy_action):
        return False
    if event_name == "PreToolUse":
        return _codex_pretooluse_live_wait_candidate(payload)
    return True

def _codex_browser_wait_metadata(
    *,
    args: argparse.Namespace,
    event_name: str,
    policy_action: str,
    config: GuardConfig,
    payload: Mapping[str, object] | None = None,
) -> dict[str, object]:
    waits_for_browser = _codex_hook_waits_for_browser_approval(
        args=args,
        event_name=event_name,
        policy_action=policy_action,
        payload=payload,
    )
    if not waits_for_browser:
        return {"codex_hook_waits_for_browser_approval": False}
    wait_timeout_seconds = _codex_browser_wait_timeout_seconds(
        event_name=event_name,
        configured_timeout=config.approval_wait_timeout_seconds,
    )
    started_at = datetime.now(timezone.utc)
    deadline_at = started_at + timedelta(seconds=wait_timeout_seconds)
    return {
        "codex_hook_waits_for_browser_approval": True,
        "codex_browser_wait_started_at": started_at.isoformat(),
        "codex_browser_wait_deadline_at": deadline_at.isoformat(),
        "codex_browser_wait_timeout_seconds": wait_timeout_seconds,
    }

def _codex_browser_wait_timeout_seconds(*, event_name: str, configured_timeout: int) -> int:
    wait_timeout_seconds = max(configured_timeout, 0)
    if event_name in {"UserPromptSubmit", "PreToolUse", "PostToolUse"}:
        wait_timeout_seconds = min(wait_timeout_seconds, _CODEX_BROWSER_APPROVAL_WAIT_MAX_SECONDS)
    return wait_timeout_seconds


def _codex_pretooluse_live_wait_candidate(payload: Mapping[str, object] | None) -> bool:
    if not isinstance(payload, Mapping):
        return False
    command_text = _hook_command_text(payload)
    if not command_text:
        tool_input = payload.get("tool_input")
        if isinstance(tool_input, Mapping):
            command_text = str(
                tool_input.get("command")
                or tool_input.get("cmd")
                or tool_input.get("shell_command")
                or tool_input.get("shellCommand")
                or ""
            )
    if not command_text:
        risk_signals = payload.get("risk_signals")
        text_parts = [
            str(payload.get("artifact_name", "")),
            str(payload.get("risk_summary", "")),
            str(payload.get("risk_headline", "")),
            str(payload.get("trigger_summary", "")),
            " ".join(
                str(item)
                for item in (risk_signals if isinstance(risk_signals, list) else [])
                if isinstance(item, str)
            )
            if isinstance(risk_signals, list)
            else "",
        ]
        command_text = " ".join(text_parts)
    lowered = command_text.lower()
    return bool(
        re.search(r"\b(?:npm|pnpm|yarn|bun|pip|pip3|python(?:3(?:\.\d+)?)?\s+-m\s+pip)\s+install\b", lowered)
        or "package install request" in lowered
        or "before install" in lowered
    )

def _attach_primary_approval_link(
    response_payload: dict[str, object],
    *,
    harness: str,
    approval_center_url: str | None,
) -> None:
    attach_primary_approval_link(
        response_payload,
        harness=harness,
        approval_center_url=approval_center_url,
    )

def _primary_approval_lookup_kwargs(response_payload: dict[str, object], *, harness: str) -> dict[str, str | None]:
    return {
        "harness": harness,
        "approval_center_url": _optional_string(response_payload.get("approval_center_url")),
        "request_id": _optional_string(response_payload.get("primary_approval_request_id")),
        "artifact_id": _optional_string(response_payload.get("artifact_id")),
    }

def _preferred_approval_review_url(response_payload: Mapping[str, object], *, harness: str) -> str | None:
    approval_center_url = _optional_string(response_payload.get("approval_center_url"))
    queued = response_payload.get("approval_requests")
    lookup_kwargs = _primary_approval_lookup_kwargs(dict(response_payload), harness=harness)
    artifact_id = lookup_kwargs.get("artifact_id")
    queued_has_artifact_metadata = (
        any(_optional_string(item.get("artifact_id")) is not None for item in queued if isinstance(item, Mapping))
        if isinstance(queued, list)
        else False
    )
    queued_url = (
        first_approval_url(
            queued,
            **lookup_kwargs,
        )
        if isinstance(queued, list)
        else None
    )
    if queued_url is None and isinstance(queued, list) and artifact_id is not None:
        queued_url = first_approval_url(
            queued,
            harness=harness,
            approval_center_url=approval_center_url,
            artifact_id=artifact_id,
        )
    if queued_url is None and isinstance(queued, list) and (artifact_id is None or not queued_has_artifact_metadata):
        queued_url = first_approval_url(
            queued,
            harness=harness,
            approval_center_url=approval_center_url,
        )
    if queued_url is not None:
        return queued_url
    primary_url = _optional_string(response_payload.get("primary_approval_url"))
    if primary_url is not None:
        return canonical_local_approval_url(
            primary_url,
            approval_center_url=approval_center_url,
        )
    return approval_center_url

def _open_codex_live_approval(response_payload: Mapping[str, object], *, guard_home: Path | None = None) -> None:
    harness = _optional_string(response_payload.get("harness")) or "codex"
    review_url = _preferred_approval_review_url(response_payload, harness=harness)
    if not review_url:
        return
    print(
        f"HOL Guard is waiting for approval in your browser: {review_url}",
        file=sys.stderr,
        flush=True,
    )
    browser_url = review_url
    if guard_home is not None:
        browser_url = (
            build_approval_browser_url(
                review_url,
                auth_token=load_guard_daemon_auth_token(guard_home),
            )
            or review_url
        )
    with suppress(Exception):
        webbrowser.open(browser_url)

__all__ = [
    "_apps_disconnect_confirm_command", "_attach_primary_approval_link", "_build_cisco_scan_options",
    "_codex_browser_approval_decision",
    "_codex_browser_wait_metadata",
    "_codex_browser_wait_timeout_seconds",
    "_codex_can_use_browser_approval",
    "_codex_hook_waits_for_browser_approval", "_codex_pretooluse_live_wait_candidate", "_emit",
    "_guard_cloud_app_error_payload", "_guard_cloud_app_urls", "_open_codex_live_approval",
    "_open_guard_cloud_app", "_policy_write_needs_approval_gate", "_policy_write_requires_approval_gate",
    "_preferred_approval_review_url", "_primary_approval_lookup_kwargs", "_record_harness_usage_for_hook",
    "_resolve_cisco_scan_options", "_run_apps_command", "_run_consumer_scan_with_mode",
    "_should_emit_claude_native_pretooluse_notice", "_should_emit_copilot_hook_response",
    "_should_emit_native_hook_exit_block", "_should_emit_native_hook_json_response",
    "_should_emit_native_hook_response",
]
