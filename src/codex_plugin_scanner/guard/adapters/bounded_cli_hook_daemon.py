"""Daemon fast path for the bounded CLI hook bridge."""

from __future__ import annotations

import json
import sqlite3
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from pathlib import Path
from urllib.parse import urlparse

from ..action_lattice import is_guard_action
from ..daemon.hook_availability_policy import hook_reason_continues_session
from ..private_file_io import read_private_regular_text
from .bounded_cli_hook_bridge import _event_name, _json_object

_MAX_HOOK_RESPONSE_BYTES = 1_000_000
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_DAEMON_TIMEOUT_BUDGET_SECONDS = 5.0


def _assert_loopback_http_url(url: str) -> None:
    """Reject non-loopback daemon URLs."""
    parsed = urlparse(url)
    if parsed.scheme != "http":
        raise ValueError(f"daemon URL must use http, not {parsed.scheme!r}")
    if parsed.hostname not in _LOOPBACK_HOSTS:
        raise ValueError(f"daemon URL must target loopback, not {parsed.hostname!r}")


def _build_loopback_opener() -> urllib.request.OpenerDirector:
    """Build an opener that blocks proxies and off-loopback redirects."""
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _LoopbackOnlyRedirectHandler(),
    )


class _LoopbackOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        _assert_loopback_http_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _read_daemon_auth_token(guard_home: Path) -> str | None:
    token = read_private_regular_text(
        guard_home / "daemon-auth-token",
        max_bytes=4096,
        require_private_parent=True,
    )
    return token or None


def _daemon_hook_endpoint(guard_home: Path, harness: str) -> str | None:
    """Return the loopback hook URL from authenticated daemon state, or None."""
    raw_state = read_private_regular_text(
        guard_home / "daemon-state.json",
        max_bytes=64 * 1024,
        require_private_parent=True,
    )
    if raw_state is None:
        return None
    try:
        state = json.loads(raw_state)
    except json.JSONDecodeError:
        return None
    if not isinstance(state, dict):
        return None
    host = state.get("host")
    port = state.get("port")
    if (
        not isinstance(host, str)
        or host not in _LOOPBACK_HOSTS
        or not isinstance(port, int)
        or isinstance(port, bool)
        or not 1 <= port <= 65535
    ):
        return None
    rendered_host = f"[{host}]" if host == "::1" else host
    return f"http://{rendered_host}:{port}/v1/hooks/{harness}"


def _native_hook_permission_decision(policy_action: str) -> str | None:
    if policy_action in {"allow", "warn"}:
        return "allow"
    if policy_action in {"review", "require-reapproval", "sandbox-required"}:
        return "ask"
    if policy_action == "block":
        return "deny"
    return None


def _policy_action_from_daemon(daemon_response: Mapping[str, object]) -> str:
    reason_code = str(daemon_response.get("reason_code") or "")
    if hook_reason_continues_session(reason_code):
        return "warn"
    raw_policy_action = daemon_response.get("policy_action")
    if isinstance(raw_policy_action, str) and is_guard_action(raw_policy_action.strip()):
        return raw_policy_action.strip()
    return "block"


def _should_exit_block(harness: str, event_name: str, policy_action: str) -> bool:
    canonical = harness.strip().lower().replace("_", "-")
    compact = event_name.replace("_", "").replace("-", "").lower()
    if canonical in {"kimi", "grok", "hermes", "pi", "omp", "zcode"} and compact in {
        "pretooluse",
        "userpromptsubmit",
        "pretoolcall",
    }:
        return policy_action in {"review", "require-reapproval", "sandbox-required", "block"}
    return False


def _consistent_native_response(
    daemon_response: dict[str, object],
    *,
    harness: str,
    event_name: str,
) -> tuple[dict[str, object], str]:
    """Align recognized native decisions without weakening review semantics."""

    response = dict(daemon_response)
    gating_event = event_name.replace("_", "").replace("-", "").lower() in {
        "permissionrequest",
        "pretoolcall",
        "pretooluse",
        "userpromptsubmit",
    }
    raw_policy = response.get("policy_action")
    policy_action = raw_policy.strip() if isinstance(raw_policy, str) and is_guard_action(raw_policy.strip()) else None
    if gating_event and "policy_action" in response and policy_action is None:
        policy_action = "block"
        response["policy_action"] = policy_action
    explicit_restrictive_policy = policy_action in {
        "block",
        "require-reapproval",
        "review",
        "sandbox-required",
    }
    raw_top = response.get("decision")
    top = raw_top.strip().lower() if isinstance(raw_top, str) else None
    if top not in {"allow", "ask", "deny", "block"}:
        top = None
    if gating_event and "decision" in response and top is None:
        top = "deny"
        response["decision"] = top
    raw_hook_specific = response.get("hookSpecificOutput")
    hook_specific = dict(raw_hook_specific) if isinstance(raw_hook_specific, dict) else None
    raw_nested = hook_specific.get("permissionDecision") if hook_specific is not None else None
    nested = raw_nested.strip().lower() if isinstance(raw_nested, str) else None
    if nested not in {"allow", "ask", "deny", "block"}:
        nested = None
    if gating_event and hook_specific is not None and "permissionDecision" in hook_specific and nested is None:
        nested = "deny"
        hook_specific["permissionDecision"] = nested

    compact_event = event_name.replace("_", "").replace("-", "").lower()
    canonical_harness = harness.strip().lower().replace("_", "-")
    if explicit_restrictive_policy and compact_event == "userpromptsubmit" and top is None:
        top = "block"
        response["decision"] = top
    elif explicit_restrictive_policy and compact_event in {"permissionrequest", "pretoolcall", "pretooluse"}:
        if hook_specific is None and "hookSpecificOutput" in response:
            hook_specific = {"hookEventName": event_name}
        if hook_specific is not None and nested is None:
            nested = "deny" if policy_action == "block" else "ask"
            hook_specific["permissionDecision"] = nested
        if canonical_harness in {"grok", "openclaw"} and top is None:
            top = "deny"
            response["decision"] = top

    decisions = {decision for decision in (top, nested) if decision is not None}
    has_deny = bool(decisions & {"deny", "block"})
    has_ask = "ask" in decisions
    if policy_action in {"allow", "warn"} and has_deny:
        policy_action = "block"
        response["policy_action"] = policy_action
    elif policy_action in {"allow", "warn"} and has_ask:
        policy_action = "review"
        response["policy_action"] = policy_action

    if policy_action == "block" or (policy_action is None and has_deny):
        if top is not None:
            response["decision"] = "block" if top == "block" else "deny"
        if nested is not None and hook_specific is not None:
            hook_specific["permissionDecision"] = "deny"
    elif policy_action in {"review", "require-reapproval", "sandbox-required"} or (policy_action is None and has_ask):
        if top is not None:
            response["decision"] = "block" if top == "block" else "deny"
        if nested == "allow" and hook_specific is not None:
            hook_specific["permissionDecision"] = "ask"
    elif policy_action in {"allow", "warn"}:
        if top is not None:
            response["decision"] = "allow"
        if nested is not None and hook_specific is not None:
            hook_specific["permissionDecision"] = "allow"

    if hook_specific is not None:
        response["hookSpecificOutput"] = hook_specific
    if policy_action is not None:
        return response, policy_action
    if has_deny:
        return response, "block"
    if has_ask:
        return response, "review"
    return response, "allow"


def _daemon_response_to_native(
    daemon_response: dict[str, object],
    *,
    harness: str,
    event_name: str,
) -> tuple[str, str, int]:
    """Transform daemon policy data into harness-native output."""
    canonical = harness.strip().lower().replace("_", "-")
    if canonical == "grok" and not daemon_response:
        from .grok_hooks import is_grok_observe_only_event

        if is_grok_observe_only_event(event_name):
            return "{}", "", 0

    if "hookSpecificOutput" in daemon_response or "decision" in daemon_response:
        native_response, policy_action_for_exit = _consistent_native_response(
            daemon_response,
            harness=harness,
            event_name=event_name,
        )
        stdout = json.dumps(native_response, ensure_ascii=True, separators=(",", ":"))
        hook_specific = native_response.get("hookSpecificOutput")
        exit_code = 2 if _should_exit_block(harness, event_name, policy_action_for_exit) else 0
        stderr = ""
        if exit_code == 2 and canonical == "kimi":
            reason = native_response.get("reason")
            if (not isinstance(reason, str) or not reason) and isinstance(hook_specific, dict):
                reason = hook_specific.get("permissionDecisionReason")
            if isinstance(reason, str) and reason:
                stderr = reason
        return stdout, stderr, exit_code

    policy_action = _policy_action_from_daemon(daemon_response)
    reason = str(daemon_response.get("reason") or daemon_response.get("permission_decision_reason") or "")
    payload: dict[str, object] = {}
    if event_name == "UserPromptSubmit":
        if policy_action in {"review", "require-reapproval", "sandbox-required", "block"}:
            payload["decision"] = "block"
            payload["reason"] = reason or f"HOL Guard blocked this action ({policy_action})"
            if canonical == "codex":
                payload["continue"] = False
                payload["stopReason"] = payload["reason"]
                payload["hookSpecificOutput"] = {
                    "hookEventName": event_name,
                    "additionalContext": payload["reason"],
                }
        elif canonical in {"claude-code", "codex"}:
            payload["hookSpecificOutput"] = {"hookEventName": event_name}
    else:
        permission_decision = _native_hook_permission_decision(policy_action)
        if canonical == "codex" and event_name == "PreToolUse" and permission_decision is None:
            return "", "", 0
        hook_specific_output: dict[str, object] = {"hookEventName": event_name}
        if permission_decision is not None:
            hook_specific_output["permissionDecision"] = permission_decision
            if permission_decision != "allow" or "unreachable" in reason.lower():
                hook_specific_output["permissionDecisionReason"] = reason or f"HOL Guard {policy_action} this action"
        payload["hookSpecificOutput"] = hook_specific_output
        if canonical in {"grok", "openclaw"} and permission_decision is not None:
            payload["decision"] = "allow" if permission_decision == "allow" else "deny"
            payload["policy_action"] = policy_action
            if permission_decision != "allow" and reason:
                payload["reason"] = reason
            for key in (
                "reason_code",
                "approval_url",
                "approval_request_id",
                "primary_approval_request_id",
                "primary_approval_url",
                "guardApprovalRequestId",
                "guardApprovalUrl",
                "approval_requests",
            ):
                value = daemon_response.get(key)
                if value is not None:
                    payload[key] = value

    stdout = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
    exit_code = 2 if _should_exit_block(harness, event_name, policy_action) else 0
    stderr = reason if exit_code == 2 and canonical == "kimi" else ""
    return stdout, stderr, exit_code


def _apply_grok_bridge_approval_wait(
    *,
    guard_home: Path,
    harness: str,
    input_text: str,
    stdout: str,
    stderr: str,
    exit_code: int,
    timeout_seconds: float | None = None,
) -> tuple[str, str, int]:
    """Wait for Grok review after a fast daemon decision, inside the hook budget."""
    if harness.strip().lower() != "grok" or _event_name(input_text) != "PreToolUse":
        return stdout, stderr, exit_code
    payload = _json_object(stdout)
    if payload is None:
        return stdout, stderr, exit_code
    if str(payload.get("policy_action") or "") not in {"review", "require-reapproval"}:
        return stdout, stderr, exit_code
    try:
        from ..config import load_guard_config
        from ..store import GuardStore
        from .grok_approval_resume import apply_grok_pretool_approval_wait

        configured = load_guard_config(guard_home).approval_wait_timeout_seconds
        wait_seconds = configured
        if timeout_seconds is not None:
            wait_seconds = min(configured, max(0, int(timeout_seconds)))
        updated = apply_grok_pretool_approval_wait(
            payload,
            event_name="PreToolUse",
            store=GuardStore(guard_home),
            timeout_seconds=wait_seconds,
        )
    except (OSError, RuntimeError, TypeError, ValueError, KeyError, sqlite3.Error):
        return stdout, stderr, exit_code
    rewritten = json.dumps(updated, ensure_ascii=True, separators=(",", ":")) + "\n"
    if updated.get("decision") == "allow":
        return rewritten, stderr, 0
    return rewritten, stderr, exit_code


def try_daemon_hook(
    *,
    guard_home: Path,
    harness: str,
    input_text: str,
    timeout_seconds: float,
    _endpoint_loader: Callable[[Path, str], str | None] | None = None,
    _token_loader: Callable[[Path], str | None] | None = None,
    _opener_builder: Callable[[], urllib.request.OpenerDirector] | None = None,
) -> tuple[str, str, int] | None:
    """POST the hook payload to the running daemon; return native stdout or None."""
    endpoint = (_endpoint_loader or _daemon_hook_endpoint)(guard_home, harness)
    if endpoint is None:
        return None
    try:
        _assert_loopback_http_url(endpoint)
    except ValueError:
        return None
    token = (_token_loader or _read_daemon_auth_token)(guard_home)
    if token is None:
        return None
    timeout = min(float(timeout_seconds) * 0.5, _DAEMON_TIMEOUT_BUDGET_SECONDS)
    request = urllib.request.Request(
        endpoint,
        data=input_text.encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Guard-Token": token},
        method="POST",
    )
    try:
        opener = (_opener_builder or _build_loopback_opener)()
        with opener.open(request, timeout=timeout) as response:
            final_url = response.geturl()
            if final_url:
                _assert_loopback_http_url(final_url)
            if response.status != 200:
                return None
            body = response.read(_MAX_HOOK_RESPONSE_BYTES + 1)
    except (OSError, urllib.error.URLError, TimeoutError, ValueError):
        return None
    if len(body) > _MAX_HOOK_RESPONSE_BYTES:
        return None
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return None
    candidate = text.strip()
    if not candidate:
        return None
    try:
        parsed = json.loads(candidate)
    except ValueError:
        return None
    if not isinstance(parsed, dict):
        return None
    event_name = _event_name(input_text)
    if harness.strip().lower().replace("_", "-") == "hermes":
        from .hermes_runtime_hooks import hermes_bridge_response

        return hermes_bridge_response(parsed, event_name=event_name)
    return _daemon_response_to_native(parsed, harness=harness, event_name=event_name)


__all__ = ["try_daemon_hook"]
