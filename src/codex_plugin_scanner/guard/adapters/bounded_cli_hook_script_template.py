"""Stdlib-only bounded hook client that fans into the running Guard daemon."""

from __future__ import annotations

BOUNDED_HOOK_SCRIPT_TEMPLATE = '''#!/usr/bin/env python3
"""Managed by HOL Guard. Re-run hol-guard install after moving Guard home."""
from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

GUARD_HOME = __GUARD_HOME__
HARNESS = __HARNESS__
TIMEOUT_SECONDS = __TIMEOUT_SECONDS__
_MAX_INPUT_BYTES = 1_000_000
_MAX_RESPONSE_BYTES = 1_000_000
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_EVENT_ALIASES = {
    "permissionrequest": "PermissionRequest",
    "pretooluse": "PreToolUse",
    "pretoolcall": "PreToolUse",
    "userpromptsubmit": "UserPromptSubmit",
    "posttooluse": "PostToolUse",
}
_EVENT_NAME_KEYS = ("hook_event_name", "hookEventName", "event", "eventName", "hook_name", "hookName")
_FAILURE_REASON = "HOL Guard could not complete this review before the hook deadline. Retry the action."


def _assert_loopback_http_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "http":
        raise ValueError("hook URL must use http")
    if parsed.hostname not in _LOOPBACK_HOSTS:
        raise ValueError("hook URL must target loopback")


class _LoopbackOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        _assert_loopback_http_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _json_object(text: str) -> dict[str, object] | None:
    try:
        raw = json.loads(text)
    except json.JSONDecodeError:
        return None
    return raw if isinstance(raw, dict) else None


def _event_name(input_text: str) -> str:
    payload = _json_object(input_text or "{}")
    if payload is not None:
        for key in _EVENT_NAME_KEYS:
            value = payload.get(key)
            if isinstance(value, str):
                compact = value.strip().replace("_", "").replace("-", "").lower()
                return _EVENT_ALIASES.get(compact, value.strip() or "PreToolUse")
    return "PreToolUse"


def _read_private_text(path: Path, *, max_bytes: int) -> str | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if len(data) > max_bytes:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _endpoint() -> tuple[str, str] | None:
    raw_state = _read_private_text(Path(GUARD_HOME) / "daemon-state.json", max_bytes=64 * 1024)
    token = _read_private_text(Path(GUARD_HOME) / "daemon-auth-token", max_bytes=4096)
    if raw_state is None or token is None:
        return None
    state = _json_object(raw_state)
    if state is None:
        return None
    host = state.get("host")
    port = state.get("port")
    auth = token.strip()
    if (
        not isinstance(host, str)
        or host not in _LOOPBACK_HOSTS
        or not isinstance(port, int)
        or isinstance(port, bool)
        or not 1 <= port <= 65535
        or not auth
    ):
        return None
    rendered = f"[{host}]" if host == "::1" else host
    return f"http://{rendered}:{port}/v1/hooks/{HARNESS}", auth


def _permission_decision(policy_action: str) -> str | None:
    if policy_action in {"allow", "warn"}:
        return "allow"
    if policy_action in {"review", "require-reapproval", "sandbox-required"}:
        return "ask"
    if policy_action == "block":
        return "deny"
    return None


def _should_exit_block(event_name: str, policy_action: str) -> bool:
    compact = event_name.replace("_", "").replace("-", "").lower()
    if HARNESS in {"kimi", "grok", "hermes", "pi", "omp", "zcode"} and compact in {
        "pretooluse",
        "userpromptsubmit",
        "pretoolcall",
    }:
        return policy_action in {"review", "require-reapproval", "sandbox-required", "block"}
    return False


def _to_native(daemon_response: dict[str, object], event_name: str) -> tuple[str, str, int]:
    if "hookSpecificOutput" in daemon_response or "decision" in daemon_response:
        stdout = json.dumps(daemon_response, ensure_ascii=True, separators=(",", ":"))
        policy = str(daemon_response.get("policy_action") or "allow")
        exit_code = 2 if _should_exit_block(event_name, policy) else 0
        return stdout, "", exit_code
    policy_action = str(daemon_response.get("policy_action") or "block")
    reason = str(daemon_response.get("reason") or daemon_response.get("permission_decision_reason") or "")
    payload: dict[str, object] = {}
    if event_name == "UserPromptSubmit":
        if policy_action in {"review", "require-reapproval", "sandbox-required", "block"}:
            payload["decision"] = "block"
            payload["reason"] = reason or f"HOL Guard blocked this action ({policy_action})"
    else:
        permission_decision = _permission_decision(policy_action)
        hook_specific: dict[str, object] = {"hookEventName": event_name}
        if permission_decision is not None:
            hook_specific["permissionDecision"] = permission_decision
            if permission_decision != "allow" or "unreachable" in reason.lower():
                hook_specific["permissionDecisionReason"] = reason or f"HOL Guard {policy_action} this action"
        payload["hookSpecificOutput"] = hook_specific
        if HARNESS in {"grok", "openclaw"} and permission_decision is not None:
            payload["decision"] = "allow" if permission_decision == "allow" else "deny"
            payload["policy_action"] = policy_action
            if permission_decision != "allow" and reason:
                payload["reason"] = reason
    stdout = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
    exit_code = 2 if _should_exit_block(event_name, policy_action) else 0
    return stdout, reason if exit_code == 2 and HARNESS == "kimi" else "", exit_code


def _fail(input_text: str, *, reason: str = _FAILURE_REASON) -> int:
    event_name = _event_name(input_text)
    payload = {
        "decision": "deny",
        "reason": reason,
        "hookSpecificOutput": {
            "hookEventName": event_name,
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        },
    }
    sys.stdout.write(json.dumps(payload, ensure_ascii=True, separators=(",", ":")) + "\\n")
    return 0


def _post_hook(input_text: str) -> tuple[str, str, int] | None:
    discovered = _endpoint()
    if discovered is None:
        return None
    url, token = discovered
    try:
        _assert_loopback_http_url(url)
    except ValueError:
        return None
    timeout = min(float(TIMEOUT_SECONDS) * 0.5, 5.0)
    request = urllib.request.Request(
        url,
        data=input_text.encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Guard-Token": token},
        method="POST",
    )
    try:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _LoopbackOnlyRedirectHandler(),
        )
        with opener.open(request, timeout=timeout) as response:
            final_url = response.geturl()
            if final_url:
                _assert_loopback_http_url(final_url)
            if response.status != 200:
                return None
            body = response.read(_MAX_RESPONSE_BYTES + 1)
    except (OSError, urllib.error.URLError, TimeoutError, ValueError):
        return None
    if len(body) > _MAX_RESPONSE_BYTES:
        return None
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return None
    parsed = _json_object(text.strip())
    if parsed is None:
        return None
    return _to_native(parsed, _event_name(input_text))


def main() -> int:
    raw = sys.stdin.buffer.read(_MAX_INPUT_BYTES + 1)
    prefix = raw[:_MAX_INPUT_BYTES].decode("utf-8", errors="replace")
    if len(raw) > _MAX_INPUT_BYTES:
        return _fail(
            prefix,
            reason="HOL Guard blocked this action because hook input exceeded the safe size limit.",
        )
    result = _post_hook(prefix)
    if result is None:
        return _fail(prefix)
    stdout, stderr, exit_code = result
    if stdout:
        sys.stdout.write(stdout if stdout.endswith("\\n") else stdout + "\\n")
    if stderr:
        print(stderr, file=sys.stderr)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
'''
