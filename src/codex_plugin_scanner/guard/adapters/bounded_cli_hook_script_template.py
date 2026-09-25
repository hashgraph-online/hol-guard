"""Stdlib-only bounded hook client that fans into the running Guard daemon."""

from __future__ import annotations

BOUNDED_HOOK_SCRIPT_TEMPLATE = '''#!/usr/bin/env python3
"""Managed by HOL Guard. Re-run hol-guard install after moving Guard home."""
from __future__ import annotations

import json
import os
import stat
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import quote, urlparse

GUARD_HOME = __GUARD_HOME__
HARNESS = __HARNESS__
TIMEOUT_SECONDS = __TIMEOUT_SECONDS__
_MAX_INPUT_BYTES = 1_000_000
_MAX_RESPONSE_BYTES = 1_000_000
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_DECISION_HARNESSES = frozenset({"grok", "hermes", "openclaw"})
_EVENT_ALIASES = {
    "permissionrequest": "PermissionRequest",
    "permissionrequestv2": "PermissionRequest",
    "pretooluse": "PreToolUse",
    "pretoolcall": "PreToolUse",
    "userpromptsubmit": "UserPromptSubmit",
    "posttooluse": "PostToolUse",
}
_EVENT_NAME_KEYS = ("hook_event_name", "hookEventName", "event", "eventName", "hook_name", "hookName")
_GROK_OBSERVE_EVENTS = frozenset(
    {
        "userpromptsubmit",
        "sessionstart",
        "sessionend",
        "subagentstart",
        "subagentstop",
        "posttooluse",
        "permissiondenied",
    }
)
_LIFECYCLE_EVENTS = _GROK_OBSERVE_EVENTS | frozenset(
    {
        "stop",
        "notification",
        "taskstart",
        "taskerror",
        "sessionshutdown",
        "userpromptsubmitted",
        "subagentend",
    }
)
_APPROVAL_KEYS = (
    "reason_code",
    "approval_url",
    "approval_request_id",
    "primary_approval_request_id",
    "primary_approval_url",
    "guardApprovalRequestId",
    "guardApprovalUrl",
    "approval_requests",
)
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


def _compact(event_name: str) -> str:
    return event_name.replace("_", "").replace("-", "").lower()


def _event_name(input_text: str) -> str:
    payload = _json_object(input_text or "{}")
    if payload is not None:
        for key in _EVENT_NAME_KEYS:
            value = payload.get(key)
            if isinstance(value, str):
                compact = _compact(value.strip())
                return _EVENT_ALIASES.get(compact, value.strip() or "PreToolUse")
    return "PreToolUse"


def _private_file_ok(metadata: os.stat_result) -> bool:
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        return False
    if os.name == "nt":
        return True
    return metadata.st_uid == os.getuid() and not stat.S_IMODE(metadata.st_mode) & 0o077


def _private_dir_ok(metadata: os.stat_result) -> bool:
    if not stat.S_ISDIR(metadata.st_mode):
        return False
    if os.name == "nt":
        return True
    return metadata.st_uid == os.getuid() and not stat.S_IMODE(metadata.st_mode) & 0o077


def _read_private_text(path: Path, *, max_bytes: int) -> str | None:
    try:
        parent_before = path.parent.lstat()
        path_before = path.lstat()
    except OSError:
        return None
    if not _private_dir_ok(parent_before) or not _private_file_ok(path_before):
        return None
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None
    try:
        opened = os.fstat(descriptor)
        if (
            not _private_file_ok(opened)
            or opened.st_dev != path_before.st_dev
            or opened.st_ino != path_before.st_ino
        ):
            return None
        if opened.st_size > max_bytes:
            return None
        chunks: list[bytes] = []
        consumed = 0
        while consumed < max_bytes:
            chunk = os.read(descriptor, min(64 * 1024, max_bytes - consumed))
            if not chunk:
                break
            chunks.append(chunk)
            consumed += len(chunk)
        closed = os.fstat(descriptor)
        if (
            closed.st_dev != opened.st_dev
            or closed.st_ino != opened.st_ino
            or closed.st_mode != opened.st_mode
            or closed.st_size != opened.st_size
            or closed.st_mtime_ns != opened.st_mtime_ns
            or closed.st_ctime_ns != opened.st_ctime_ns
        ):
            return None
        data = b"".join(chunks)
    finally:
        os.close(descriptor)
    try:
        parent_after = path.parent.lstat()
    except OSError:
        return None
    if (
        not _private_dir_ok(parent_after)
        or parent_after.st_dev != parent_before.st_dev
        or parent_after.st_ino != parent_before.st_ino
        or parent_after.st_mode != parent_before.st_mode
    ):
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _toml_scalar(raw: str, key: str) -> str:
    for line in raw.splitlines():
        stripped = line.split("#", 1)[0].strip()
        if not stripped or "=" not in stripped:
            continue
        left, right = stripped.split("=", 1)
        if left.strip() != key:
            continue
        return right.strip().strip('"').strip("'")
    return ""


def _recording_only() -> bool:
    raw = _read_private_text(Path(GUARD_HOME) / "config.toml", max_bytes=64 * 1024)
    if raw is None:
        return False
    return _toml_scalar(raw, "protection_posture") == "watch" or _toml_scalar(raw, "mode") == "observe"


def _approval_wait_seconds() -> float:
    raw = _read_private_text(Path(GUARD_HOME) / "config.toml", max_bytes=64 * 1024)
    configured = TIMEOUT_SECONDS
    if raw is not None:
        token = _toml_scalar(raw, "approval_wait_timeout_seconds")
        try:
            parsed = float(token)
        except ValueError:
            parsed = configured
        else:
            if parsed >= 0:
                configured = parsed
    return min(max(configured, 0.0), min(float(TIMEOUT_SECONDS) * 0.4, 80.0))


def _daemon_auth() -> tuple[str, int, str] | None:
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
    return host, port, auth


def _loopback_url(host: str, port: int, path: str) -> str:
    rendered = f"[{host}]" if host == "::1" else host
    return f"http://{rendered}:{port}{path}"


def _permission_decision(policy_action: str) -> str | None:
    if policy_action in {"allow", "warn"}:
        return "allow"
    if policy_action in {"review", "require-reapproval", "sandbox-required"}:
        return "ask"
    if policy_action == "block":
        return "deny"
    return None


def _should_exit_block(event_name: str, policy_action: str) -> bool:
    compact = _compact(event_name)
    blocking_events = {"pretooluse", "userpromptsubmit", "pretoolcall"}
    if HARNESS == "devin":
        blocking_events.add("permissionrequest")
    if HARNESS in {"kimi", "grok", "hermes", "pi", "omp", "zcode", "devin"} and compact in blocking_events:
        return policy_action in {"review", "require-reapproval", "sandbox-required", "block"}
    return False


def _is_permission_event(event_name: str) -> bool:
    return _compact(event_name) in {
        "permissionrequest",
        "permissionrequestv2",
        "copilotpermissionrequest",
    }


def _pauses_when_unavailable(event_name: str) -> bool:
    compact = _compact(event_name)
    if compact in _LIFECYCLE_EVENTS or compact.startswith("after"):
        return False
    return compact not in {"posttooluse", "posttool"}


def _copy_approval_metadata(source: dict[str, object], payload: dict[str, object]) -> None:
    for key in _APPROVAL_KEYS:
        value = source.get(key)
        if value is not None:
            payload[key] = value


def _hermes_policy(daemon_response: dict[str, object]) -> tuple[str, str]:
    decision = daemon_response.get("decision")
    reason = str(daemon_response.get("reason") or daemon_response.get("permission_decision_reason") or "")
    hook_specific = daemon_response.get("hookSpecificOutput")
    if isinstance(hook_specific, dict):
        nested_reason = hook_specific.get("permissionDecisionReason")
        if not reason and isinstance(nested_reason, str):
            reason = nested_reason
        permission = hook_specific.get("permissionDecision")
        if isinstance(permission, str) and permission.strip().lower() in {"deny", "ask"}:
            return "block", reason
        if isinstance(permission, str) and permission.strip().lower() == "allow":
            return "allow", reason
    if isinstance(decision, str) and decision.strip().lower() in {"block", "deny"}:
        return "block", reason
    if isinstance(decision, str) and decision.strip().lower() == "allow":
        return "allow", reason
    policy_action = daemon_response.get("policy_action")
    if isinstance(policy_action, str) and policy_action.strip():
        return policy_action.strip(), reason
    return "block", reason


def _to_native(daemon_response: dict[str, object], event_name: str) -> tuple[str, str, int]:
    if HARNESS == "grok" and not daemon_response and _compact(event_name) in _GROK_OBSERVE_EVENTS:
        return "{}", "", 0
    if HARNESS == "hermes":
        policy_action, reason = _hermes_policy(daemon_response)
        decision = "allow" if policy_action in {"allow", "warn"} else "block"
        payload = {"decision": decision, "reason": reason}
        stdout = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
        return stdout, "", 2 if decision == "block" else 0
    if "hookSpecificOutput" in daemon_response or "decision" in daemon_response:
        native_response = dict(daemon_response)
        policy = str(native_response.get("policy_action") or "block")
        exit_code = 2 if _should_exit_block(event_name, policy) else 0
        if HARNESS == "devin" and exit_code == 2:
            native_response["decision"] = "block"
            if not native_response.get("reason"):
                native_response["reason"] = f"HOL Guard blocked this action ({policy})"
        stdout = json.dumps(native_response, ensure_ascii=True, separators=(",", ":"))
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
            _copy_approval_metadata(daemon_response, payload)
    exit_code = 2 if _should_exit_block(event_name, policy_action) else 0
    if HARNESS == "devin" and exit_code == 2:
        payload["decision"] = "block"
        if not payload.get("reason"):
            payload["reason"] = reason or f"HOL Guard blocked this action ({policy_action})"
    stdout = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
    return stdout, reason if exit_code == 2 and HARNESS in {"kimi", "devin"} else "", exit_code


def _failure_payload(event_name: str, reason: str) -> tuple[dict[str, object], int]:
    if _recording_only():
        if HARNESS == "copilot":
            return {"permissionDecision": "allow"}, 0
        if HARNESS in _DECISION_HARNESSES:
            return {"decision": "allow"}, 0
        return {"hookSpecificOutput": {"hookEventName": event_name, "permissionDecision": "allow"}}, 0
    if not _pauses_when_unavailable(event_name):
        if HARNESS == "copilot":
            return {"permissionDecision": "allow"}, 0
        if HARNESS in _DECISION_HARNESSES:
            return {"decision": "allow", "reason": reason}, 0
        return {
            "continue": True,
            "systemMessage": reason,
            "hookSpecificOutput": {"hookEventName": event_name},
        }, 0
    if HARNESS == "copilot":
        if _is_permission_event(event_name):
            return {"behavior": "deny", "message": reason, "interrupt": False}, 0
        return {"permissionDecision": "deny", "permissionDecisionReason": reason}, 0
    if HARNESS in _DECISION_HARNESSES:
        decision = "block" if HARNESS == "hermes" else "deny"
        return {"decision": decision, "reason": reason}, (2 if HARNESS == "hermes" else 0)
    if _is_permission_event(event_name):
        return {"continue": False, "stopReason": reason, "systemMessage": reason}, 0
    return {
        "hookSpecificOutput": {
            "hookEventName": event_name,
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }, 2


def _fail(input_text: str, *, reason: str = _FAILURE_REASON) -> int:
    event_name = _event_name(input_text)
    payload, exit_code = _failure_payload(event_name, reason)
    sys.stdout.write(json.dumps(payload, ensure_ascii=True, separators=(",", ":")) + "\\n")
    if exit_code == 2 and HARNESS in {"kimi", "zcode", "devin"}:
        print(reason, file=sys.stderr)
    return exit_code


def _http_json(url: str, token: str, *, data: bytes | None, timeout: float) -> dict[str, object] | None:
    try:
        _assert_loopback_http_url(url)
    except ValueError:
        return None
    headers = {"X-Guard-Token": token}
    method = "GET"
    if data is not None:
        headers["Content-Type"] = "application/json"
        method = "POST"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
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
    return _json_object(text.strip())


def _approval_request_ids(payload: dict[str, object]) -> list[str]:
    ids: list[str] = []
    queued = payload.get("approval_requests")
    if isinstance(queued, list):
        for item in queued:
            if isinstance(item, dict):
                request_id = item.get("request_id")
                if isinstance(request_id, str) and request_id.strip():
                    ids.append(request_id.strip())
    if ids:
        return ids
    for key in ("primary_approval_request_id", "approval_request_id", "guardApprovalRequestId"):
        request_id = payload.get(key)
        if isinstance(request_id, str) and request_id.strip():
            return [request_id.strip()]
    return []


def _rewrite_grok_decision(payload: dict[str, object], *, allowed: bool) -> dict[str, object]:
    updated = dict(payload)
    updated["decision"] = "allow" if allowed else "deny"
    updated["policy_action"] = "allow" if allowed else "block"
    if allowed:
        updated.pop("reason", None)
    hook_specific = updated.get("hookSpecificOutput")
    if isinstance(hook_specific, dict):
        rewritten = dict(hook_specific)
        rewritten["permissionDecision"] = "allow" if allowed else "deny"
        if allowed:
            rewritten.pop("permissionDecisionReason", None)
        updated["hookSpecificOutput"] = rewritten
    return updated


def _apply_grok_wait(input_text: str, native: tuple[str, str, int]) -> tuple[str, str, int]:
    stdout, stderr, exit_code = native
    if HARNESS != "grok" or _event_name(input_text) != "PreToolUse":
        return native
    payload = _json_object(stdout)
    if payload is None:
        return native
    if str(payload.get("policy_action") or "") not in {"review", "require-reapproval"}:
        return native
    request_ids = _approval_request_ids(payload)
    if not request_ids:
        return native
    auth = _daemon_auth()
    if auth is None:
        return native
    host, port, token = auth
    wait_seconds = _approval_wait_seconds()
    if wait_seconds <= 0:
        return native
    deadline = time.monotonic() + wait_seconds
    resolved: dict[str, str] = {}
    while time.monotonic() < deadline and len(resolved) < len(request_ids):
        for request_id in request_ids:
            if request_id in resolved:
                continue
            url = _loopback_url(host, port, "/v1/requests/" + quote(request_id, safe=""))
            remaining = max(0.05, deadline - time.monotonic())
            status = _http_json(url, token, data=None, timeout=min(remaining, 1.0))
            if status is None:
                continue
            action = status.get("resolution_action")
            if isinstance(action, str) and action.strip():
                resolved[request_id] = action.strip().lower()
        if len(resolved) < len(request_ids):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(0.2, remaining))
    if len(resolved) != len(request_ids):
        return native
    allowed = all(action == "allow" for action in resolved.values())
    rewritten = _rewrite_grok_decision(payload, allowed=allowed)
    text = json.dumps(rewritten, ensure_ascii=True, separators=(",", ":"))
    return text, stderr, 0 if allowed else exit_code


def _post_hook(input_text: str) -> tuple[str, str, int] | None:
    auth = _daemon_auth()
    if auth is None:
        return None
    host, port, token = auth
    url = _loopback_url(host, port, f"/v1/hooks/{HARNESS}")
    timeout = min(float(TIMEOUT_SECONDS) * 0.5, 5.0)
    parsed = _http_json(url, token, data=input_text.encode("utf-8"), timeout=timeout)
    if parsed is None:
        return None
    return _apply_grok_wait(input_text, _to_native(parsed, _event_name(input_text)))


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
