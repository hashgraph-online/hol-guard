"""Stdlib-only bounded hook client that fans into the running Guard daemon."""

from __future__ import annotations

from .bounded_cli_hook_script_native import BOUNDED_HOOK_NATIVE_TEMPLATE
from .grok_hook_invocation_template import GROK_HOOK_INVOCATION_TEMPLATE
from .grok_hook_readiness_template import GROK_HOOK_READINESS_TEMPLATE
from .hook_http_deadline import HOOK_HTTP_DEADLINE_TEMPLATE
from .hook_input_reader import HOOK_INPUT_READER_TEMPLATE

BOUNDED_HOOK_SCRIPT_TEMPLATE = (
    '''#!/usr/bin/env python3
"""Managed by HOL Guard. Re-run hol-guard install after moving Guard home."""
from __future__ import annotations

import hashlib
import time
_HOOK_STARTED_MONOTONIC = time.monotonic()

import json
import os
import stat
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import quote, urlparse

GUARD_HOME = __GUARD_HOME__
HARNESS = __HARNESS__
TIMEOUT_SECONDS = __TIMEOUT_SECONDS__
_HOOK_DEADLINE_MONOTONIC = _HOOK_STARTED_MONOTONIC + TIMEOUT_SECONDS
__HOOK_INPUT_READER__
__HOOK_HTTP_DEADLINE__
_MAX_RESPONSE_BYTES = 1_000_000
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_DECISION_HARNESSES = frozenset({"grok", "hermes", "openclaw"})
_EVENT_ALIASES = {
    "permissionrequest": "PermissionRequest",
    "permissionrequestv2": "PermissionRequest",
    "pretooluse": "PreToolUse",
    "pretoolcall": "PreToolUse",
    "userpromptsubmit": "UserPromptSubmit",
    "userpromptsubmitted": "UserPromptSubmit",
    "posttooluse": "PostToolUse",
}
_EVENT_NAME_KEYS = ("hook_event_name", "hookEventName", "event", "eventName", "hook_name", "hookName")
_GROK_OBSERVE_EVENTS = frozenset(
    {
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
_FAILURE_REASON = "HOL Guard could not complete a trusted hook decision. Retry or repair Guard from a terminal."
_AUTHORITY_MARKER = "native command extension policy"
_AUTHORITY_REMEDIATION = (
    " Run `hol-guard command controls acknowledge-degraded` after reviewing the "
    "degradation, or `hol-guard command controls recover-authority`, to restore the "
    "protected control floor."
)
_GIT_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})


def _git_config_no_system_enabled(value: str | None) -> bool:
    return value is not None and value.casefold() in _GIT_TRUE_VALUES


def _stderr_reason(reason: str) -> str:
    if (
        HARNESS == "zcode"
        and _AUTHORITY_MARKER in reason
        and "hol-guard command controls" not in reason
    ):
        return reason + _AUTHORITY_REMEDIATION
    return reason


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


def _stamp_hook_input(text: str) -> str:
    payload = _json_object(text)
    if payload is None:
        return text
    active = {key: value for key, value in os.environ.items() if value}
    payload["guard_execution_environment"] = {
        "path": os.environ.get("PATH", ""),
        "environment_names": sorted(active),
        "environment_digest": hashlib.sha256(
            json.dumps(active, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "xdg_config_home": os.environ.get("XDG_CONFIG_HOME") or None,
        "git_config_no_system": _git_config_no_system_enabled(
            os.environ.get("GIT_CONFIG_NOSYSTEM")
        ),
        "home": os.environ.get("HOME"),
        "git_pager_disabled": os.environ.get("GIT_PAGER") in ("", "cat"),
        "pager_disabled": os.environ.get("PAGER") in ("", "cat"),
    }
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":"))


def _compact(event_name: str) -> str:
    return event_name.replace("_", "").replace("-", "").lower()


def _grok_pretool_event_conflict(input_text: str) -> bool:
    payload = _json_object(input_text) or {}
    events = {_compact(value.strip()) for key in _EVENT_NAME_KEYS if isinstance(value := payload.get(key), str)}
    if "pretoolcall" in events:
        events.discard("pretoolcall")
        events.add("pretooluse")
    return "pretooluse" in events and len(events) > 1


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
    if time.monotonic() >= _HOOK_DEADLINE_MONOTONIC:
        return None
    raw_state = _read_private_text(Path(GUARD_HOME) / "daemon-state.json", max_bytes=64 * 1024)
    if raw_state is None or time.monotonic() >= _HOOK_DEADLINE_MONOTONIC:
        return None
    token = _read_private_text(Path(GUARD_HOME) / "daemon-auth-token", max_bytes=4096)
    if token is None or time.monotonic() >= _HOOK_DEADLINE_MONOTONIC:
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
    query = "?home=" + quote(_GROK_HOME, safe="") if HARNESS == "grok" and _GROK_HOME is not None else ""
    return f"http://{rendered}:{port}{path}{query}"


__HOOK_NATIVE_RESPONSES__
def _http_json(url: str, token: str, *, data: bytes | None, timeout: float) -> dict[str, object] | None:
    deadline = min(_HOOK_DEADLINE_MONOTONIC, time.monotonic() + timeout)
    if time.monotonic() >= deadline:
        return None
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
            _deadline_http_handler(deadline),
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
    if time.monotonic() >= deadline or len(body) > _MAX_RESPONSE_BYTES:
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
    deadline = min(time.monotonic() + wait_seconds, _HOOK_DEADLINE_MONOTONIC)
    resolved: dict[str, str] = {}
    while time.monotonic() < deadline and len(resolved) < len(request_ids):
        for request_id in request_ids:
            if request_id in resolved:
                continue
            url = _loopback_url(host, port, "/v1/requests/" + quote(request_id, safe=""))
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
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


__GROK_HOOK_READINESS__
__GROK_HOOK_INVOCATION__

def _post_hook(input_text: str) -> tuple[str, str, int] | None:
    if HARNESS == "grok":
        input_text = _grok_invocation_payload(input_text)
    if time.monotonic() >= _HOOK_DEADLINE_MONOTONIC:
        return None
    auth = _daemon_auth()
    if auth is None:
        return None
    host, port, token = auth
    url = _loopback_url(host, port, f"/v1/hooks/{HARNESS}")
    transport_cap = 10.0 if HARNESS == "grok" and _event_name(input_text) == "UserPromptSubmit" else 5.0
    timeout = min(float(TIMEOUT_SECONDS) * 0.5, transport_cap, _HOOK_DEADLINE_MONOTONIC - time.monotonic())
    if HARNESS == "grok" and _compact(_event_name(input_text)) in _GROK_OBSERVE_EVENTS:
        # Keep the daemon request within 1s of Grok's 15s outer hook lifetime.
        # Observations must not hold up a session on an unavailable daemon.
        timeout = min(timeout, 1.0)
    if timeout <= 0:
        return None
    if HARNESS == "grok" and _event_name(input_text) == "UserPromptSubmit":
        deadline = min(_HOOK_DEADLINE_MONOTONIC, time.monotonic() + timeout)
        input_text = _prepare_grok_prompt(input_text, host, port, token, deadline)
        if input_text is None:
            return None
        timeout = deadline - time.monotonic()
        if timeout <= 0:
            return None
    parsed = _http_json(url, token, data=input_text.encode("utf-8"), timeout=timeout)
    if parsed is None:
        return None
    return _apply_grok_wait(input_text, _to_native(parsed, _event_name(input_text)))


def main() -> int:
    try:
        prefix = _read_hook_input(_HOOK_DEADLINE_MONOTONIC)
    except _HookInputError as error:
        return _fail(
            error.prefix,
            reason="HOL Guard blocked this action because hook input exceeded the safe size limit.",
        )
    except (TimeoutError, OSError, ValueError):
        return _fail("{}")
    if HARNESS == "grok" and not _configure_grok_invocation():
        return _fail(prefix)
    if HARNESS == "grok" and _grok_pretool_event_conflict(prefix):
        return _fail(prefix, reason="HOL Guard blocked this action because hook event labels conflict.")
    stamped_prefix = _stamp_hook_input(prefix)
    result = _post_hook(stamped_prefix)
    if result is None or time.monotonic() >= _HOOK_DEADLINE_MONOTONIC:
        return _fail(prefix)
    stdout, stderr, exit_code = result
    if stdout:
        sys.stdout.write(stdout if stdout.endswith("\\n") else stdout + "\\n")
    if stderr:
        print(stderr, file=sys.stderr)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
'''.replace("__HOOK_INPUT_READER__", HOOK_INPUT_READER_TEMPLATE)
    .replace("__HOOK_HTTP_DEADLINE__", HOOK_HTTP_DEADLINE_TEMPLATE)
    .replace("__GROK_HOOK_READINESS__", GROK_HOOK_READINESS_TEMPLATE)
    .replace("__GROK_HOOK_INVOCATION__", GROK_HOOK_INVOCATION_TEMPLATE)
    .replace("__HOOK_NATIVE_RESPONSES__\n", BOUNDED_HOOK_NATIVE_TEMPLATE)
)
