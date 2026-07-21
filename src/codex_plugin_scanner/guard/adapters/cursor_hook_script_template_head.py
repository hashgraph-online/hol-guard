"""First half of the generated Cursor hook script template."""

from __future__ import annotations

HOOK_SCRIPT_TEMPLATE_HEAD = '''#!/usr/bin/env python3
"""Managed by HOL Guard. Re-run `hol-guard install cursor` after moving Guard home."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import shlex
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from pathlib import Path

GUARD_HOME = __GUARD_HOME__
GUARD_CLI = __GUARD_CLI__
GUARD_HOOK_ARGV = __GUARD_HOOK_ARGV__
GUARD_INHERIT_ENV_KEYS = __GUARD_INHERIT_ENV_KEYS__
GUARD_HOOK_TIMEOUT_SECONDS = __GUARD_HOOK_TIMEOUT_SECONDS__
GUARD_ACTIONS = frozenset({"allow", "warn", "review", "require-reapproval", "sandbox-required", "block"})


def _hook_process_env() -> dict[str, str]:
    env: dict[str, str] = {}
    for key in GUARD_INHERIT_ENV_KEYS:
        value = os.environ.get(key)
        if isinstance(value, str) and value:
            env[key] = value
    dev_src = os.environ.get("HOL_GUARD_SRC")
    validated = _validated_hol_guard_src_path(dev_src) if isinstance(dev_src, str) else None
    if validated is not None:
        env["PYTHONPATH"] = validated
    else:
        dev_src_file = Path(GUARD_HOME) / "cursor-dev-src"
        if dev_src_file.is_file():
            try:
                configured_src = dev_src_file.read_text(encoding="utf-8").strip()
            except OSError:
                configured_src = ""
            validated = _validated_hol_guard_src_path(configured_src)
            if validated is not None:
                env["PYTHONPATH"] = validated
    return env


def _guard_hook_arg_value(flag: str) -> str | None:
    try:
        index = GUARD_HOOK_ARGV.index(flag)
    except ValueError:
        return None
    if index + 1 >= len(GUARD_HOOK_ARGV):
        return None
    value = GUARD_HOOK_ARGV[index + 1]
    return value if isinstance(value, str) and value.strip() else None


def _daemon_hook_env_overlay(guard_env: Mapping[str, str]) -> dict[str, str]:
    overlay: dict[str, str] = {}
    for key in (
        "HOL_GUARD_MANAGED_CURSOR_HOOK",
        "HOL_GUARD_CURSOR_APPROVAL_BINDING",
        "HOL_GUARD_CURSOR_AFTER_SHELL_PROOF",
        "CURSOR_PROJECT_DIR",
        "CURSOR_VERSION",
        "CURSOR_TRACE_ID",
        "CURSOR_SESSION_ID",
        "CURSOR_TRANSCRIPT_PATH",
    ):
        value = guard_env.get(key)
        if isinstance(value, str) and value:
            overlay[key] = value
    return overlay


def _daemon_hook_result(
    payload_json: str,
    *,
    workspace: str | None,
    hook_env_overlay: Mapping[str, str] | None = None,
) -> tuple[int, str, str] | None:
    state_path = Path(GUARD_HOME) / "daemon-state.json"
    token_path = Path(GUARD_HOME) / "daemon-auth-token"
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
        auth_token = token_path.read_text(encoding="utf-8").strip()
    except (OSError, ValueError):
        return None
    if not isinstance(state, dict):
        return None
    port = state.get("port")
    if not isinstance(port, int) or port <= 0 or not auth_token:
        return None
    # Validate the recorded PID is still alive before trusting the state file.
    # A stale state file after a crash could point at an attacker-controlled listener.
    pid = state.get("pid")
    if not isinstance(pid, int) or pid <= 0:
        return None
    try:
        os.kill(pid, 0)
    except OSError:
        return None
    # Probe /healthz before sending the hook payload and auth token.
    # Ensures the listener is actually the Guard daemon, not a spoofed process.
    # Validate the response body — not just HTTP 200 — so an attacker listener
    # that returns 200 but doesn't know the daemon's compatibility version is rejected.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        health_req = urllib.request.Request(f"http://127.0.0.1:{port}/healthz", method="GET")
        with opener.open(health_req, timeout=2) as health_response:
            if health_response.status != 200:
                return None
            health_body = health_response.read().decode("utf-8", errors="replace")
    except (OSError, urllib.error.URLError):
        return None
    try:
        health_json = json.loads(health_body)
    except ValueError:
        return None
    if not isinstance(health_json, dict) or health_json.get("ok") is not True:
        return None
    state_compat = state.get("compatibility_version")
    if isinstance(state_compat, str) and health_json.get("compatibility_version") != state_compat:
        return None
    # Challenge-response: prove the listener knows the auth_token before sending it.
    # A spoofed listener can return public healthz values but cannot forge the HMAC.
    # The proof is bound to the daemon's listening port so a relay attacker cannot
    # proxy the nonce to the real daemon and reuse its proof from a different port.
    # Old daemons without /v1/healthz/verify fail with HTTPError — return None to
    # fall through to the CLI path. Never bypass the HMAC challenge.
    nonce = os.urandom(16).hex()
    proof_message = f"{port}:{nonce}"
    try:
        verify_req = urllib.request.Request(
            f"http://127.0.0.1:{port}/v1/healthz/verify",
            data=json.dumps({"nonce": nonce}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with opener.open(verify_req, timeout=2) as verify_response:
            verify_body = verify_response.read().decode("utf-8", errors="replace")
            try:
                verify_json = json.loads(verify_body)
            except ValueError:
                return None
            if not isinstance(verify_json, dict) or not isinstance(verify_json.get("proof"), str):
                return None
            expected_proof = hmac.new(
                auth_token.encode("utf-8"),
                proof_message.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(verify_json["proof"], expected_proof):
                return None
    except (urllib.error.HTTPError, OSError, urllib.error.URLError):
        return None
    params = [("guard-home", GUARD_HOME)]
    if workspace:
        params.append(("workspace", workspace))
    home_dir = _guard_hook_arg_value("--home")
    if home_dir:
        params.append(("home", home_dir))
    try:
        request_payload = json.loads(payload_json)
    except ValueError:
        return None
    if not isinstance(request_payload, dict):
        return None
    if hook_env_overlay:
        request_payload["hook_env"] = dict(hook_env_overlay)
    query = urllib.parse.urlencode(params)
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/v1/hooks/cursor?{query}",
        data=json.dumps(request_payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-Guard-Token": auth_token,
        },
        method="POST",
    )
    try:
        with opener.open(request, timeout=max(GUARD_HOOK_TIMEOUT_SECONDS - 2, 1)) as response:
            body = response.read().decode("utf-8", errors="replace")
    except (OSError, urllib.error.URLError):
        return None
    # Reject empty or non-dict responses — they default policy_action to "allow".
    # Fall through to the CLI subprocess path instead of trusting a malformed response.
    body_stripped = body.strip()
    if not body_stripped:
        return None
    try:
        parsed_body = json.loads(body_stripped)
    except ValueError:
        return None
    if not isinstance(parsed_body, dict):
        return None
    raw_event_name = _raw_hook_event_name(request_payload)
    if raw_event_name not in {"aftershellexecution", "aftermcpexecution"}:
        policy_action = parsed_body.get("policy_action")
        if not isinstance(policy_action, str) or policy_action not in GUARD_ACTIONS:
            return None
    return (0, body_stripped, "")


def _validated_hol_guard_src_path(path_str: str) -> str | None:
    try:
        if not isinstance(path_str, str) or not path_str.strip():
            return None
        candidate = Path(path_str.strip()).expanduser().resolve()
    except (OSError, RuntimeError, ValueError, TypeError):
        return None
    if not candidate.is_dir():
        return None
    if not (candidate / "codex_plugin_scanner").is_dir():
        return None
    return str(candidate)


def _workspace_from_cursor_input(payload: dict[str, object]) -> str | None:
    project_dir = os.environ.get("CURSOR_PROJECT_DIR")
    if isinstance(project_dir, str) and project_dir.strip():
        candidate = project_dir.strip()
        if Path(candidate).is_dir():
            return candidate
    roots = payload.get("workspace_roots") or payload.get("workspaceRoots")
    if isinstance(roots, list):
        for item in roots:
            if isinstance(item, str) and item.strip():
                candidate = item.strip()
                if Path(candidate).is_dir():
                    return candidate
    cwd = payload.get("cwd")
    if isinstance(cwd, str) and cwd.strip():
        candidate = cwd.strip()
        if Path(candidate).is_dir():
            return candidate
    return None


def _tool_input_dict(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, list):
        return {"arguments": list(value)}
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {"raw": value.strip()}
        if isinstance(parsed, dict):
            return dict(parsed)
        if isinstance(parsed, list):
            return {"arguments": list(parsed)}
    return {}


def _raw_hook_event_name(payload: dict[str, object]) -> str:
    for key in ("hook_event_name", "hookEventName", "hook_name", "hookName", "event", "eventName"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    return ""


def _infer_cursor_hook_event_name(payload: dict[str, object]) -> dict[str, object]:
    normalized = dict(payload)
    if _raw_hook_event_name(normalized):
        return normalized
    file_path = normalized.get("file_path")
    if isinstance(file_path, str) and file_path.strip():
        normalized["hook_event_name"] = "beforeReadFile"
        return normalized
    command = normalized.get("command")
    if isinstance(command, str) and command.strip():
        normalized["hook_event_name"] = "beforeShellExecution"
        return normalized
    if normalized.get("tool_name") is not None or normalized.get("tool_input") is not None:
        normalized["hook_event_name"] = "preToolUse"
    return normalized


def _cursor_shell_hook_payload(normalized: dict[str, object], hook_event_name: str) -> dict[str, object]:
    payload = dict(normalized)
    payload["hook_event_name"] = hook_event_name
    payload.setdefault("tool_name", "Shell")
    tool_input = _tool_input_dict(payload.get("tool_input"))
    command = payload.get("command")
    if isinstance(command, str) and command.strip():
        tool_input.setdefault("command", command.strip())
    cwd = payload.get("cwd")
    if isinstance(cwd, str) and cwd.strip():
        tool_input.setdefault("working_directory", cwd.strip())
    payload["tool_input"] = tool_input
    return payload


def _cursor_mcp_hook_payload(normalized: dict[str, object], hook_event_name: str) -> dict[str, object]:
    payload = dict(normalized)
    payload["hook_event_name"] = hook_event_name
    tool_input = _tool_input_dict(payload.get("tool_input"))
    payload["tool_input"] = tool_input
    tool_name = payload.get("tool_name")
    if isinstance(tool_name, str) and tool_name.strip():
        payload["tool_name"] = tool_name.strip()
    else:
        payload.setdefault("tool_name", "MCP")
    return payload


def _prepare_cursor_hook_payload(payload: dict[str, object]) -> dict[str, object]:
    normalized = _infer_cursor_hook_event_name(payload)
    raw_event = _raw_hook_event_name(normalized)
    if raw_event == "aftershellexecution":
        return _cursor_shell_hook_payload(normalized, "afterShellExecution")
    if raw_event == "aftermcpexecution":
        return _cursor_mcp_hook_payload(normalized, "afterMCPExecution")
    if raw_event == "beforeshellexecution":
        prepared = _cursor_shell_hook_payload(normalized, "PreToolUse")
        prepared["cursor_source_hook_event"] = "beforeShellExecution"
        return prepared
    if raw_event == "beforemcpexecution":
        prepared = _cursor_mcp_hook_payload(normalized, "PreToolUse")
        tool_input = _tool_input_dict(prepared.get("tool_input"))
        for key in ("url", "command"):
            value = normalized.get(key)
            if isinstance(value, str) and value.strip():
                tool_input.setdefault(key, value.strip())
        prepared["tool_input"] = tool_input
        prepared["cursor_source_hook_event"] = "beforeMCPExecution"
        return prepared
    if raw_event == "beforereadfile":
        normalized["hook_event_name"] = "PreToolUse"
        normalized.setdefault("tool_name", "Read")
        tool_input = _tool_input_dict(normalized.get("tool_input"))
        file_path = normalized.get("file_path")
        if isinstance(file_path, str) and file_path.strip():
            tool_input.setdefault("file_path", file_path.strip())
            tool_input.setdefault("path", file_path.strip())
        normalized["tool_input"] = tool_input
        return normalized
    if raw_event == "pretooluse":
        normalized["hook_event_name"] = "PreToolUse"
    return normalized


def _cursor_permission(policy_action: str, guard_payload: dict[str, object]) -> str:
    del guard_payload
    if policy_action not in GUARD_ACTIONS:
        return "deny"
    if policy_action in {"block", "sandbox-required"}:
        return "deny"
    if policy_action in {"require-reapproval", "review"}:
        return "ask"
    return "allow"


def _cursor_read_file_permission(permission: str) -> str:
    if permission in {"deny", "ask"}:
        return "deny"
    return "allow"


def _cursor_reason(guard_payload: dict[str, object]) -> str:
    primary_url = guard_payload.get("primary_approval_url")
    reason: str | None = None
    for key in ("review_hint", "risk_summary", "why_now", "risk_headline"):
        value = guard_payload.get(key)
        if isinstance(value, str) and value.strip():
            reason = value.strip()
            break
    if reason is None:
        decision = guard_payload.get("decision_v2_json")
        if isinstance(decision, Mapping):
            for key in ("harness_message", "retry_instruction", "user_body", "user_title"):
                value = decision.get(key)
                if isinstance(value, str) and value.strip():
                    reason = value.strip()
                    break
    if reason is None:
        if isinstance(primary_url, str) and primary_url.strip():
            return f"HOL Guard needs approval for this Cursor action. Review it at {primary_url.strip()}."
        return "HOL Guard blocked this Cursor action."
    if isinstance(primary_url, str) and primary_url.strip():
        url_str = primary_url.strip()
        if url_str in reason:
            return reason
        return f"{reason} Review: {url_str}"
    return reason


'''
