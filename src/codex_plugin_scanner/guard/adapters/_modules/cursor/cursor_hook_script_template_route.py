"""Installed Cursor hook copy for the silent ``preToolUse`` probe for ``Shell``."""

from __future__ import annotations

HOOK_SCRIPT_TEMPLATE_ROUTE = """
_CURSOR_ROUTED_REASON = "native_contained_execution_routed"


def _cursor_shell_route_probe(prepared: dict[str, object]) -> bool:
    # beforeShellExecution prepares as a Shell call that names its source hook.
    return (
        prepared.get("hook_event_name") == "PreToolUse"
        and prepared.get("tool_name") == "Shell"
        and "cursor_source_hook_event" not in prepared
    )


def _cursor_refuse_constant(_text: str) -> object:
    raise ValueError("non-finite number")


def _cursor_finite_float(text: str) -> float:
    value = float(text)
    if value != value or value in (float("inf"), float("-inf")):
        raise ValueError("non-finite number")
    return value


def _cursor_shell_route_response(body: str) -> dict[str, object]:
    # Only a call the daemon rewrote into the contained sink changes; anything
    # else is a plain allow, as beforeShellExecution reviews the call that runs.
    allow: dict[str, object] = {"permission": "allow"}
    try:
        response = json.loads(
            body.strip(), parse_constant=_cursor_refuse_constant, parse_float=_cursor_finite_float
        )
        json.dumps(response, ensure_ascii=False).encode("utf-8")
    except (ValueError, UnicodeError, RecursionError):
        return allow
    if not isinstance(response, dict):
        return allow
    if response.get("policy_action") != "allow" or response.get("reason_code") != _CURSOR_ROUTED_REASON:
        return allow
    output = response.get("hookSpecificOutput")
    updated = output.get("updatedInput") if isinstance(output, dict) else None
    if not isinstance(updated, dict) or not isinstance(updated.get("command"), str):
        return allow
    return {"permission": "allow", "updated_input": updated}


def _cursor_shell_route_main(payload_json: str, workspace: str | None, guard_env: dict[str, str]) -> int:
    # The probe records nothing and never restarts the daemon or runs the CLI.
    try:
        result, _failure_kind = _daemon_hook_result(
            payload_json,
            deadline_monotonic=_HOOK_DEADLINE_MONOTONIC,
            workspace=workspace,
            hook_env_overlay=_daemon_hook_env_overlay(guard_env),
        )
    except Exception:
        result = None
    body = result[1] if result is not None else ""
    print(json.dumps(_cursor_shell_route_response(body), sort_keys=True))
    return 0
"""
