"""Fast, authenticated bridge from Codex hooks to the local Guard daemon."""

from __future__ import annotations

import json
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path

if __package__:
    from ..codex_hook_bridge_runtime import BridgeConfig
    from ..codex_hook_bridge_runtime import bounded_hook_input as _hook_input
    from ..codex_hook_bridge_runtime import bridge_config_from_argv as _parse_bridge_config
    from ..config import MAX_APPROVAL_WAIT_TIMEOUT_SECONDS
    from ..live_process_identity import (
        CODEX_BROWSER_WAIT_PROCESS_KEY,
        CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY,
        current_process_identity,
    )
    from .codex_daemon_hook_bridge_flow import bridge_review_response
    from .codex_daemon_hook_resume import apply_browser_approval_wait
else:  # pragma: no cover - exercised by subprocess integration tests
    _package_root = str(Path(__file__).resolve().parents[3])
    if _package_root not in sys.path:
        sys.path.insert(0, _package_root)
    from codex_plugin_scanner.guard.adapters.codex_daemon_hook_bridge_flow import (
        bridge_review_response,
    )
    from codex_plugin_scanner.guard.adapters.codex_daemon_hook_resume import (
        apply_browser_approval_wait,
    )
    from codex_plugin_scanner.guard.codex_hook_bridge_runtime import (
        BridgeConfig,
    )
    from codex_plugin_scanner.guard.codex_hook_bridge_runtime import (
        bounded_hook_input as _hook_input,
    )
    from codex_plugin_scanner.guard.codex_hook_bridge_runtime import (
        bridge_config_from_argv as _parse_bridge_config,
    )
    from codex_plugin_scanner.guard.config import MAX_APPROVAL_WAIT_TIMEOUT_SECONDS
    from codex_plugin_scanner.guard.live_process_identity import (
        CODEX_BROWSER_WAIT_PROCESS_KEY,
        CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY,
        current_process_identity,
    )

_HOOK_TIMEOUT_GRACE_SECONDS = 2
_DISCOVERY_PROTOCOL_VERSION = 1
_MAX_HOOK_INPUT_BYTES = 1_000_000
_FAIL_CLOSED_REASON = "HOL Guard could not authenticate the local daemon. Run `hol-guard daemon repair`, then retry."
_LAUNCH_INTEGRITY_REASON = (
    "HOL Guard could not authenticate its managed Codex hook launcher. Run `hol-guard install codex`, then retry."
)
_OVERLOAD_REASON = (
    "HOL Guard is temporarily saturated and kept this action blocked. No approval was requested; retry the action."
)


def _json_object(text: str) -> dict[str, object] | None:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _event_name(data: str) -> str:
    payload = _json_object(data)
    if payload is None:
        return "PreToolUse"
    value = payload.get("hook_event_name", payload.get("event", "PreToolUse"))
    return value.strip() if isinstance(value, str) and value.strip() else "PreToolUse"


def _with_browser_wait_process(data: str, *, wait_timeout_seconds: float) -> str:
    payload = _json_object(data)
    if payload is None:
        return data
    process_identity = current_process_identity()
    if process_identity is None:
        payload.pop(CODEX_BROWSER_WAIT_PROCESS_KEY, None)
        payload.pop(CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY, None)
    else:
        payload[CODEX_BROWSER_WAIT_PROCESS_KEY] = process_identity
        payload[CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY] = min(
            MAX_APPROVAL_WAIT_TIMEOUT_SECONDS,
            max(1, int(wait_timeout_seconds)),
        )
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":"))


def _request_timeout(event_name: str, hook_timeouts: Mapping[str, int]) -> float:
    timeout = hook_timeouts.get(event_name, min(hook_timeouts.values(), default=10))
    return float(max(1, timeout - _HOOK_TIMEOUT_GRACE_SECONDS))


def _fail_closed(event_name: str, reason: str = _FAIL_CLOSED_REASON) -> dict[str, object]:
    if event_name == "PermissionRequest":
        return {
            "hookSpecificOutput": {
                "hookEventName": event_name,
                "decision": {
                    "behavior": "deny",
                    "message": reason,
                },
            }
        }
    if event_name == "PreToolUse":
        return {
            "hookSpecificOutput": {
                "hookEventName": event_name,
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }
    if event_name == "PostToolUse":
        return {
            "continue": False,
            "stopReason": reason,
            "systemMessage": reason,
        }
    return {
        "continue": False,
        "stopReason": reason,
        "systemMessage": reason,
    }


def _unavailable_response(event_name: str, reason: str) -> dict[str, object]:
    if event_name == "UserPromptSubmit":
        return {
            "continue": True,
            "systemMessage": reason,
        }
    return _fail_closed(event_name, reason)


def _codex_hook_response(response: Mapping[str, object], *, event_name: str) -> dict[str, object]:
    """Keep daemon metadata out of Codex's strict hook response schemas."""

    universal_keys = {"continue", "stopReason", "suppressOutput", "systemMessage"}
    event_keys = {
        "PostToolUse": {"decision", "reason"},
    }.get(event_name, set())
    allowed_keys = universal_keys | event_keys | {"hookSpecificOutput"}
    filtered = {key: value for key, value in response.items() if key in allowed_keys}
    hook_output = filtered.get("hookSpecificOutput")
    if event_name == "PostToolUse":
        if not isinstance(hook_output, Mapping):
            filtered.pop("hookSpecificOutput", None)
        else:
            post_tool_keys = {"hookEventName", "additionalContext", "updatedMCPToolOutput"}
            filtered["hookSpecificOutput"] = {key: value for key, value in hook_output.items() if key in post_tool_keys}
    return filtered


def _bound_hook_input(hook_timeouts: Mapping[str, int]) -> tuple[str, str, float] | None:
    raw_data = _hook_input(_MAX_HOOK_INPUT_BYTES)
    if raw_data is None:
        return None
    event_name = _event_name(raw_data)
    timeout_seconds = _request_timeout(event_name, hook_timeouts)
    data = (
        _with_browser_wait_process(raw_data, wait_timeout_seconds=max(1.0, timeout_seconds - 1.0))
        if event_name == "PreToolUse"
        else raw_data
    )
    return event_name, data, timeout_seconds


def main(
    *,
    state_path: str | Path,
    fallback_command: Sequence[str],
    start_command: Sequence[str],
    query: str,
    hook_timeouts: Mapping[str, int],
    manifest_path: str | Path | None = None,
    config_json: str | None = None,
) -> int:
    """Review one Codex hook through the resident daemon or a fail-safe fallback."""

    hook_input = _bound_hook_input(hook_timeouts)
    if hook_input is None:
        sys.stdout.write(json.dumps(_fail_closed("PreToolUse"), separators=(",", ":")))
        return 0
    event_name, data, timeout_seconds = hook_input
    deadline = time.monotonic() + timeout_seconds
    response, daemon_overloaded, launch_integrity_failed = bridge_review_response(
        state_path=state_path,
        fallback_command=fallback_command,
        start_command=start_command,
        query=query,
        data=data,
        deadline=deadline,
        manifest_path=manifest_path,
        config_json=config_json,
    )
    if response is None:
        failure_reason = (
            _OVERLOAD_REASON
            if daemon_overloaded
            else _LAUNCH_INTEGRITY_REASON
            if launch_integrity_failed
            else _FAIL_CLOSED_REASON
        )
        response = _unavailable_response(event_name, failure_reason)
    sys.stdout.write(
        _bridge_output(
            response,
            event_name=event_name,
            hook_input=data,
            state_path=state_path,
            deadline=deadline,
        )
    )
    return 0


def _bridge_output(
    response: dict[str, object],
    *,
    event_name: str,
    hook_input: str,
    state_path: str | Path,
    deadline: float,
) -> str:
    payload = apply_browser_approval_wait(
        response,
        event_name=event_name,
        hook_input=hook_input,
        state_path=state_path,
        deadline=deadline,
    )
    return json.dumps(_codex_hook_response(payload, event_name=event_name), separators=(",", ":"))


def _bridge_config_from_argv(argv: Sequence[str]) -> BridgeConfig:
    return _parse_bridge_config(argv, timeout_grace_seconds=_HOOK_TIMEOUT_GRACE_SECONDS)


if __name__ == "__main__":
    _config = _bridge_config_from_argv(sys.argv)
    raise SystemExit(
        main(
            state_path=_config["state_path"],
            manifest_path=_config["manifest_path"],
            fallback_command=_config["fallback_command"],
            start_command=_config["start_command"],
            query=_config["query"],
            hook_timeouts=_config["hook_timeouts"],
            config_json=_config["config_json"],
        )
    )
