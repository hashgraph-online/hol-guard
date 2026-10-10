"""Fast, authenticated bridge from Codex hooks to the local Guard daemon."""

from __future__ import annotations

import json
import os
import sys
import time
from collections.abc import Mapping, Sequence
from contextlib import suppress
from pathlib import Path
from urllib.parse import parse_qs

if __package__:
    from ..codex_binding_capture import record_bridge_ingress
    from ..codex_hook_bridge_runtime import BridgeConfig
    from ..codex_hook_bridge_runtime import bounded_hook_input as _hook_input
    from ..codex_hook_bridge_runtime import bridge_config_from_argv as _parse_bridge_config
    from ..codex_hook_launch_runtime import (
        desktop_hook_proxy_context,
        isolated_hook_environment,
        run_isolated_hook_process,
    )
    from ..config import MAX_APPROVAL_WAIT_TIMEOUT_SECONDS
    from ..daemon.hook_availability_policy import hook_event_is_permission_request
    from ..daemon.hook_request_parsing import runtime_hook_event_name
    from ..hook_execution_environment import stamp_hook_input_text
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
    from codex_plugin_scanner.guard.codex_binding_capture import record_bridge_ingress
    from codex_plugin_scanner.guard.codex_hook_bridge_runtime import (
        BridgeConfig,
    )
    from codex_plugin_scanner.guard.codex_hook_bridge_runtime import (
        bounded_hook_input as _hook_input,
    )
    from codex_plugin_scanner.guard.codex_hook_bridge_runtime import (
        bridge_config_from_argv as _parse_bridge_config,
    )
    from codex_plugin_scanner.guard.codex_hook_launch_runtime import (
        desktop_hook_proxy_context,
        isolated_hook_environment,
        run_isolated_hook_process,
    )
    from codex_plugin_scanner.guard.config import MAX_APPROVAL_WAIT_TIMEOUT_SECONDS
    from codex_plugin_scanner.guard.daemon.hook_availability_policy import (
        hook_event_is_permission_request,
    )
    from codex_plugin_scanner.guard.daemon.hook_request_parsing import runtime_hook_event_name
    from codex_plugin_scanner.guard.hook_execution_environment import stamp_hook_input_text
    from codex_plugin_scanner.guard.live_process_identity import (
        CODEX_BROWSER_WAIT_PROCESS_KEY,
        CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY,
        current_process_identity,
    )

_HOOK_TIMEOUT_GRACE_SECONDS = 2
_DISCOVERY_PROTOCOL_VERSION = 1
_MAX_HOOK_INPUT_BYTES = 1_000_000
_BRIDGE_FAILURE_SCHEMA = "hol-guard.codex-bridge-failure.v1"
_FAIL_CLOSED_REASON = (
    "HOL Guard could not authenticate the local daemon. Run `hol-guard daemon repair` from a terminal, then retry."
)
_LAUNCH_INTEGRITY_REASON = (
    "HOL Guard could not authenticate its managed Codex hook launcher. "
    "Run `hol-guard install codex` from a terminal, then retry."
)
_OVERLOAD_REASON = (
    "HOL Guard is temporarily saturated and kept this action blocked. No approval was requested; retry the action."
)
_TRANSITION_PROBE_OUTPUT_LIMIT = 64 * 1024


def _json_object(text: str) -> dict[str, object] | None:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _write_transition_observation(data: str, response: Mapping[str, object]) -> None:
    envelope = response.get("guard_transition_observation")
    if not isinstance(envelope, dict):
        return
    from codex_plugin_scanner.guard.runtime_transition_hook_probe import (
        transition_hook_observation,
    )

    payload = _json_object(data)
    if payload is None:
        return
    validated = transition_hook_observation(payload, envelope.get("native_receipt"))
    if validated is None or envelope != validated:
        return
    # Diagnostics must never interfere with the app's enforcement response.
    with suppress(OSError, ValueError):
        sys.stderr.write(json.dumps(validated, sort_keys=True, separators=(",", ":")) + "\n")


def _desktop_transition_probe_command(
    *,
    data: str,
    state_path: str | Path,
    query: str,
    hook_timeouts: Mapping[str, int],
    environment: Mapping[str, str] | None = None,
) -> tuple[str, ...] | None:
    """Build the strict signed-proxy path for an authenticated Desktop probe."""

    source = os.environ if environment is None else environment
    if not bool(getattr(sys, "frozen", False)) or sys.platform != "darwin":
        return None
    if source.get("HOL_GUARD_DESKTOP") != "1":
        return None

    payload = _json_object(data)
    if payload is None or payload.get("hook_event_name") != "PreToolUse":
        return None
    from codex_plugin_scanner.guard.runtime_transition_hook_probe import (
        PROBE_FIELD,
        transition_hook_probe,
    )

    if PROBE_FIELD not in payload or transition_hook_probe(payload) is None:
        return None

    guard_home = Path(state_path)
    if guard_home.name == "daemon-state.json":
        guard_home = guard_home.parent
    if not guard_home.is_absolute():
        raise RuntimeError("Desktop transition probe has no absolute Guard home")

    proxy = desktop_hook_proxy_context(source).get("HOL_GUARD_DESKTOP_HOOK_PROXY")
    timeout_seconds = hook_timeouts.get("PreToolUse")
    if proxy is None or type(timeout_seconds) is not int or timeout_seconds <= 0:
        raise RuntimeError("Desktop transition probe has no signed proxy or valid deadline")

    query_values = parse_qs(query, keep_blank_values=True)
    home_values = query_values.get("home", [])
    home = Path(home_values[0]) if len(home_values) == 1 else None
    workspace_value = payload.get("cwd")
    workspace = Path(workspace_value) if isinstance(workspace_value, str) else None
    if (
        home is None
        or not home.is_absolute()
        or workspace is None
        or not workspace.is_absolute()
        or "\x00" in str(home)
        or "\x00" in str(workspace)
    ):
        raise RuntimeError("Desktop transition probe has an invalid home or workspace")

    from codex_plugin_scanner.guard.adapters.bounded_cli_hook_bridge import bounded_cli_hook_command

    command = bounded_cli_hook_command(
        # The bundle executable is both the signed proxy and the fallback
        # target. Requiring the proxy makes fallback exit before Core runs.
        python_executable=proxy,
        package_root=Path(__file__).resolve().parents[3],
        guard_home=guard_home,
        cli_args=[
            "guard",
            "hook",
            "--guard-home",
            str(guard_home.resolve(strict=False)),
            "--harness",
            "codex",
            "--home",
            str(home.resolve(strict=False)),
            "--workspace",
            str(workspace.resolve(strict=False)),
        ],
        harness="codex",
        timeout_seconds=float(timeout_seconds),
        require_desktop_proxy=True,
    )
    if len(command) != 10 or command[4] != proxy or command[8] != proxy or command[9] != "1":
        raise RuntimeError("Desktop transition probe did not resolve to its strict signed proxy")
    return command


def _event_name(data: str) -> str:
    payload = _json_object(data)
    if payload is None:
        return "PreToolUse"
    return runtime_hook_event_name(payload)


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
    if hook_event_is_permission_request(event_name):
        return {
            "hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
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
    return {
        "continue": True,
        "systemMessage": reason,
    }


def _unavailable_response(
    event_name: str,
    reason: str,
    data: str | None = None,
) -> dict[str, object]:
    # A payload's command name or path is not an authenticated tool decision.
    del data
    if event_name == "PreToolUse":
        return _fail_closed(event_name, reason)
    if hook_event_is_permission_request(event_name):
        return _fail_closed(event_name, reason)
    return {
        "continue": True,
        "systemMessage": reason,
    }


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
    if event_name == "PreToolUse" and "hookSpecificOutput" in filtered:
        cleaned: dict[str, object] = {"hookEventName": event_name}
        if isinstance(hook_output, Mapping):
            decision = hook_output.get("permissionDecision")
            normalized = decision.strip().lower() if isinstance(decision, str) else ""
            if response.get("policy_action") == "deny":
                normalized = "deny"
            reason = hook_output.get("permissionDecisionReason")
            if normalized in {"deny", "ask"}:
                cleaned["permissionDecision"] = normalized
                if isinstance(reason, str) and reason:
                    cleaned["permissionDecisionReason"] = reason
            elif normalized == "allow":
                if (
                    response.get("policy_action") == "warn"
                    and isinstance(reason, str)
                    and reason.strip()
                    and not filtered.get("systemMessage")
                ):
                    filtered["systemMessage"] = reason
        filtered["hookSpecificOutput"] = cleaned
    return filtered


def _bound_hook_input(
    hook_timeouts: Mapping[str, int],
    *,
    capture_guard_home: Path | None = None,
) -> tuple[str, str, float, float] | None:
    raw_data = _hook_input(_MAX_HOOK_INPUT_BYTES)
    if raw_data is None:
        return None
    input_ready_at = time.monotonic()
    event_name = _event_name(raw_data)
    timeout_seconds = _request_timeout(event_name, hook_timeouts)
    data = (
        _with_browser_wait_process(raw_data, wait_timeout_seconds=max(1.0, timeout_seconds - 1.0))
        if event_name == "PreToolUse"
        else raw_data
    )
    # Native Git-helper checks need the environment Codex will run the command
    # in; without it every Git read is treated as unverifiable.
    data = stamp_hook_input_text(data)
    if capture_guard_home is not None:
        with suppress(Exception):
            record_bridge_ingress(
                guard_home=capture_guard_home,
                raw_payload=raw_data,
                forwarded_payload=data,
                event_name=event_name,
            )
    return event_name, data, timeout_seconds, input_ready_at


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

    state = Path(state_path)
    capture_guard_home = state.parent if state.is_absolute() and state.name == "daemon-state.json" else None
    hook_input = _bound_hook_input(hook_timeouts, capture_guard_home=capture_guard_home)
    if hook_input is None:
        sys.stdout.write(json.dumps(_fail_closed("PreToolUse"), separators=(",", ":")))
    else:
        event_name, data, timeout_seconds, input_ready_at = hook_input
        deadline = input_ready_at + timeout_seconds
        try:
            probe_command = _desktop_transition_probe_command(
                data=data,
                state_path=state_path,
                query=query,
                hook_timeouts=hook_timeouts,
            )
        except (OSError, RuntimeError, ValueError):
            sys.stdout.write(json.dumps(_fail_closed(event_name), separators=(",", ":")))
            return 1
        if probe_command is not None:
            try:
                probe_result = run_isolated_hook_process(
                    probe_command,
                    input_text=data,
                    cwd=Path.home(),
                    environment=isolated_hook_environment(),
                    output_limit=_TRANSITION_PROBE_OUTPUT_LIMIT,
                    deadline_monotonic=deadline,
                )
            except OSError:
                sys.stdout.write(json.dumps(_fail_closed(event_name), separators=(",", ":")))
                return 1
            if (
                probe_result.returncode != 0
                or probe_result.timed_out
                or probe_result.containment_failed
                or probe_result.output_limit_exceeded
            ):
                sys.stdout.write(json.dumps(_fail_closed(event_name), separators=(",", ":")))
                return 1
            sys.stdout.write(probe_result.stdout)
            sys.stderr.write(probe_result.stderr)
            return 0
        failure_causes = []
        response, daemon_overloaded, launch_integrity_failed = bridge_review_response(
            state_path=state_path,
            fallback_command=fallback_command,
            start_command=start_command,
            query=query,
            data=data,
            deadline=deadline,
            manifest_path=manifest_path,
            config_json=config_json,
            failure_causes=failure_causes,
            event_name=event_name,
        )
        if response is None:
            if launch_integrity_failed:
                # Diagnostic delivery must not interrupt the denial response.
                with suppress(OSError, ValueError, TypeError):
                    sys.stderr.write(
                        json.dumps(
                            {
                                "schema": _BRIDGE_FAILURE_SCHEMA,
                                "causes": failure_causes,
                            },
                            separators=(",", ":"),
                        )
                        + "\n"
                    )
                if any(
                    isinstance(cause, dict) and cause.get("reason_code") == "codex_hook_validation_deadline_expired"
                    for cause in failure_causes
                ):
                    response = _unavailable_response(
                        event_name,
                        "HOL Guard could not finish hook identity verification before the deadline. "
                        "Retry this action after local review recovers.",
                        data,
                    )
                else:
                    response = _launcher_integrity_response(event_name, data)
            else:
                failure_reason = _OVERLOAD_REASON if daemon_overloaded else _FAIL_CLOSED_REASON
                response = _unavailable_response(event_name, failure_reason, data)
        _write_transition_observation(data, response)
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


def _launcher_integrity_response(event_name: str, data: str) -> dict[str, object]:
    """Deny tool actions through a bad launcher and identify a terminal repair."""

    return _unavailable_response(event_name, _LAUNCH_INTEGRITY_REASON, data)


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
