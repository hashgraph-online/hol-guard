"""Bounded subprocess bridge for harnesses without a daemon-native hook."""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast
from urllib.parse import urlparse

from ..codex_hook_launch_runtime import (
    isolated_guard_cli_command,
    isolated_hook_environment,
    run_isolated_hook_process,
)
from ..daemon.hook_availability_policy import EMERGENCY_SAFE_REASON, hook_action_is_emergency_safe
from ..private_file_io import read_private_regular_text
from .desktop_hook_proxy import (
    _DESKTOP_PROXY_LAUNCH_SCRIPT as _DESKTOP_PROXY_LAUNCH_SCRIPT,
)
from .desktop_hook_proxy import (
    _trusted_desktop_hook_proxy_command,
)

_MAX_HOOK_INPUT_BYTES = 1_000_000
_MAX_HOOK_RESPONSE_BYTES = 1_000_000
_FAILURE_REASON = "HOL Guard could not complete this review before the hook deadline. Retry the action."
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_DAEMON_TIMEOUT_BUDGET_SECONDS = 5.0
_FROZEN_BRIDGE_COMMAND = "__guard-bounded-hook"
_FROZEN_OPTIONAL_PATH_FLAGS = frozenset({"--home", "--workspace"})


def _assert_loopback_http_url(url: str) -> None:
    """Assert the URL is HTTP on a loopback host.

    Mirrors _assert_loopback_http_url from claude_daemon_hook_bridge.
    """
    parsed = urlparse(url)
    if parsed.scheme != "http":
        raise ValueError(f"daemon URL must use http, not {parsed.scheme!r}")
    if parsed.hostname not in _LOOPBACK_HOSTS:
        raise ValueError(f"daemon URL must target loopback, not {parsed.hostname!r}")


def _build_loopback_opener() -> urllib.request.OpenerDirector:
    """Build an opener that blocks proxies and off-loopback redirects.

    Mirrors _build_loopback_opener from claude_daemon_hook_bridge.
    """
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _LoopbackOnlyRedirectHandler(),
    )


class _LoopbackOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        _assert_loopback_http_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def bounded_cli_hook_command(
    *,
    python_executable: str,
    package_root: Path,
    guard_home: Path,
    cli_args: Sequence[str],
    harness: str,
    timeout_seconds: float,
) -> tuple[str, ...]:
    """Build a shell-free hook command backed by a process-tree deadline."""

    frozen_launcher = bool(getattr(sys, "frozen", False))
    config = {
        "python_executable": python_executable,
        "package_root": str(package_root.resolve()),
        "guard_home": str(guard_home.resolve(strict=False)),
        "cli_args": list(cli_args),
        "harness": harness,
        "timeout_seconds": timeout_seconds,
        "frozen_launcher": frozen_launcher,
    }
    bootstrap = (
        "import sys;"
        f"sys.path.insert(0,{str(package_root.resolve())!r});"
        "from codex_plugin_scanner.guard.adapters.bounded_cli_hook_bridge import main_from_argv;"
        "raise SystemExit(main_from_argv(sys.argv[1:]))"
    )
    if frozen_launcher:
        config_json = json.dumps(config, ensure_ascii=True, separators=(",", ":"))
        desktop_proxy = _trusted_desktop_hook_proxy_command(python_executable, config_json)
        if desktop_proxy is not None:
            return desktop_proxy
        return (
            python_executable,
            _FROZEN_BRIDGE_COMMAND,
            config_json,
        )
    return (
        python_executable,
        "-I",
        "-c",
        bootstrap,
        json.dumps(config, ensure_ascii=True, separators=(",", ":")),
    )


_EVENT_ALIASES = {
    "permissionrequest": "PermissionRequest",
    "pretooluse": "PreToolUse",
    "pretoolcall": "PreToolUse",
    "userpromptsubmit": "UserPromptSubmit",
    "posttooluse": "PostToolUse",
    "sessionstart": "SessionStart",
    "notification": "Notification",
    "stop": "Stop",
}
_EVENT_NAME_KEYS = ("hook_event_name", "hookEventName", "event", "eventName", "hook_name", "hookName")


def _read_bounded_stdin() -> tuple[str | None, str]:
    raw = sys.stdin.buffer.read(_MAX_HOOK_INPUT_BYTES + 1)
    prefix = raw[:_MAX_HOOK_INPUT_BYTES].decode("utf-8", errors="replace")
    if len(raw) > _MAX_HOOK_INPUT_BYTES:
        return None, prefix
    return prefix, prefix


def _bounded_stdin() -> str | None:
    text, _prefix = _read_bounded_stdin()
    return text


def _validated_frozen_cli_args(
    cli_args: Sequence[str],
    *,
    guard_home: Path,
    harness: str,
) -> tuple[str, ...] | None:
    if len(cli_args) < 6 or tuple(cli_args[:3]) != ("guard", "hook", "--guard-home"):
        return None
    supplied_guard_home_value = Path(cli_args[3])
    if not supplied_guard_home_value.is_absolute() or not guard_home.is_absolute():
        return None
    try:
        supplied_guard_home = supplied_guard_home_value.resolve(strict=False)
        expected_guard_home = guard_home.resolve(strict=False)
    except (OSError, RuntimeError):
        return None
    if supplied_guard_home != expected_guard_home:
        return None
    if tuple(cli_args[4:6]) != ("--harness", harness):
        return None
    tail = cli_args[6:]
    if tail and tail[-1] == "--json":
        tail = tail[:-1]
    if len(tail) % 2 != 0:
        return None
    seen_flags: set[str] = set()
    for index in range(0, len(tail), 2):
        flag, value = tail[index : index + 2]
        if flag not in _FROZEN_OPTIONAL_PATH_FLAGS or flag in seen_flags:
            return None
        if not Path(value).is_absolute():
            return None
        seen_flags.add(flag)
    return (
        "hook",
        "--guard-home",
        str(expected_guard_home),
        "--harness",
        harness,
        *tail,
        "--json",
    )


def _json_object(text: str) -> dict[str, object] | None:
    try:
        raw = cast(object, json.loads(text))
    except json.JSONDecodeError:
        return None
    if not isinstance(raw, dict):
        return None
    payload: dict[str, object] = {}
    for key, value in cast(dict[object, object], raw).items():
        if isinstance(key, str):
            payload[key] = value
    return payload


def _canonical_event_token(value: str) -> str | None:
    stripped = value.strip()
    if not stripped:
        return None
    normalized = stripped.replace("_", "").replace("-", "").lower()
    return _EVENT_ALIASES.get(normalized, stripped)


def _event_name(input_text: str) -> str:
    payload = _json_object(input_text or "{}")
    if payload is not None:
        for key in _EVENT_NAME_KEYS:
            value = payload.get(key)
            if isinstance(value, str):
                named = _canonical_event_token(value)
                if named is not None:
                    return named
    for key in _EVENT_NAME_KEYS:
        token = f'"{key}"'
        start = input_text.find(token)
        colon = input_text.find(":", start + len(token)) if start >= 0 else -1
        quote = input_text.find('"', colon + 1) if colon >= 0 else -1
        end = input_text.find('"', quote + 1) if quote >= 0 else -1
        if 0 <= quote < end:
            named = _canonical_event_token(input_text[quote + 1 : end])
            if named is not None:
                return named
    return "PreToolUse"


def _has_json_object_line(output: str) -> bool:
    stripped = output.strip()
    if stripped and _json_object(stripped) is not None:
        return True
    for line in reversed(output.splitlines()):
        if not line.strip():
            continue
        return _json_object(line.strip()) is not None
    return False


def _cli_args_with_json(cli_args: Sequence[str]) -> list[str]:
    if cli_args and cli_args[-1] == "--json":
        return list(cli_args)
    return [*cli_args, "--json"]


def _guard_home_is_recording_only(guard_home: Path) -> bool:
    try:
        from ..config import maybe_auto_revert_watch
        from ..protection_posture import protection_is_off

        config = maybe_auto_revert_watch(guard_home)
    except (OSError, RuntimeError, ValueError):
        return False
    return protection_is_off(posture=config.protection_posture, mode=config.mode)


def _watch_continue_payload(harness: str, event_name: str) -> dict[str, object]:
    if harness == "copilot":
        return {"permissionDecision": "allow"}
    if harness in {"grok", "hermes", "openclaw"}:
        return {"decision": "allow"}
    return {
        "hookSpecificOutput": {
            "hookEventName": event_name,
            "permissionDecision": "allow",
        }
    }


def _failure_payload(
    *,
    harness: str,
    event_name: str,
    reason: str,
    input_text: str = "",
    guard_home: Path | None = None,
) -> tuple[dict[str, object], int]:
    if guard_home is not None and _guard_home_is_recording_only(guard_home):
        return _watch_continue_payload(harness, event_name), 0
    payload = _json_object(input_text or "{}")
    if event_name == "PreToolUse" and isinstance(payload, dict) and hook_action_is_emergency_safe(payload):
        if harness == "copilot":
            return {
                "permissionDecision": "allow",
                "permissionDecisionReason": EMERGENCY_SAFE_REASON,
            }, 0
        if harness in {"grok", "hermes", "openclaw"}:
            return {"decision": "allow", "reason": EMERGENCY_SAFE_REASON}, 0
        return {
            "hookSpecificOutput": {
                "hookEventName": event_name,
                "permissionDecision": "allow",
                "permissionDecisionReason": EMERGENCY_SAFE_REASON,
            }
        }, 0
    if harness == "copilot":
        if event_name == "PermissionRequest":
            return {
                "behavior": "deny",
                "message": reason,
                "interrupt": True,
            }, 0
        return {
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }, 0
    if harness in {"grok", "hermes", "openclaw"}:
        decision = "block" if harness == "hermes" else "deny"
        return {"decision": decision, "reason": reason}, (2 if harness == "hermes" else 0)
    if event_name == "UserPromptSubmit":
        return {
            "decision": "block",
            "reason": reason,
            "hookSpecificOutput": {
                "hookEventName": event_name,
                "additionalContext": reason,
            },
        }, 2
    if event_name == "PreToolUse":
        return {
            "hookSpecificOutput": {
                "hookEventName": event_name,
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }, 2
    return {
        "continue": False,
        "stopReason": reason,
        "systemMessage": reason,
    }, 0


def _emit_failure(
    *,
    harness: str,
    input_text: str,
    reason: str = _FAILURE_REASON,
    guard_home: Path | None = None,
) -> int:
    payload, returncode = _failure_payload(
        harness=harness,
        event_name=_event_name(input_text),
        reason=reason,
        input_text=input_text,
        guard_home=guard_home,
    )
    _ = sys.stdout.write(json.dumps(payload, ensure_ascii=True, separators=(",", ":")) + "\n")
    return returncode


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
    return f"http://{host}:{port}/v1/hooks/{harness}"


def _native_hook_permission_decision(policy_action: str) -> str | None:
    """Map policy action to harness permission decision.

    Mirrors _native_hook_permission_decision from commands_support_hook_payload.
    """
    if policy_action in {"allow", "warn"}:
        return "allow"
    if policy_action in {"review", "require-reapproval", "sandbox-required"}:
        return "ask"
    if policy_action == "block":
        return "deny"
    return None


def _should_exit_block(harness: str, event_name: str, policy_action: str) -> bool:
    """Mirror _should_emit_native_hook_exit_block."""
    canonical = harness.strip().lower().replace("_", "-")
    if canonical in {"kimi", "grok", "hermes", "pi", "omp", "zcode"} and event_name in {
        "PreToolUse",
        "UserPromptSubmit",
    }:
        return policy_action in {"review", "require-reapproval", "sandbox-required", "block"}
    return False


def _daemon_response_to_native(
    daemon_response: dict[str, object],
    *,
    harness: str,
    event_name: str,
) -> tuple[str, str, int]:
    """Transform daemon policy response into harness-native hook JSON + stderr + exit code.

    The daemon returns raw policy data (policy_action, approval_reuse, etc.).
    The bridge transforms this into the harness-native format that the CLI
    hook handler would emit.

    Returns (stdout_json, stderr_text, exit_code).
    """
    canonical = harness.strip().lower().replace("_", "-")

    # Defensive: if the daemon already returned harness-native JSON, pass it through.
    # This handles the case where the daemon's hook_process_runner is running and
    # returns harness-native JSON via capture_hook_command.
    if "hookSpecificOutput" in daemon_response or "decision" in daemon_response:
        stdout = json.dumps(daemon_response, ensure_ascii=True, separators=(",", ":"))
        hook_specific = daemon_response.get("hookSpecificOutput")
        permission_decision = None
        if isinstance(hook_specific, dict):
            pd = hook_specific.get("permissionDecision")
            if isinstance(pd, str):
                permission_decision = pd
        if permission_decision is None:
            decision = daemon_response.get("decision")
            if isinstance(decision, str) and decision in {"block", "deny"}:
                permission_decision = "deny"
        # Map permission decision to policy action for exit code calculation
        policy_action_for_exit = {
            "allow": "allow",
            "deny": "block",
            "ask": "review",
        }.get(permission_decision or "allow", "allow")
        exit_code = 2 if _should_exit_block(harness, event_name, policy_action_for_exit) else 0
        stderr = ""
        if exit_code == 2 and canonical == "kimi":
            # Extract reason from harness-native response
            reason = daemon_response.get("reason")
            if (not isinstance(reason, str) or not reason) and isinstance(hook_specific, dict):
                reason = hook_specific.get("permissionDecisionReason")
            if isinstance(reason, str) and reason:
                stderr = reason
        return stdout, stderr, exit_code

    policy_action = str(daemon_response.get("policy_action", "block"))
    reason = str(daemon_response.get("reason") or daemon_response.get("permission_decision_reason") or "")

    # Build harness-native response
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
        # PreToolUse, PostToolUse, etc.
        permission_decision = _native_hook_permission_decision(policy_action)
        if canonical == "codex" and event_name == "PreToolUse" and permission_decision is None:
            # Codex PreToolUse with no permission decision: emit nothing
            return "", "", 0
        hook_specific_output: dict[str, object] = {"hookEventName": event_name}
        if permission_decision is not None:
            hook_specific_output["permissionDecision"] = permission_decision
            if permission_decision != "allow" or "unreachable" in reason.lower():
                hook_specific_output["permissionDecisionReason"] = reason or f"HOL Guard {policy_action} this action"
        payload["hookSpecificOutput"] = hook_specific_output

    stdout = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
    exit_code = 2 if _should_exit_block(harness, event_name, policy_action) else 0
    stderr = reason if exit_code == 2 and canonical == "kimi" else ""
    return stdout, stderr, exit_code


def _try_daemon_hook(
    *,
    guard_home: Path,
    harness: str,
    input_text: str,
    timeout_seconds: float,
) -> tuple[str, str, int] | None:
    """POST the hook payload to the running daemon; return native stdout or None."""
    if harness.strip().lower() == "grok" and _event_name(input_text) == "PreToolUse":
        return None

    endpoint = _daemon_hook_endpoint(guard_home, harness)
    if endpoint is None:
        return None
    try:
        _assert_loopback_http_url(endpoint)
    except ValueError:
        return None
    token = _read_daemon_auth_token(guard_home)
    if token is None:
        return None
    # Reserve at least 50% of the budget for the subprocess fallback.
    # If the daemon stalls, we still have room to spawn the isolated CLI.
    daemon_budget = min(float(timeout_seconds) * 0.5, _DAEMON_TIMEOUT_BUDGET_SECONDS)
    timeout = daemon_budget
    request = urllib.request.Request(
        endpoint,
        data=input_text.encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-Guard-Token": token,
        },
        method="POST",
    )
    try:
        opener = _build_loopback_opener()
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
        from .hermes_runtime_hooks import hermes_bridge_response as _hermes_native

        return _hermes_native(parsed, event_name=event_name)
    return _daemon_response_to_native(parsed, harness=harness, event_name=event_name)


def run_bounded_cli_hook(config: Mapping[str, object], *, input_text: str) -> int:
    """Run one isolated CLI hook and preserve its native stdout contract."""

    python_executable = config.get("python_executable")
    package_root_value = config.get("package_root")
    guard_home_value = config.get("guard_home")
    cli_args_value = config.get("cli_args")
    harness = config.get("harness")
    timeout_seconds = config.get("timeout_seconds")
    frozen_launcher = config.get("frozen_launcher", False)
    if (
        not isinstance(python_executable, str)
        or not isinstance(package_root_value, str)
        or not isinstance(guard_home_value, str)
        or not isinstance(cli_args_value, list)
        or not isinstance(harness, str)
        or not isinstance(timeout_seconds, (int, float))
        or not isinstance(frozen_launcher, bool)
        or timeout_seconds <= 0
    ):
        return _emit_failure(harness=str(harness or "unknown"), input_text=input_text)
    raw_cli_args = cast(list[object], cli_args_value)
    cli_args = [item for item in raw_cli_args if isinstance(item, str)]
    if len(cli_args) != len(raw_cli_args):
        return _emit_failure(harness=harness, input_text=input_text)
    package_root = Path(package_root_value)
    guard_home = Path(guard_home_value)
    runtime_frozen = bool(getattr(sys, "frozen", False))
    if runtime_frozen:
        direct_cli_args = _validated_frozen_cli_args(
            cli_args,
            guard_home=guard_home,
            harness=harness,
        )
        if direct_cli_args is None:
            return _emit_failure(harness=harness, input_text=input_text, guard_home=guard_home)
        command = (sys.executable, *direct_cli_args)
    elif frozen_launcher:
        return _emit_failure(harness=harness, input_text=input_text, guard_home=guard_home)
    else:
        command = isolated_guard_cli_command(
            python_executable,
            package_root,
            _cli_args_with_json(cli_args),
        )
    daemon_result = _try_daemon_hook(
        guard_home=guard_home,
        harness=harness,
        input_text=input_text,
        timeout_seconds=float(timeout_seconds),
    )
    if daemon_result is not None:
        daemon_stdout, daemon_stderr, daemon_exit = daemon_result
        if daemon_stdout:
            _ = sys.stdout.write(daemon_stdout)
        if daemon_stderr:
            print(daemon_stderr, file=sys.stderr)
        return daemon_exit
    result = run_isolated_hook_process(
        command,
        input_text=input_text,
        cwd=guard_home,
        environment=isolated_hook_environment(),
        timeout_seconds=float(timeout_seconds),
    )
    if result.timed_out:
        return _emit_failure(harness=harness, input_text=input_text, guard_home=guard_home)
    if result.output_limit_exceeded:
        return _emit_failure(
            harness=harness,
            input_text=input_text,
            reason="HOL Guard blocked this action because hook output exceeded the safe size limit.",
            guard_home=guard_home,
        )
    if result.returncode is None:
        return _emit_failure(harness=harness, input_text=input_text, guard_home=guard_home)
    compact_payload = _json_object(result.stdout.strip())
    if compact_payload is None and not _has_json_object_line(result.stdout):
        return _emit_failure(harness=harness, input_text=input_text, guard_home=guard_home)
    if compact_payload is not None:
        _ = sys.stdout.write(json.dumps(compact_payload, ensure_ascii=True, separators=(",", ":")) + "\n")
    elif result.stdout:
        _ = sys.stdout.write(result.stdout)
    return result.returncode


def main_from_argv(argv: Sequence[str]) -> int:
    """Parse the authenticated install-time hook config and run it."""

    config = _json_object(argv[0]) if len(argv) == 1 else None
    configured_harness = config.get("harness") if config is not None else None
    harness = configured_harness if isinstance(configured_harness, str) else "unknown"
    input_text, stdin_prefix = _read_bounded_stdin()
    if input_text is None:
        guard_home_value = config.get("guard_home") if config is not None else None
        guard_home = Path(guard_home_value) if isinstance(guard_home_value, str) else None
        return _emit_failure(
            harness=harness,
            input_text=stdin_prefix or "{}",
            reason="HOL Guard blocked this action because hook input exceeded the safe size limit.",
            guard_home=guard_home,
        )
    if config is None:
        return _emit_failure(harness=harness, input_text=input_text)
    return run_bounded_cli_hook(config, input_text=input_text)


__all__ = [
    "_FROZEN_BRIDGE_COMMAND",
    "bounded_cli_hook_command",
    "main_from_argv",
    "run_bounded_cli_hook",
]
