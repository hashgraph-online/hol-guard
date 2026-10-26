"""Compatibility launcher for Claude hook commands written before the native bridge.

The daemon hook review itself lives in the runtime
(``rust/crates/guard-runtime/src/claude_hook_bridge.rs``). Guard installs that
runtime's ``claude-hook-bridge`` command directly whenever the runtime is
present, and SessionStart rewrites older commands, so this module only has to
carry a session that is still running a hook command written before the
runtime shipped: it runs the same native command with the same config.

There is no Python evaluator behind it. Every hook review needs the native
runtime, so an install without one has nothing left to ask and the hook denies.

The render helpers below decide no verdict of their own. They are the recorded
oracle for the Rust port's parity vectors
(``scripts/ci/record_claude_hook_bridge_vectors.py``).
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

from ..codex_hook_launch_runtime import isolated_daemon_start_command
from ..hook_execution_environment import stamp_hook_input_text
from ._modules.claude.claude_daemon_state import state_path_for_query
from .claude_hook_config import CLAUDE_GUARD_DAEMON_HOOK_MARKER
from .claude_hook_config import CLAUDE_GUARD_PERMISSION_PASSTHROUGH_KEY as PERMISSION_PASSTHROUGH_KEY
from .hook_input_reader import read_stdin_text
from .native_hook_bridge import native_hook_bridge_executable

_DEGRADED_DAEMON_MESSAGE = "HOL Guard could not complete native review ({reason}) and denied this action."
_RISKY_PROMPT_SYSTEM_MESSAGE = (
    "HOL Guard intercepted this prompt because it asks Claude to access local secrets. If Claude "
    "asks to continue, HOL Guard will route the decision through a branded approval prompt."
)
_RISKY_PROMPT_ADDITIONAL_CONTEXT = (
    "HOL Guard will intercept Claude's next attempt to access local secrets and open a branded "
    "approval question to protect you."
)
_MAX_HOOK_INPUT_BYTES = 1_000_000
_NATIVE_RUNTIME_UNAVAILABLE = "the native runtime is unavailable"


def main(
    *,
    state_path: str | Path,
    fallback_daemon_url: str,
    fallback_command: tuple[str, ...],
    query: str,
) -> int:
    """Run this hook call in the native bridge, or deny when there is no runtime."""

    bridge_home = Path(state_path).parent
    native = _native_bridge_executable(bridge_home)
    if native is None:
        return _deny_without_a_runtime()
    argv = (
        str(native),
        _native_bridge_command(),
        CLAUDE_GUARD_DAEMON_HOOK_MARKER,
        _native_bridge_config(
            state_path=state_path,
            fallback_daemon_url=fallback_daemon_url,
            fallback_command=fallback_command,
            query=query,
        ),
    )
    sys.stdout.flush()
    # The child inherits this hook call's stdio, so it reads the hook body and
    # writes the response itself. ``exec`` would save the fork, but this entry
    # point is also called in process, where replacing the caller is wrong.
    try:
        status = subprocess.run(argv, check=False).returncode
        # Claude treats most nonzero hook exits as non-blocking errors.
        # Only a successful JSON response or explicit blocking exit is safe.
        return 0 if status == 0 else 2
    except OSError:
        # A removed/unlaunchable runtime has not consumed stdin. Returning a
        # traceback with exit 1 would let Claude run the unreviewed tool.
        return _deny_without_a_runtime()


def _native_bridge_executable(guard_home: Path) -> Path | None:
    from .claude_hook_argv import NATIVE_CLAUDE_HOOK_FEATURE

    # Claude's hook window is 10s, and the child reserves up to 8s of it.
    # Bound cold native capability probing before launching the child.
    deadline = time.monotonic() + 1.5
    runtime = native_hook_bridge_executable(
        NATIVE_CLAUDE_HOOK_FEATURE, guard_home=guard_home, deadline_monotonic=deadline
    )
    # A quick transient probe miss may clear on the second check. Both attempts
    # share one deadline; a slow or missing runtime still fails closed.
    if runtime is None:
        # The native capability probe caches misses for 0.25s. Retrying
        # immediately only reads that negative cache. Leave a little time
        # after the backoff for the second bounded probe.
        retry_at = time.monotonic() + 0.26
        if retry_at + 0.25 < deadline:
            time.sleep(max(0.0, retry_at - time.monotonic()))
            runtime = native_hook_bridge_executable(
                NATIVE_CLAUDE_HOOK_FEATURE, guard_home=guard_home, deadline_monotonic=deadline
            )
    return runtime


def _native_bridge_command() -> str:
    from .claude_hook_argv import NATIVE_CLAUDE_HOOK_COMMAND

    return NATIVE_CLAUDE_HOOK_COMMAND


def _native_bridge_config(
    *,
    state_path: str | Path,
    fallback_daemon_url: str,
    fallback_command: tuple[str, ...],
    query: str,
) -> str:
    """The config the installed native command carries, rebuilt from this call.

    A query naming another Guard home resolves to no state path. The runtime
    refuses that query itself, so the raw path goes over unchanged and only
    the recovery command, which the runtime then never runs, is left pointing
    at the install's own home.
    """

    try:
        recovery_root: str | Path = state_path_for_query(state_path, query)
    except ValueError:
        recovery_root = state_path
    config = {
        "state_path": str(state_path),
        "fallback_daemon_url": fallback_daemon_url,
        "fallback_command": list(fallback_command),
        "query": query,
        "recovery_command": list(_recovery_command(recovery_root, query)),
    }
    return json.dumps(config, ensure_ascii=False, separators=(",", ":"))


def _deny_without_a_runtime() -> int:
    body, oversized = read_stdin_text(_MAX_HOOK_INPUT_BYTES)
    if oversized:
        event = _event_name(body)
        if not (event.startswith("Permission") or event in {"UserPromptSubmit", "PostToolUse", "Stop"}):
            event = "PreToolUse"
        sys.stdout.write(_limit_denied("hook input", event))
        return 0
    data = stamp_hook_input_text(body.strip() or "{}")
    if _event_name(data) == "UserPromptSubmit":
        # A legacy prompt hook must not silently accept unreviewed text when
        # its native authority is unavailable.
        message = _DEGRADED_DAEMON_MESSAGE.format(reason=_NATIVE_RUNTIME_UNAVAILABLE)
        sys.stdout.write(_deny_event("UserPromptSubmit", message))
        return 0
    sys.stdout.write(_degraded(_NATIVE_RUNTIME_UNAVAILABLE, data))
    return 0


def _event_name(data: str) -> str:
    try:
        payload = json.loads(data or "{}")
    except json.JSONDecodeError:
        payload = None
    if isinstance(payload, dict):
        return str(payload.get("hook_event_name") or payload.get("event") or "PreToolUse")
    prefix = data[:4096]
    for key in ("hook_event_name", "event"):
        start = prefix.find(f'"{key}"')
        colon = prefix.find(":", start, start + 64) if start >= 0 else -1
        quote = prefix.find('"', colon + 1, colon + 80) if colon >= 0 else -1
        end = prefix.find('"', quote + 1, quote + 80) if quote >= 0 else -1
        if quote >= 0 and end > quote:
            return prefix[quote + 1 : end] or "PreToolUse"
    return "PreToolUse"


def _prompt_text(data: str) -> str:
    try:
        payload = json.loads(data or "{}")
    except json.JSONDecodeError:
        return ""
    if not isinstance(payload, dict):
        return ""
    prompt = payload.get("prompt", payload.get("user_prompt", ""))
    return str(prompt or "")


def _degraded_prompt(data: str) -> str:
    prompt = _prompt_text(data).lower()
    risky = any(token in prompt for token in (".env", "secret", "api key", "token"))
    if risky:
        return json.dumps(
            {
                "systemMessage": _RISKY_PROMPT_SYSTEM_MESSAGE,
                "hookSpecificOutput": {
                    "hookEventName": "UserPromptSubmit",
                    "additionalContext": _RISKY_PROMPT_ADDITIONAL_CONTEXT,
                },
            },
            separators=(",", ":"),
        )
    return json.dumps({"hookSpecificOutput": {"hookEventName": "UserPromptSubmit"}}, separators=(",", ":"))


def _limit_denied(kind: str, event: str = "PreToolUse") -> str:
    return _deny_event(event, f"HOL Guard blocked this action because {kind} exceeded the safe size limit.")


def _deny_event(event: str, message: str) -> str:
    if event.startswith("Permission"):
        output: dict[str, object] = {
            "hookEventName": event,
            "decision": {"behavior": "deny", "message": message},
        }
        return json.dumps({"systemMessage": message, "hookSpecificOutput": output}, separators=(",", ":"))
    if event in {"UserPromptSubmit", "PostToolUse", "Stop"}:
        body = {"decision": "block", "reason": message, "hookSpecificOutput": {"hookEventName": event}}
        return json.dumps(body, separators=(",", ":"))
    output = {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": message,
    }
    return json.dumps({"systemMessage": message, "hookSpecificOutput": output}, separators=(",", ":"))


def _degraded(reason: str, data: str) -> str:
    event = _event_name(data)
    if event == "UserPromptSubmit":
        return _degraded_prompt(data)
    if event == "PreToolUse" or event.startswith("Permission"):
        # An unavailable or malformed evaluator grants no execution authority.
        # This bridge has no authenticated Watch snapshot to authorize a bypass.
        message = _DEGRADED_DAEMON_MESSAGE.format(reason=reason)
        return _deny_event(event, message)
    return "{}"


def _authenticated_control_plane_failure(reason: str, data: str) -> str:
    message = f"HOL Guard denied the action because daemon authentication failed: {reason}"
    event = _event_name(data)
    if event.startswith("Permission") or event == "PreToolUse":
        return _deny_event(event, message)
    return json.dumps({"continue": True, "stopReason": message}, separators=(",", ":"))


def _should_suppress_output(data: str, response_body: str) -> bool:
    if _event_name(data) != "UserPromptSubmit":
        return False
    trimmed = (response_body or "").strip()
    return trimmed in {"", "{}"}


def _valid_hook_json_or_degraded(output: str, *, reason: str, data: str) -> str:
    trimmed = (output or "").strip()
    if not trimmed:
        return _degraded(reason, data)
    try:
        decoded = json.loads(trimmed)
    except json.JSONDecodeError:
        return _degraded(reason, data)
    if not isinstance(decoded, dict):
        return _degraded(reason, data)
    event = _event_name(data)
    if event == "PreToolUse":
        hook_output = decoded.get("hookSpecificOutput")
        if (
            not isinstance(hook_output, dict)
            or hook_output.get("hookEventName") != event
            or hook_output.get("permissionDecision") not in ("allow", "ask", "deny")
        ):
            return _degraded(reason, data)
    elif event.startswith("Permission"):
        hook_output = decoded.get("hookSpecificOutput")
        decision = hook_output.get("decision") if isinstance(hook_output, dict) else None
        if _is_permission_passthrough(decoded, hook_output, event):
            return trimmed
        if (
            not isinstance(hook_output, dict)
            or hook_output.get("hookEventName") != event
            or not isinstance(decision, dict)
            or decision.get("behavior") not in ("allow", "deny")
        ):
            return _degraded(reason, data)
    return trimmed


def _is_permission_passthrough(decoded: dict[str, object], hook_output: object, event: str) -> bool:
    """Accept the daemon's explicit deferral to Claude's own permission dialog.

    The marker comes only from the authenticated daemon. It carries no
    decision, so Claude keeps its normal prompt; it never grants approval.
    """

    return (
        decoded.get(PERMISSION_PASSTHROUGH_KEY) is True
        and isinstance(hook_output, dict)
        and hook_output.get("hookEventName") == event
        and "decision" not in hook_output
    )


def _recovery_command(state_path: str | Path, query: str) -> tuple[str, ...]:
    query_values = parse_qs(query)
    home_values = query_values.get("home")
    home_dir = Path(home_values[0]) if home_values and home_values[0] else Path.home()
    from ..frozen_runtime_commands import frozen_daemon_recovery_command, is_frozen_guard_runtime

    if is_frozen_guard_runtime():
        # A frozen desktop core cannot run the Python ``-I -c`` bootstrap below.
        return frozen_daemon_recovery_command(Path(state_path).parent, home_dir)
    package_root = Path(__file__).resolve().parents[3]
    return isolated_daemon_start_command(
        sys.executable,
        package_root,
        Path(state_path).parent,
        home_dir,
    )


def _bridge_config_from_argv(argv: list[str]) -> dict[str, Any]:
    if len(argv) != 2:
        raise SystemExit("claude_daemon_hook_bridge expects one JSON config argument")
    payload = json.loads(argv[1])
    if not isinstance(payload, dict):
        raise SystemExit("claude_daemon_hook_bridge config must be a JSON object")
    fallback_command = payload.get("fallback_command")
    if not isinstance(fallback_command, list) or not fallback_command:
        raise SystemExit("claude_daemon_hook_bridge config missing fallback_command")
    config: dict[str, Any] = {}
    for required_key in ("state_path", "fallback_daemon_url", "query"):
        if required_key not in payload:
            raise SystemExit(f"claude_daemon_hook_bridge config missing {required_key!r}")
        config[required_key] = str(payload[required_key])
    config["fallback_command"] = tuple(str(item) for item in fallback_command)
    return config


if __name__ == "__main__":
    config = _bridge_config_from_argv(sys.argv)
    raise SystemExit(
        main(
            state_path=config["state_path"],
            fallback_daemon_url=config["fallback_daemon_url"],
            fallback_command=config["fallback_command"],
            query=config["query"],
        )
    )
