"""Bounded subprocess bridge for harnesses without a daemon-native hook."""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

from ..codex_hook_launch_runtime import (
    isolated_guard_cli_command,
    isolated_hook_environment,
    run_isolated_hook_process,
)

_MAX_HOOK_INPUT_BYTES = 1_000_000
_FAILURE_REASON = "HOL Guard could not complete this review before the hook deadline. Retry the action."


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

    config = {
        "python_executable": python_executable,
        "package_root": str(package_root.resolve()),
        "guard_home": str(guard_home.resolve(strict=False)),
        "cli_args": list(cli_args),
        "harness": harness,
        "timeout_seconds": timeout_seconds,
    }
    bootstrap = (
        "import sys;"
        f"sys.path.insert(0,{str(package_root.resolve())!r});"
        "from codex_plugin_scanner.guard.adapters.bounded_cli_hook_bridge import main_from_argv;"
        "raise SystemExit(main_from_argv(sys.argv[1:]))"
    )
    return (
        python_executable,
        "-I",
        "-c",
        bootstrap,
        json.dumps(config, ensure_ascii=True, separators=(",", ":")),
    )


def _bounded_stdin() -> str | None:
    raw = sys.stdin.buffer.read(_MAX_HOOK_INPUT_BYTES + 1)
    if len(raw) > _MAX_HOOK_INPUT_BYTES:
        return None
    return raw.decode("utf-8", errors="replace")


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


def _event_name(input_text: str) -> str:
    payload = _json_object(input_text or "{}")
    if payload is None:
        return "PreToolUse"
    for key in ("hook_event_name", "hookEventName", "event", "eventName", "hook_name", "hookName"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            normalized = value.replace("_", "").replace("-", "").lower()
            return {
                "permissionrequest": "PermissionRequest",
                "pretooluse": "PreToolUse",
                "userpromptsubmit": "UserPromptSubmit",
                "posttooluse": "PostToolUse",
                "sessionstart": "SessionStart",
                "notification": "Notification",
                "stop": "Stop",
            }.get(normalized, value.strip())
    return "PreToolUse"


def _has_json_object_line(output: str) -> bool:
    for line in reversed(output.splitlines()):
        if not line.strip():
            continue
        return _json_object(line.strip()) is not None
    return False


def _failure_payload(*, harness: str, event_name: str, reason: str) -> tuple[dict[str, object], int]:
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
        return {"decision": "deny", "reason": reason}, 0
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


def _emit_failure(*, harness: str, input_text: str, reason: str = _FAILURE_REASON) -> int:
    payload, returncode = _failure_payload(
        harness=harness,
        event_name=_event_name(input_text),
        reason=reason,
    )
    _ = sys.stdout.write(json.dumps(payload, ensure_ascii=True, separators=(",", ":")) + "\n")
    return returncode


def run_bounded_cli_hook(config: Mapping[str, object], *, input_text: str) -> int:
    """Run one isolated CLI hook and preserve its native stdout contract."""

    python_executable = config.get("python_executable")
    package_root_value = config.get("package_root")
    guard_home_value = config.get("guard_home")
    cli_args_value = config.get("cli_args")
    harness = config.get("harness")
    timeout_seconds = config.get("timeout_seconds")
    if (
        not isinstance(python_executable, str)
        or not isinstance(package_root_value, str)
        or not isinstance(guard_home_value, str)
        or not isinstance(cli_args_value, list)
        or not isinstance(harness, str)
        or not isinstance(timeout_seconds, (int, float))
        or timeout_seconds <= 0
    ):
        return _emit_failure(harness=str(harness or "unknown"), input_text=input_text)
    raw_cli_args = cast(list[object], cli_args_value)
    cli_args = [item for item in raw_cli_args if isinstance(item, str)]
    if len(cli_args) != len(raw_cli_args):
        return _emit_failure(harness=harness, input_text=input_text)
    package_root = Path(package_root_value)
    guard_home = Path(guard_home_value)
    command = isolated_guard_cli_command(
        python_executable,
        package_root,
        cli_args,
    )
    result = run_isolated_hook_process(
        command,
        input_text=input_text,
        cwd=guard_home,
        environment=isolated_hook_environment(),
        timeout_seconds=float(timeout_seconds),
    )
    if result.timed_out:
        return _emit_failure(harness=harness, input_text=input_text)
    if result.output_limit_exceeded:
        return _emit_failure(
            harness=harness,
            input_text=input_text,
            reason="HOL Guard blocked this action because hook output exceeded the safe size limit.",
        )
    if result.returncode is None:
        return _emit_failure(harness=harness, input_text=input_text)
    if not _has_json_object_line(result.stdout):
        return _emit_failure(harness=harness, input_text=input_text)
    if result.stdout:
        _ = sys.stdout.write(result.stdout)
    return result.returncode


def main_from_argv(argv: Sequence[str]) -> int:
    """Parse the authenticated install-time hook config and run it."""

    input_text = _bounded_stdin()
    if input_text is None:
        return _emit_failure(
            harness="unknown",
            input_text="{}",
            reason="HOL Guard blocked this action because hook input exceeded the safe size limit.",
        )
    if len(argv) != 1:
        return _emit_failure(harness="unknown", input_text=input_text)
    config = _json_object(argv[0])
    if config is None:
        return _emit_failure(harness="unknown", input_text=input_text)
    return run_bounded_cli_hook(config, input_text=input_text)


__all__ = ["bounded_cli_hook_command", "main_from_argv", "run_bounded_cli_hook"]
