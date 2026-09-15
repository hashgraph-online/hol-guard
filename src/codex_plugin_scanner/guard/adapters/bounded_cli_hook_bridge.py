"""Bounded subprocess bridge for harnesses without a daemon-native hook."""

from __future__ import annotations

import json
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

from ..codex_hook_launch_runtime import (
    isolated_guard_cli_command,
    isolated_hook_environment,
    run_isolated_hook_process,
)
from ..stable_guard_cli import prune_safe_cli_executable
from .bounded_cli_hook_failure import failure_payload as _failure_payload
from .desktop_hook_proxy import (
    _DESKTOP_PROXY_LAUNCH_SCRIPT as _DESKTOP_PROXY_LAUNCH_SCRIPT,
)
from .desktop_hook_proxy import (
    _trusted_desktop_hook_proxy_command,
)

_MAX_HOOK_INPUT_BYTES = 1_000_000
_FAILURE_REASON = "HOL Guard could not complete this review before the hook deadline. Retry the action."
_FROZEN_BRIDGE_COMMAND = "__guard-bounded-hook"
_FROZEN_OPTIONAL_PATH_FLAGS = frozenset({"--home", "--workspace"})


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
    if frozen_launcher:
        python_executable = prune_safe_cli_executable(python_executable)
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
    "permissionrequestv2": "PermissionRequest",
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


def _emit_failure(
    *,
    harness: str,
    input_text: str,
    reason: str = _FAILURE_REASON,
    guard_home: Path | None = None,
    continue_session: bool = False,
) -> int:
    payload, returncode = _failure_payload(
        harness=harness,
        event_name=_event_name(input_text),
        reason=reason,
        payload=_json_object(input_text or "{}"),
        recording_only=guard_home is not None and _guard_home_is_recording_only(guard_home),
        continue_session=continue_session,
    )
    _ = sys.stdout.write(json.dumps(payload, ensure_ascii=True, separators=(",", ":")) + "\n")
    return returncode


def _daemon_hook_endpoint(guard_home: Path, harness: str) -> str | None:
    from .bounded_cli_hook_daemon import _daemon_hook_endpoint as implementation

    return implementation(guard_home, harness)


def _read_daemon_auth_token(guard_home: Path) -> str | None:
    from .bounded_cli_hook_daemon import _read_daemon_auth_token as implementation

    return implementation(guard_home)


def _build_loopback_opener():  # type: ignore[no-untyped-def]
    from .bounded_cli_hook_daemon import _build_loopback_opener as implementation

    return implementation()


def _try_daemon_hook(
    *,
    guard_home: Path,
    harness: str,
    input_text: str,
    timeout_seconds: float,
) -> tuple[str, str, int] | None:
    """Retain legacy private patch points for established direct callers."""
    from . import bounded_cli_hook_daemon as daemon

    return daemon.try_daemon_hook(
        guard_home=guard_home,
        harness=harness,
        input_text=input_text,
        timeout_seconds=timeout_seconds,
        _endpoint_loader=_daemon_hook_endpoint,
        _token_loader=_read_daemon_auth_token,
        _opener_builder=_build_loopback_opener,
    )


def _daemon_response_to_native(
    daemon_response: dict[str, object],
    *,
    harness: str,
    event_name: str,
) -> tuple[str, str, int]:
    from .bounded_cli_hook_daemon import _daemon_response_to_native as implementation

    return implementation(daemon_response, harness=harness, event_name=event_name)


def run_bounded_cli_hook(config: Mapping[str, object], *, input_text: str) -> int:
    """Run one isolated CLI hook and preserve its native stdout contract."""

    from .bounded_cli_hook_daemon import _apply_grok_bridge_approval_wait, try_daemon_hook

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
    deadline = time.monotonic() + float(timeout_seconds)
    daemon_result = try_daemon_hook(
        guard_home=guard_home,
        harness=harness,
        input_text=input_text,
        timeout_seconds=float(timeout_seconds),
    )
    if daemon_result is not None:
        remaining = max(0.0, deadline - time.monotonic())
        daemon_stdout, daemon_stderr, daemon_exit = _apply_grok_bridge_approval_wait(
            guard_home=guard_home,
            harness=harness,
            input_text=input_text,
            stdout=daemon_result[0],
            stderr=daemon_result[1],
            exit_code=daemon_result[2],
            timeout_seconds=remaining,
        )
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
        return _emit_failure(
            harness=harness,
            input_text=input_text,
            guard_home=guard_home,
            continue_session=True,
        )
    if result.output_limit_exceeded:
        return _emit_failure(
            harness=harness,
            input_text=input_text,
            reason="HOL Guard blocked this action because hook output exceeded the safe size limit.",
            guard_home=guard_home,
        )
    if result.returncode is None:
        return _emit_failure(
            harness=harness,
            input_text=input_text,
            guard_home=guard_home,
            continue_session=True,
        )
    compact_payload = _json_object(result.stdout.strip())
    if compact_payload is None and not _has_json_object_line(result.stdout):
        return _emit_failure(
            harness=harness,
            input_text=input_text,
            guard_home=guard_home,
            continue_session=True,
        )
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
