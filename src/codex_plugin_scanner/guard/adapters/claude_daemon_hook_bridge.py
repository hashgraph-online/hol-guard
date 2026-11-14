"""Compatibility launcher for Claude hook commands written before the native bridge.

The daemon hook review itself lives in the runtime
(``rust/crates/guard-runtime/src/claude_hook_bridge.rs``). Guard installs that
runtime's ``claude-hook-bridge`` command directly whenever the runtime is
present, and SessionStart rewrites older commands, so this module only has to
carry a session that is still running a hook command written before the
runtime shipped: it runs the same native command with the same config.

There is no Python evaluator behind it. Every hook review needs the native
runtime, so an install without one has nothing left to ask and the hook denies.
The runtime also builds the daemon recovery command: this launcher only names
the program that recovers the daemon, which is itself.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from .hook_input_reader import read_stdin_text
from .native_hook_bridge import native_hook_bridge_executable

CLAUDE_GUARD_DAEMON_HOOK_MARKER = "HOL_GUARD_CLAUDE_DAEMON_HOOK"
_NATIVE_CLAUDE_HOOK_COMMAND = "claude-hook-bridge"
_NATIVE_CLAUDE_HOOK_FEATURE = "claude-hook-bridge-v1"
_DEGRADED_DAEMON_MESSAGE = "HOL Guard could not complete native review ({reason}) and denied this action."
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
    # Claude's hook window is 10s, and the child reserves up to 8s of it.
    # Bound cold native capability probing before launching the child.
    deadline = time.monotonic() + 1.5
    runtime = native_hook_bridge_executable(
        _NATIVE_CLAUDE_HOOK_FEATURE, guard_home=guard_home, deadline_monotonic=deadline
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
                _NATIVE_CLAUDE_HOOK_FEATURE, guard_home=guard_home, deadline_monotonic=deadline
            )
    return runtime


def _native_bridge_command() -> str:
    return _NATIVE_CLAUDE_HOOK_COMMAND


def _native_bridge_config(
    *,
    state_path: str | Path,
    fallback_daemon_url: str,
    fallback_command: tuple[str, ...],
    query: str,
) -> str:
    """The config the installed native command carries, rebuilt from this call."""

    config = {
        "state_path": str(state_path),
        "fallback_daemon_url": fallback_daemon_url,
        "fallback_command": list(fallback_command),
        "query": query,
        "recovery_launcher": _recovery_launcher(),
    }
    return json.dumps(config, ensure_ascii=False, separators=(",", ":"))


def _recovery_launcher() -> dict[str, object]:
    """The program the runtime starts to recover the daemon: this Guard."""

    from ..frozen_runtime_commands import is_frozen_guard_runtime
    from ..stable_guard_cli import resolve_frozen_guard_cli

    if is_frozen_guard_runtime():
        # A frozen desktop core has no interpreter to run a Python bootstrap.
        return {"executable": resolve_frozen_guard_cli(), "frozen": True}
    return {"executable": sys.executable, "package_root": str(Path(__file__).resolve().parents[3])}


def _deny_without_a_runtime() -> int:
    body, oversized = read_stdin_text(_MAX_HOOK_INPUT_BYTES)
    event = _event_name(body if oversized else body.strip() or "{}")
    if oversized:
        message = "HOL Guard blocked this action because hook input exceeded the safe size limit."
    elif event in {"UserPromptSubmit", "PreToolUse"} or event.startswith("Permission"):
        # A legacy prompt hook must not silently accept unreviewed text either.
        message = _DEGRADED_DAEMON_MESSAGE.format(reason=_NATIVE_RUNTIME_UNAVAILABLE)
    else:
        sys.stdout.write("{}")
        return 0
    sys.stdout.write(_deny_event(event, message))
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
