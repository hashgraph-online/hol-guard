"""Compatibility launcher for Codex hook commands written before the native bridge.

The daemon hook review itself lives in the runtime
(``rust/crates/guard-runtime/src/codex_hook_bridge.rs``). Guard installs that
runtime's ``codex-hook-bridge`` command ahead of this bridge whenever the
runtime is present, so what is left here is the hook command of a session
written before the runtime shipped, and the frozen Desktop entry point that
still calls ``main`` in process: both run the same native command with the
same config argument.

There is no Python evaluator behind it. Every hook review needs the native
runtime, so an install without one has nothing left to ask and the hook
fails closed.

A frozen macOS Desktop keeps one lane of its own. A transition probe there
must be answered by the signed bundle executable, not by a runtime copy
published beside the Guard home. The runtime reads the hook and hands a probe
back with the paths it names, and this module builds that strict signed-proxy
command and runs it. Python decides nothing on that lane either; it only
starts the signed binary the runtime named the hook for.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

if __package__:
    from ..codex_hook_bridge_runtime import BridgeConfig, trusted_hook_launch
    from ..codex_hook_bridge_runtime import bounded_hook_input as _hook_input
    from ..codex_hook_bridge_runtime import bridge_config_from_argv as _parse_bridge_config
    from ..codex_hook_compatibility import NATIVE_CODEX_HOOK_COMMAND, NATIVE_CODEX_HOOK_FEATURE
    from ..codex_hook_launch_runtime import (
        desktop_hook_proxy_context,
        isolated_hook_environment,
        run_isolated_hook_process,
    )
    from ..hook_review.hook_availability_policy import hook_event_is_permission_request
    from ..hook_review.hook_request_parsing import runtime_hook_event_name
    from .native_hook_bridge import native_hook_bridge_executable
else:  # pragma: no cover - exercised by subprocess integration tests
    _package_root = str(Path(__file__).resolve().parents[3])
    if _package_root not in sys.path:
        sys.path.insert(0, _package_root)
    from codex_plugin_scanner.guard.adapters.native_hook_bridge import native_hook_bridge_executable
    from codex_plugin_scanner.guard.codex_hook_bridge_runtime import (
        BridgeConfig,
        trusted_hook_launch,
    )
    from codex_plugin_scanner.guard.codex_hook_bridge_runtime import (
        bounded_hook_input as _hook_input,
    )
    from codex_plugin_scanner.guard.codex_hook_bridge_runtime import (
        bridge_config_from_argv as _parse_bridge_config,
    )
    from codex_plugin_scanner.guard.codex_hook_compatibility import (
        NATIVE_CODEX_HOOK_COMMAND,
        NATIVE_CODEX_HOOK_FEATURE,
    )
    from codex_plugin_scanner.guard.codex_hook_launch_runtime import (
        desktop_hook_proxy_context,
        isolated_hook_environment,
        run_isolated_hook_process,
    )
    from codex_plugin_scanner.guard.hook_review.hook_availability_policy import (
        hook_event_is_permission_request,
    )
    from codex_plugin_scanner.guard.hook_review.hook_request_parsing import runtime_hook_event_name

_HOOK_TIMEOUT_GRACE_SECONDS = 2
_MAX_HOOK_INPUT_BYTES = 1_000_000
_TRANSITION_PROBE_OUTPUT_LIMIT = 64 * 1024
_NATIVE_RUNTIME_UNAVAILABLE = (
    "HOL Guard could not complete native review (the native runtime is unavailable) and denied this action."
)
_BRIDGE_FAILURE_SCHEMA = "hol-guard.codex-bridge-failure.v1"
_NATIVE_RUNTIME_MISSING_CODE = "codex_hook_native_runtime_missing"
_LAUNCH_UNAUTHENTICATED_CODE = "codex_hook_launch_unauthenticated"
_RUNTIME_LAUNCH_FAILED_CODE = "codex_hook_native_runtime_launch_failed"
_DESKTOP_LANE_FLAG = "--guard-desktop-lane"
_FAILURE_FLAG = "--guard-registration-failure="
_PROBE_HANDOFF_SCHEMA = "hol-guard.codex-desktop-probe.v1"
_PROBE_HANDOFF_EXIT = 75


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
    """Run this hook call in the native bridge, or deny when there is no runtime."""

    state = Path(state_path)
    if _desktop_probe_lane():
        return _desktop_main(
            state=state,
            query=query,
            hook_timeouts=hook_timeouts,
            fallback_command=fallback_command,
            start_command=start_command,
            manifest_path=manifest_path,
            config_json=config_json,
        )
    native = _native_bridge_executable(state.parent)
    if native is None:
        return _deny_before_the_runtime_runs(_NATIVE_RUNTIME_MISSING_CODE)
    unauthenticated = _registration_failure(
        state_path=state,
        fallback_command=fallback_command,
        start_command=start_command,
        hook_timeouts=hook_timeouts,
        manifest_path=manifest_path,
        config_json=config_json,
    )
    if unauthenticated is not None:
        return _deny_before_the_runtime_runs(unauthenticated)
    sys.stdout.flush()
    # The child inherits this hook call's stdio, so it reads the hook body and
    # writes the response itself. ``exec`` would save the fork, but this entry
    # point is also called in process, where replacing the caller is wrong.
    try:
        return subprocess.run(
            _native_argv(
                native,
                state_path=state_path,
                fallback_command=fallback_command,
                start_command=start_command,
                query=query,
                hook_timeouts=hook_timeouts,
                manifest_path=manifest_path,
                config_json=config_json,
            ),
            check=False,
        ).returncode
    except OSError:
        # A runtime that cannot be started answers nothing, and a hook that
        # answers nothing lets the call through, so deny it here instead.
        return _deny_before_the_runtime_runs(_RUNTIME_LAUNCH_FAILED_CODE)


def _desktop_main(
    *,
    state: Path,
    query: str,
    hook_timeouts: Mapping[str, int],
    fallback_command: Sequence[str],
    start_command: Sequence[str],
    manifest_path: str | Path | None,
    config_json: str | None,
) -> int:
    """Review this hook in the runtime, or in the signed bundle when it is a probe.

    The runtime reads the hook body and decides whether it is a transition
    probe. A probe comes back as a handoff, because only the signed bundle
    executable may answer it; anything else the runtime reviews itself.
    """

    native = _native_bridge_executable(state.parent)
    if native is None:
        return _deny_before_the_runtime_runs(_NATIVE_RUNTIME_MISSING_CODE)
    # The runtime cannot be told the body is not a probe before it reads it,
    # so a registration that failed is passed on rather than denied here.
    unauthenticated = _registration_failure(
        state_path=state,
        fallback_command=fallback_command,
        start_command=start_command,
        hook_timeouts=hook_timeouts,
        manifest_path=manifest_path,
        config_json=config_json,
    )
    lane = (_DESKTOP_LANE_FLAG,) if unauthenticated is None else (_DESKTOP_LANE_FLAG, _FAILURE_FLAG + unauthenticated)
    sys.stdout.flush()
    try:
        completed = subprocess.run(
            _native_argv(
                native,
                state_path=state,
                fallback_command=fallback_command,
                start_command=start_command,
                query=query,
                hook_timeouts=hook_timeouts,
                manifest_path=manifest_path,
                config_json=config_json,
                lane=lane,
            ),
            stdout=subprocess.PIPE,
            check=False,
        )
    except OSError:
        # Nothing reviewed this call, and silence here would let it run.
        return _deny_before_the_runtime_runs(_RUNTIME_LAUNCH_FAILED_CODE)
    output = completed.stdout.decode("utf-8", "surrogateescape")
    if completed.returncode != _PROBE_HANDOFF_EXIT:
        sys.stdout.write(output)
        return completed.returncode
    try:
        handoff = _probe_handoff(output)
        probe_command = _desktop_transition_probe_command(handoff)
    except (OSError, RuntimeError, ValueError):
        sys.stdout.write(json.dumps(_fail_closed("PreToolUse"), separators=(",", ":")))
        return 1
    try:
        probe_result = run_isolated_hook_process(
            probe_command,
            input_text=handoff["data"],
            cwd=Path.home(),
            environment=isolated_hook_environment(),
            output_limit=_TRANSITION_PROBE_OUTPUT_LIMIT,
            deadline_monotonic=time.monotonic() + handoff["remaining_seconds"],
        )
    except OSError:
        sys.stdout.write(json.dumps(_fail_closed("PreToolUse"), separators=(",", ":")))
        return 1
    if (
        probe_result.returncode != 0
        or probe_result.timed_out
        or probe_result.containment_failed
        or probe_result.output_limit_exceeded
    ):
        sys.stdout.write(json.dumps(_fail_closed("PreToolUse"), separators=(",", ":")))
        return 1
    sys.stdout.write(probe_result.stdout)
    sys.stderr.write(probe_result.stderr)
    return 0


def _probe_handoff(output: str) -> dict[str, Any]:
    """The probe handoff the runtime wrote; anything else is refused."""

    payload = _json_object(output) or {}
    if (
        payload.get("schema") != _PROBE_HANDOFF_SCHEMA
        or not all(isinstance(payload.get(key), str) for key in ("data", "guard_home", "home", "workspace"))
        or type(payload.get("timeout_seconds")) is not int
        or type(payload.get("remaining_seconds")) not in (int, float)
    ):
        raise ValueError("codex_hook_probe_handoff_invalid")
    return payload


def _desktop_probe_lane(environment: Mapping[str, str] | None = None) -> bool:
    """Whether this call is the frozen macOS Desktop lane that owns the probe."""

    source = os.environ if environment is None else environment
    return bool(getattr(sys, "frozen", False)) and sys.platform == "darwin" and source.get("HOL_GUARD_DESKTOP") == "1"


def _native_argv(
    native: Path,
    *,
    state_path: str | Path,
    fallback_command: Sequence[str],
    start_command: Sequence[str],
    query: str,
    hook_timeouts: Mapping[str, int],
    manifest_path: str | Path | None,
    config_json: str | None,
    lane: Sequence[str] = (),
) -> tuple[str, ...]:
    return (
        str(native),
        _native_bridge_command(),
        *lane,
        config_json
        if config_json is not None
        else _native_bridge_config(
            state_path=state_path,
            fallback_command=fallback_command,
            start_command=start_command,
            query=query,
            hook_timeouts=hook_timeouts,
            manifest_path=manifest_path,
        ),
    )


def _native_bridge_executable(guard_home: Path) -> Path | None:
    return native_hook_bridge_executable(NATIVE_CODEX_HOOK_FEATURE, guard_home=guard_home)


def _native_bridge_command() -> str:
    return NATIVE_CODEX_HOOK_COMMAND


def _native_bridge_config(
    *,
    state_path: str | Path,
    fallback_command: Sequence[str],
    start_command: Sequence[str],
    query: str,
    hook_timeouts: Mapping[str, int],
    manifest_path: str | Path | None,
) -> str:
    """The config the installed native command carries, rebuilt from this call.

    The runtime reads the same fields ``bridge_config_from_argv`` does, and
    refuses anything Python would refuse, so a call that arrives without its
    original argument is rebuilt here rather than repaired.
    """

    config = {
        "state_path": str(state_path),
        "manifest_path": str(manifest_path or ""),
        "fallback_command": [str(item) for item in fallback_command],
        "start_command": [str(item) for item in start_command],
        "query": query,
        "hook_timeouts": {str(event): int(timeout) for event, timeout in hook_timeouts.items()},
    }
    return json.dumps(config, ensure_ascii=False, separators=(",", ":"))


def _desktop_transition_probe_command(
    handoff: Mapping[str, Any],
    environment: Mapping[str, str] | None = None,
) -> tuple[str, ...]:
    """Build the strict signed-proxy path for the probe the runtime handed back."""

    source = os.environ if environment is None else environment
    proxy = desktop_hook_proxy_context(source).get("HOL_GUARD_DESKTOP_HOOK_PROXY")
    if proxy is None:
        raise RuntimeError("Desktop transition probe has no signed proxy")
    guard_home = Path(handoff["guard_home"])

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
            str(Path(handoff["home"]).resolve(strict=False)),
            "--workspace",
            str(Path(handoff["workspace"]).resolve(strict=False)),
        ],
        harness="codex",
        timeout_seconds=float(handoff["timeout_seconds"]),
        require_desktop_proxy=True,
    )
    if len(command) != 10 or command[4] != proxy or command[8] != proxy or command[9] != "1":
        raise RuntimeError("Desktop transition probe did not resolve to its strict signed proxy")
    return command


def _registration_failure(
    *,
    state_path: Path,
    fallback_command: Sequence[str],
    start_command: Sequence[str],
    hook_timeouts: Mapping[str, int],
    manifest_path: str | Path | None,
    config_json: str | None,
) -> str | None:
    """The reason code this registration no longer matches its manifest, if any.

    The runtime runs the registered fallback argv as the prefix of the
    contained-execution sink and the start argv to bring the daemon up, so a
    registration an attacker rewrote must not reach it. This authenticates the
    hook's own installation; it renders no verdict about the call, which stays
    the runtime's to make. ``None`` means the registration authenticated.
    """

    if manifest_path is None and config_json is None:
        return None
    if manifest_path is None or config_json is None:
        return _LAUNCH_UNAUTHENTICATED_CODE
    try:
        trusted_hook_launch(
            manifest_path=manifest_path,
            state_path=state_path,
            fallback_command=fallback_command,
            start_command=start_command,
            config_json=config_json,
            deadline_monotonic=_validation_deadline(hook_timeouts),
        )
    except Exception as exc:  # a validator fault leaves the launch unauthenticated
        # The validators carry a stable, non-secret reason; anything else is
        # reported as the authentication failure it is rather than guessed at.
        reason = getattr(exc, "reason", None)
        return reason if isinstance(reason, str) and reason else _LAUNCH_UNAUTHENTICATED_CODE
    return None


def _validation_deadline(hook_timeouts: Mapping[str, int]) -> float | None:
    """The budget this authentication may spend out of the hook's own timeout.

    The call's event is unknown here, because the body belongs to the runtime,
    so the shortest configured timeout bounds it. Authentication reads the
    manifest and hashes the registered files; it must never be what makes a
    hook miss its deadline.
    """

    timeouts = [int(timeout) for timeout in hook_timeouts.values() if int(timeout) > 0]
    if not timeouts:
        return None
    return time.monotonic() + max(1, min(timeouts) - _HOOK_TIMEOUT_GRACE_SECONDS)


def _deny_before_the_runtime_runs(reason_code: str) -> int:
    """Fail this hook closed without launching anything, and say why."""

    data = _hook_input(_MAX_HOOK_INPUT_BYTES)
    event_name = "PreToolUse" if data is None else _event_name(data)
    sys.stdout.write(json.dumps(_fail_closed(event_name), separators=(",", ":")))
    _write_failure_cause(reason_code)
    return 0


def _write_failure_cause(reason_code: str) -> None:
    """Report the fixed reason code behind a denial without exposing details.

    The denial itself is already on stdout, so a diagnostic that cannot be
    written must not take the response down with it.
    """

    document = {"schema": _BRIDGE_FAILURE_SCHEMA, "causes": [{"reason_code": reason_code}]}
    try:
        sys.stderr.write(json.dumps(document, separators=(",", ":")) + "\n")
        sys.stderr.flush()
    except (OSError, ValueError):
        return


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
    return runtime_hook_event_name(payload)


def _fail_closed(event_name: str, reason: str = _NATIVE_RUNTIME_UNAVAILABLE) -> dict[str, object]:
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
