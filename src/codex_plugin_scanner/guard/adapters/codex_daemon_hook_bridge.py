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
published beside the Guard home, so this module still builds that strict
signed-proxy command and runs it. Python decides nothing on that lane either;
it only chooses which signed binary reviews the hook.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from urllib.parse import parse_qs

if __package__:
    from ..approval_wait_limits import MAX_APPROVAL_WAIT_TIMEOUT_SECONDS
    from ..codex_hook_bridge_runtime import BridgeConfig, trusted_hook_launch
    from ..codex_hook_bridge_runtime import bounded_hook_input as _hook_input
    from ..codex_hook_bridge_runtime import bridge_config_from_argv as _parse_bridge_config
    from ..codex_hook_compatibility import NATIVE_CODEX_HOOK_COMMAND, NATIVE_CODEX_HOOK_FEATURE
    from ..codex_hook_launch_runtime import (
        desktop_hook_proxy_context,
        isolated_hook_environment,
        run_isolated_hook_process,
    )
    from ..daemon.hook_availability_policy import hook_event_is_permission_request
    from ..daemon.hook_request_parsing import runtime_hook_event_name
    from ..hook_execution_environment import stamp_hook_input_text
    from ..live_process_identity import (
        CODEX_BROWSER_WAIT_PROCESS_KEY,
        CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY,
        current_process_identity,
    )
    from .native_hook_bridge import native_hook_bridge_executable
else:  # pragma: no cover - exercised by subprocess integration tests
    _package_root = str(Path(__file__).resolve().parents[3])
    if _package_root not in sys.path:
        sys.path.insert(0, _package_root)
    from codex_plugin_scanner.guard.adapters.native_hook_bridge import native_hook_bridge_executable
    from codex_plugin_scanner.guard.approval_wait_limits import MAX_APPROVAL_WAIT_TIMEOUT_SECONDS
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
_MAX_HOOK_INPUT_BYTES = 1_000_000
_TRANSITION_PROBE_OUTPUT_LIMIT = 64 * 1024
_NATIVE_RUNTIME_UNAVAILABLE = (
    "HOL Guard could not complete native review (the native runtime is unavailable) and denied this action."
)
_BRIDGE_FAILURE_SCHEMA = "hol-guard.codex-bridge-failure.v1"
_NATIVE_RUNTIME_MISSING_CODE = "codex_hook_native_runtime_missing"
_LAUNCH_UNAUTHENTICATED_CODE = "codex_hook_launch_unauthenticated"
_RUNTIME_LAUNCH_FAILED_CODE = "codex_hook_native_runtime_launch_failed"
_RUNTIME_DEADLINE_CODE = "codex_hook_native_runtime_deadline_exceeded"


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
    """Review this hook inside the signed bundle, or hand the body to the runtime.

    The probe lane is the one case where Python has to read the hook body
    before it knows where the review belongs, so a body read here is passed on
    rather than inherited.
    """

    hook_input = _bound_hook_input(hook_timeouts)
    if hook_input is None:
        sys.stdout.write(json.dumps(_fail_closed("PreToolUse"), separators=(",", ":")))
        return 0
    event_name, data, timeout_seconds, input_ready_at, raw_data = hook_input
    try:
        probe_command = _desktop_transition_probe_command(
            data=data,
            state_path=state,
            query=query,
            hook_timeouts=hook_timeouts,
        )
    except (OSError, RuntimeError, ValueError):
        sys.stdout.write(json.dumps(_fail_closed(event_name), separators=(",", ":")))
        return 1
    if probe_command is None:
        native = _native_bridge_executable(state.parent)
        if native is None:
            return _desktop_denial(event_name, _NATIVE_RUNTIME_MISSING_CODE)
        unauthenticated = _registration_failure(
            state_path=state,
            fallback_command=fallback_command,
            start_command=start_command,
            hook_timeouts=hook_timeouts,
            manifest_path=manifest_path,
            config_json=config_json,
        )
        if unauthenticated is not None:
            return _desktop_denial(event_name, unauthenticated)
        sys.stdout.flush()
        # Desktop dispatch spends part of this hook's budget before the runtime
        # starts, so the runtime reviews inside what is left of it rather than
        # starting a second one. It derives its own deadline, and the browser
        # approval wait hanging off it, from the configured timeout for this
        # event, so the remainder has to reach it as that timeout.
        remaining = int(input_ready_at + timeout_seconds - time.monotonic())
        if remaining < 1:
            return _desktop_denial(event_name, _RUNTIME_DEADLINE_CODE)
        try:
            child_timeouts, child_config = _budget_for_the_runtime(
                event_name=event_name,
                remaining_seconds=remaining,
                hook_timeouts=hook_timeouts,
                config_json=config_json,
            )
        except ValueError:
            # A registration this hook cannot read is not one it can shorten.
            return _desktop_denial(event_name, _LAUNCH_UNAUTHENTICATED_CODE)
        try:
            completed = subprocess.run(
                _native_argv(
                    native,
                    state_path=state,
                    fallback_command=fallback_command,
                    start_command=start_command,
                    query=query,
                    hook_timeouts=child_timeouts,
                    manifest_path=manifest_path,
                    config_json=child_config,
                ),
                input=raw_data.encode("utf-8", "surrogateescape"),
                capture_output=True,
                # The runtime answers on its own deadline; this only stops a
                # child that ignored the deadline it was given. It takes back
                # part of the grace Python held so the denial below is written
                # while Codex is still reading this hook, not as it gives up.
                timeout=remaining + _HOOK_TIMEOUT_GRACE_SECONDS / 2,
                check=False,
            )
        except OSError:
            # Nothing reviewed this call, and silence here would let it run.
            return _desktop_denial(event_name, _RUNTIME_LAUNCH_FAILED_CODE)
        except subprocess.TimeoutExpired:
            return _desktop_denial(event_name, _RUNTIME_DEADLINE_CODE)
        sys.stdout.write(completed.stdout.decode("utf-8", "surrogateescape"))
        sys.stderr.write(completed.stderr.decode("utf-8", "surrogateescape"))
        return completed.returncode
    try:
        probe_result = run_isolated_hook_process(
            probe_command,
            input_text=data,
            cwd=Path.home(),
            environment=isolated_hook_environment(),
            output_limit=_TRANSITION_PROBE_OUTPUT_LIMIT,
            deadline_monotonic=input_ready_at + timeout_seconds,
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
) -> tuple[str, ...]:
    return (
        str(native),
        _native_bridge_command(),
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
    *,
    data: str,
    state_path: str | Path,
    query: str,
    hook_timeouts: Mapping[str, int],
    environment: Mapping[str, str] | None = None,
) -> tuple[str, ...] | None:
    """Build the strict signed-proxy path for an authenticated Desktop probe."""

    source = os.environ if environment is None else environment
    if not _desktop_probe_lane(source):
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


def _bound_hook_input(hook_timeouts: Mapping[str, int]) -> tuple[str, str, float, float, str] | None:
    """The probe lane's hook body, stamped the way the runtime stamps its own, and as it arrived."""

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
    return event_name, stamp_hook_input_text(data), timeout_seconds, input_ready_at, raw_data


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


def _budget_for_the_runtime(
    *,
    event_name: str,
    remaining_seconds: int,
    hook_timeouts: Mapping[str, int],
    config_json: str | None,
) -> tuple[Mapping[str, int], str | None]:
    """This hook's registration with one event's timeout cut to what is left.

    The runtime subtracts the same grace Python did, so the remainder goes back
    on as a configured timeout rather than as a deadline of its own.
    """

    configured = remaining_seconds + _HOOK_TIMEOUT_GRACE_SECONDS
    timeouts = {str(event): int(timeout) for event, timeout in hook_timeouts.items()}
    timeouts[event_name] = configured
    if config_json is None:
        return timeouts, None
    config = json.loads(config_json)
    if not isinstance(config, dict):
        raise ValueError("codex_hook_bridge_config_not_an_object")
    registered = config.get("hook_timeouts")
    config["hook_timeouts"] = {
        **({str(event): int(timeout) for event, timeout in registered.items()} if isinstance(registered, dict) else {}),
        event_name: configured,
    }
    return timeouts, json.dumps(config, ensure_ascii=False, separators=(",", ":"))


def _desktop_denial(event_name: str, reason_code: str) -> int:
    """Fail a Desktop hook closed once its body has already been read."""

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
