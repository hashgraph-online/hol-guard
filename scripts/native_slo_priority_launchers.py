"""Measure the four priority hooks using their installed command registrations.

Every sample starts the registered executable, sends stdin, captures stdout,
waits for exit, and checks the harness response. No direct HTTP request replaces
a launcher. The caller owns a prepared, otherwise idle daemon with an explicit
acknowledged allow policy (``DaemonFixture(runtime, policy="normal")``).
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import shlex
import sys
import threading
import time
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.claude_code import ClaudeCodeHarnessAdapter
from codex_plugin_scanner.guard.adapters.claude_hook_config import (
    claude_managed_settings_path,
    command_handler_argv,
    is_guard_hook_handler,
)
from codex_plugin_scanner.guard.adapters.codex import CodexHarnessAdapter
from codex_plugin_scanner.guard.codex_hook_launch_runtime import run_isolated_hook_process
from scripts.native_probe_receipts import wait_for_route_corpus
from scripts.native_slo_adapter import Observation, route_counts
from scripts.native_slo_batch import validate_batch_routes
from scripts.native_slo_contract import clear_proof_environment, summarize

_CONFIG_LIMIT = 1_000_000
_TOML = importlib.import_module("tomllib" if sys.version_info >= (3, 11) else "tomli")
_OUTPUT_LIMIT = 2 * 1024 * 1024
_LAUNCH_TIMEOUT_SECONDS = 10.0
_MAX_SAMPLES_PER_SERIES = 100_000
_CONCURRENCY = 16
_PRIORITY_ROUTES = (
    ("claude-code", "PreToolUse"),
    ("claude-code", "PostToolUse"),
    ("codex", "PreToolUse"),
    ("codex", "PostToolUse"),
)


class _Metrics(Protocol):
    def snapshot(self) -> Mapping[str, object]: ...


class _Worker(Protocol):
    metrics: _Metrics


class _Server(Protocol):
    hook_worker: _Worker


class _Daemon(Protocol):
    _server: _Server


class LauncherSession(Protocol):
    """Only control metadata is shared with the load generator."""

    root: Path
    workspace: Path
    guard_home: Path
    daemon: _Daemon


@dataclass(frozen=True, slots=True)
class RegisteredLauncher:
    harness: str
    event: str
    argv: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    registration_sha256: str
    config_path: Path


def _read_configuration(path: Path, *, is_toml: bool) -> Mapping[str, object]:
    with path.open("rb") as stream:
        raw = stream.read(_CONFIG_LIMIT + 1)
    if len(raw) > _CONFIG_LIMIT:
        raise RuntimeError("priority_launcher_configuration_limit")
    try:
        parsed: object = _TOML.loads(raw.decode("utf-8")) if is_toml else json.loads(raw)
    except (UnicodeDecodeError, ValueError) as error:
        raise RuntimeError("priority_launcher_configuration_invalid") from error
    if not isinstance(parsed, Mapping):
        raise RuntimeError("priority_launcher_configuration_invalid")
    return cast(Mapping[str, object], parsed)


def registered_launcher(config_path: Path, harness: str, event: str) -> RegisteredLauncher:
    """Read exact generated argv and environment back from the installed file.

    Codex's adapter serializes argv with POSIX ``shlex.join`` on every platform.
    Require a lossless round trip; never execute reconstructed shell operators.
    Claude's installed structured command/args need no tokenization.
    """

    if (harness, event) not in _PRIORITY_ROUTES:
        raise ValueError("priority_launcher_route_unsupported")
    configuration = _read_configuration(config_path, is_toml=harness == "codex")
    if harness == "codex":
        features = configuration.get("features")
        if not isinstance(features, Mapping) or features.get("hooks") is not True:
            raise RuntimeError("priority_launcher_hooks_disabled")
    hooks = configuration.get("hooks")
    groups = hooks.get(event) if isinstance(hooks, Mapping) else None
    if not isinstance(groups, list):
        raise RuntimeError("priority_launcher_registration_missing")
    registrations: list[tuple[tuple[str, ...], tuple[tuple[str, str], ...], Mapping[str, object]]] = []
    for group in groups:
        if not isinstance(group, Mapping) or group.get("enabled", True) is not True:
            raise RuntimeError("priority_launcher_group_invalid")
        handlers = group.get("hooks")
        if not isinstance(handlers, list):
            raise RuntimeError("priority_launcher_group_invalid")
        for raw_handler in handlers:
            if not isinstance(raw_handler, dict) or raw_handler.get("enabled", True) is not True:
                raise RuntimeError("priority_launcher_handler_invalid")
            handler = cast(dict[str, object], raw_handler)
            if handler.get("type") != "command":
                raise RuntimeError("priority_launcher_handler_not_command")
            if harness == "claude-code":
                if not is_guard_hook_handler(handler):
                    raise RuntimeError("priority_launcher_unmanaged_handler")
                argv = command_handler_argv(handler)
            else:
                command = handler.get("command")
                if not isinstance(command, str):
                    raise RuntimeError("priority_launcher_command_invalid")
                try:
                    argv = tuple(shlex.split(command, posix=True))
                except ValueError as error:
                    raise RuntimeError("priority_launcher_command_invalid") from error
                if shlex.join(argv) != command:
                    raise RuntimeError("priority_launcher_command_not_lossless")
                if len(argv) != 4 or argv[1] != "-I" or Path(argv[2]).name != "codex_daemon_hook_bridge.py":
                    raise RuntimeError("priority_launcher_unmanaged_handler")
            if not argv or any(not isinstance(arg, str) or "\x00" in arg for arg in argv):
                raise RuntimeError("priority_launcher_command_invalid")
            configured_env = handler.get("env", {})
            if not isinstance(configured_env, Mapping) or any(
                not isinstance(key, str) or not isinstance(value, str) for key, value in configured_env.items()
            ):
                raise RuntimeError("priority_launcher_environment_invalid")
            environment = tuple(sorted(cast(Mapping[str, str], configured_env).items()))
            registrations.append((argv, environment, {"group": dict(group), "handler": handler}))
    if len(registrations) != 1:
        raise RuntimeError("priority_launcher_registration_missing_or_ambiguous")
    argv, environment, registered = registrations[0]
    digest = hashlib.sha256(json.dumps(registered, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return RegisteredLauncher(harness, event, argv, environment, digest, config_path)


def install_priority_launchers(session: LauncherSession) -> tuple[RegisteredLauncher, ...]:
    """Install once into the fixture home, then independently read both configs."""

    # Both installed arms use this owned workspace even when a frozen payload
    # deliberately omits cwd. Codex only registers it for an explicit override.
    context = HarnessContext(
        home_dir=session.root,
        workspace_dir=session.workspace,
        guard_home=session.guard_home,
        workspace_override_explicit=True,
    )
    claude = ClaudeCodeHarnessAdapter().install(context)
    codex = CodexHarnessAdapter().install(context)
    if claude.get("active") is not True or codex.get("active") is not True:
        raise RuntimeError("priority_launcher_install_incomplete")
    claude_path = claude_managed_settings_path(context)
    codex_path = CodexHarnessAdapter._hook_config_path(context)
    return tuple(
        registered_launcher(claude_path if harness == "claude-code" else codex_path, harness, event)
        for harness, event in _PRIORITY_ROUTES
    )


def launcher_payload(event: str, sample: int, *, case: str = "benign") -> dict[str, object]:
    """Create only synthetic payloads; neither sample command is executed."""

    if case not in {"benign", "block"} or event not in {"PreToolUse", "PostToolUse"}:
        raise ValueError("priority_launcher_case_unsupported")
    result: dict[str, object] = {
        "hook_event_name": event,
        "guard_remaining_ms": 4_000,
        "tool_use_id": f"priority-qualification-{sample}",
    }
    if event == "PreToolUse":
        result.update(tool_name="Bash", tool_input={"command": "pwd" if case == "benign" else "rm -rf /"})
    else:
        prefix = ("gh" + "p_" + "b" * 30 + "\n") if case == "block" else ""
        content = (prefix + "const guard_value = 1;\n" * 49)[:1024]
        result.update(tool_name="Read", tool_response=[{"type": "text", "text": content}])
    return result


def validate_launcher_stdout(launcher: RegisteredLauncher, response: Mapping[str, object], *, case: str) -> None:
    """Frozen delivered contracts, including Codex's metadata filtering."""

    if case not in {"benign", "block"}:
        raise ValueError("priority_launcher_case_unsupported")
    allowed = case == "benign"
    specific = response.get("hookSpecificOutput")
    if not isinstance(specific, Mapping) or specific.get("hookEventName") != launcher.event:
        raise RuntimeError("priority_launcher_event_mismatch")
    if launcher.event == "PreToolUse":
        if specific.get("permissionDecision") != ("allow" if allowed else "deny"):
            raise RuntimeError("priority_launcher_permission_mismatch")
        if allowed and response.get("continue") is not True:
            raise RuntimeError("priority_launcher_continue_mismatch")
        if not allowed and (
            "continue" in response
            or not isinstance(specific.get("permissionDecisionReason"), str)
            or not specific["permissionDecisionReason"]
        ):
            raise RuntimeError("priority_launcher_block_mismatch")
    elif allowed:
        if set(specific) != {"hookEventName"} or "decision" in response or "model_output_action" in response:
            raise RuntimeError("priority_launcher_post_allow_mismatch")
    elif response.get("decision") != "block" or response.get("continue") is not True:
        raise RuntimeError("priority_launcher_post_block_mismatch")
    if launcher.harness == "codex":
        keys = {"hookSpecificOutput"}
        if launcher.event == "PreToolUse" and allowed:
            keys.add("continue")
        if launcher.event == "PostToolUse" and not allowed:
            keys |= {"decision", "reason", "continue", "stopReason"}
        if set(response) != keys:
            raise RuntimeError("priority_launcher_codex_schema_mismatch")
        if not allowed:
            reason = (
                "HOL Guard blocked a destructive command before execution."
                if launcher.event == "PreToolUse"
                else "HOL Guard blocked this output because it contains sensitive content."
            )
            if launcher.event == "PreToolUse":
                if specific.get("permissionDecisionReason") != reason:
                    raise RuntimeError("priority_launcher_pre_reason_mismatch")
            elif (
                response.get("reason") != reason
                or response.get("stopReason") != reason
                or specific.get("additionalContext") != reason
            ):
                raise RuntimeError("priority_launcher_post_reason_mismatch")
    else:
        if response.get("policy_action") != ("allow" if allowed else "block"):
            raise RuntimeError("priority_launcher_policy_mismatch")
        expected_reason = "native_exact_safe_command" if allowed else "native_destructive_command"
        if launcher.event == "PreToolUse" and response.get("reason_code") != expected_reason:
            raise RuntimeError("priority_launcher_reason_mismatch")
        if launcher.event == "PostToolUse":
            if allowed and "reason_code" in response:
                raise RuntimeError("priority_launcher_unexpected_reason")
            if not allowed and (
                response.get("reason_code") != "output_secret_match" or response.get("model_output_action") != "block"
            ):
                raise RuntimeError("priority_launcher_secret_mismatch")


def observe_priority_launcher(
    session: LauncherSession,
    launcher: RegisteredLauncher,
    *,
    sample: int,
    case: str = "benign",
    stop_event: threading.Event | None = None,
) -> Observation:
    """Time real process startup/stdin/transport/stdout/exit; attribute routes later."""

    environment = dict(os.environ)
    clear_proof_environment(environment)
    environment.update(launcher.environment)
    # A fixture-specific child home is the installed harness context. Do not
    # mutate the parent process's HOME/CODEX_HOME or inherit another user's home.
    environment["HOME"] = str(session.root)
    environment["USERPROFILE"] = str(session.root)
    if launcher.harness == "codex":
        environment["CODEX_HOME"] = str(session.root / ".codex")
    encoded = json.dumps(launcher_payload(launcher.event, sample, case=case), separators=(",", ":"))
    started = time.perf_counter()
    completed = run_isolated_hook_process(
        launcher.argv,
        input_text=encoded,
        cwd=session.workspace,
        environment=environment,
        timeout_seconds=_LAUNCH_TIMEOUT_SECONDS,
        output_limit=_OUTPUT_LIMIT,
        stop_event=stop_event,
    )
    elapsed_ms = (time.perf_counter() - started) * 1_000.0
    if (
        completed.returncode != 0
        or completed.timed_out
        or completed.containment_failed
        or completed.output_limit_exceeded
    ):
        raise RuntimeError("priority_launcher_process_contract_failed")
    try:
        response: object = json.loads(completed.stdout)
    except (ValueError, UnicodeDecodeError) as error:
        raise RuntimeError("priority_launcher_stdout_not_json") from error
    if not isinstance(response, Mapping):
        raise RuntimeError("priority_launcher_stdout_not_object")
    try:
        validate_launcher_stdout(launcher, cast(Mapping[str, object], response), case=case)
    except Exception as error:
        from scripts.native_slo_observation_failure import contextual_failure, verdict_evidence

        raise contextual_failure(error, observed_semantics=verdict_evidence(response)) from error
    return Observation(
        launcher.harness,
        launcher.event,
        "1k" if launcher.event == "PostToolUse" else "small",
        elapsed_ms,
        "pending_batch_validation",
        case == "benign",
        False,
    )


def _route_snapshot(session: LauncherSession, *, expected: int | None = None) -> Mapping[str, int]:
    metrics = session.daemon._server.hook_worker.metrics
    snapshot = metrics.snapshot() if expected is None else wait_for_route_corpus(metrics, expected=expected)
    return route_counts(snapshot)


def _require_native_count(before: Mapping[str, int], after: Mapping[str, int], count: int) -> None:
    deltas = {route: after.get(route, 0) - before.get(route, 0) for route in set(before) | set(after)}
    if {route: number for route, number in deltas.items() if number} != {"native_resident": count}:
        raise RuntimeError("priority_launcher_native_route_mismatch")


def _serial_series(session: LauncherSession, launcher: RegisteredLauncher, count: int, *, offset: int) -> list[float]:
    if registered_launcher(launcher.config_path, launcher.harness, launcher.event) != launcher:
        raise RuntimeError("priority_launcher_registration_changed")
    values: list[float] = []
    before = _route_snapshot(session)
    for index in range(count):
        observation = observe_priority_launcher(session, launcher, sample=offset + index)
        values.append(observation.latency_ms)
    after = _route_snapshot(session, expected=sum(before.values()) + count)
    _require_native_count(before, after, count)
    return values


def _concurrent_series(session: LauncherSession, launcher: RegisteredLauncher, count: int) -> list[float]:
    if registered_launcher(launcher.config_path, launcher.harness, launcher.event) != launcher:
        raise RuntimeError("priority_launcher_registration_changed")
    rounded = ((count + _CONCURRENCY - 1) // _CONCURRENCY) * _CONCURRENCY
    values: list[float] = []
    executor = ThreadPoolExecutor(max_workers=_CONCURRENCY, thread_name_prefix="priority-launcher")
    try:
        for offset in range(0, rounded, _CONCURRENCY):
            barrier = threading.Barrier(_CONCURRENCY + 1)
            stop = threading.Event()

            def launch(sample: int, launch_barrier: threading.Barrier, launch_stop: threading.Event) -> Observation:
                launch_barrier.wait(timeout=_LAUNCH_TIMEOUT_SECONDS)
                return observe_priority_launcher(session, launcher, sample=sample, stop_event=launch_stop)

            before = _route_snapshot(session)
            futures = [
                executor.submit(launch, 1_000_000 + offset + slot, barrier, stop) for slot in range(_CONCURRENCY)
            ]
            try:
                barrier.wait(timeout=_LAUNCH_TIMEOUT_SECONDS)
                observations = [future.result() for future in as_completed(futures, timeout=30.0)]
            except BaseException:
                stop.set()
                barrier.abort()
                for future in futures:
                    future.cancel()
                raise
            after = _route_snapshot(session, expected=sum(before.values()) + len(observations))
            attributed, routes = validate_batch_routes(observations, before, after)
            if routes != {"native_resident": _CONCURRENCY}:
                raise RuntimeError("priority_launcher_concurrent_route_mismatch")
            values.extend(observation.latency_ms for observation in attributed)
    except BaseException:
        executor.shutdown(wait=False, cancel_futures=True)
        raise
    else:
        executor.shutdown(wait=True)
    return values


def _sample_count(plan: Mapping[str, int], key: str) -> int:
    value = plan.get(key)
    if type(value) is not int or not 1 <= value <= _MAX_SAMPLES_PER_SERIES:
        raise ValueError("priority_launcher_sample_count_invalid")
    return value


def measure_priority_launchers(
    session: LauncherSession, plan: Mapping[str, int]
) -> tuple[dict[str, object], dict[str, list[float]]]:
    """Measure four actual registrations at c1, c16 and fresh-launcher startup.

    ``cold_per_run=20`` across five qualification blocks gives 100 fresh launcher
    processes per route. The resident remains prepared; these samples do not
    claim cold resident/bootstrap or cold OS file-cache latency.
    """

    priority_count = _sample_count(plan, "priority_per_run")
    cold_count = _sample_count(plan, "cold_per_run")
    launchers = install_priority_launchers(session)
    raw: dict[str, list[float]] = {}
    reports: list[dict[str, object]] = []
    for launcher in launchers:
        # Installation can publish a new config generation. The caller's
        # prepared policy must remain current; a fallback in this preflight
        # fails the route oracle rather than being included in warm samples.
        before = _route_snapshot(session)
        for case in ("benign", "block"):
            observe_priority_launcher(session, launcher, sample=-1, case=case)
        after = _route_snapshot(session, expected=sum(before.values()) + 2)
        _require_native_count(before, after, 2)
        name = f"{launcher.harness}.{launcher.event}"
        cold = _serial_series(session, launcher, cold_count, offset=2_000_000)
        serial = _serial_series(session, launcher, priority_count, offset=0)
        concurrent = _concurrent_series(session, launcher, priority_count)
        if registered_launcher(launcher.config_path, launcher.harness, launcher.event) != launcher:
            raise RuntimeError("priority_launcher_registration_changed")
        raw[f"INSTALLED_LAUNCHER.{name}"] = serial
        raw[f"INSTALLED_LAUNCHER.c16.{name}"] = concurrent
        raw[f"INSTALLED_LAUNCHER.cold.{name}"] = cold
        reports.append(
            {
                "harness": launcher.harness,
                "event": launcher.event,
                "registration_sha256": launcher.registration_sha256,
                "configuration": "registered_argv_and_env",
                "cases_validated": ["benign", "block"],
                "serial": summarize(serial),
                "c16": summarize(concurrent),
                "cold_launcher": summarize(cold),
                "route_attribution": "isolated_batch_counter_conservation",
            }
        )
    return {
        "boundary": "INSTALLED_LAUNCHER",
        "routes": reports,
        "contracts_passed": True,
        "process_startup_included": True,
        "stdout_and_exit_checked": True,
        "cold_state": "fresh_launcher_process_resident_prepared",
        "resident_cold_measured": False,
        "concurrency": [1, _CONCURRENCY],
        "policy_fixture": "explicit_allow_acknowledged",
        "qualification_complete": False,
    }, raw


__all__ = [
    "LauncherSession",
    "RegisteredLauncher",
    "install_priority_launchers",
    "launcher_payload",
    "measure_priority_launchers",
    "observe_priority_launcher",
    "registered_launcher",
    "validate_launcher_stdout",
]
