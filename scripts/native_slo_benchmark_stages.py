"""Lifecycle stages used by the installed native-runtime SLO benchmark."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping
from contextlib import nullcontext
from pathlib import Path

from scripts.bench_guard_native_installed_slo_runtime import _require
from scripts.native_slo_adapter import Observation, payload
from scripts.native_slo_contract import SAFE_ROUTE_NAMES
from scripts.native_slo_preflight import preflight_operation
from scripts.native_slo_progress import SloProgress
from scripts.native_slo_session import AdapterSession


def _observe_with_progress(
    progress: SloProgress,
    session: AdapterSession,
    harness: str,
    event: str,
    size_class: str,
    stage: str,
    request_payload: Mapping[str, object] | None = None,
    *,
    fatal: bool = True,
    record_attempt: bool = True,
    record_submission: bool = True,
    complete: bool = True,
) -> Observation:
    progress.activate(stage, harness=harness, event=event, size_class=size_class)
    if record_attempt:
        if record_submission:
            progress.submit(stage)
        progress.attempt(stage)
    try:
        observation = session.observe(harness, event, size_class, request_payload)
    except Exception as error:
        progress.fail_request(stage)
        if fatal:
            progress.record_failure(
                error,
                stage=stage,
                labels={"harness": harness, "event": event, "size_class": size_class},
            )
        raise
    progress.record_observation(stage, observation)
    if complete:
        progress.complete(stage)
    return observation


def _wire_request(workspace: Path, guard_home: Path, request_id: str) -> str:
    return json.dumps(
        {
            "protocol_version": 1,
            "request_id": request_id,
            "harness": "claude-code",
            "event_name": "PostToolUse",
            "payload": payload("PostToolUse", "1k"),
            "guard_remaining_ms": 1_000,
            "cwd": str(workspace),
            "home_dir": str(workspace),
            "guard_home": str(guard_home),
            "source_ref_external_allowed": False,
            "observe_mode": False,
            "deadline_budget_ms": 5_000,
        },
        separators=(",", ":"),
    )


def _run_cold(
    runtime: Path,
    session: AdapterSession,
    iterations: int,
    *,
    progress: SloProgress | None = None,
) -> list[float]:
    values: list[float] = []
    environment = {
        "HOME": str(session.workspace),
        "TMPDIR": tempfile.gettempdir(),
        **{key: value for key in ("LANG", "LC_ALL") if (value := os.environ.get(key))},
    }
    request = _wire_request(session.workspace, session.guard_home, "native-slo-cold")
    for _ in range(iterations):
        if progress is not None:
            progress.activate("cold", size_class="1k")
            progress.submit("cold")
            progress.attempt("cold")
        try:
            _require(session.stop_resident(), "cold native resident stop was not contained")
            started = time.perf_counter()
            completed = subprocess.run(
                (str(runtime), "hook", "--stdin"),
                input=request.encode("utf-8"),
                cwd=runtime.parent,
                env=environment,
                capture_output=True,
                check=False,
                timeout=5,
            )
            elapsed_ms = (time.perf_counter() - started) * 1_000.0
            _require(completed.returncode == 0, "cold native one-shot failed")
            try:
                response = json.loads(completed.stdout)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise RuntimeError("cold native one-shot returned invalid JSON") from error
            _require(isinstance(response, Mapping) and response.get("decision") == "allow", "cold decision was unsafe")
            values.append(elapsed_ms)
        except Exception as error:
            if progress is not None:
                progress.fail_request("cold")
                progress.record_failure(error, stage="cold", labels={"size_class": "1k"})
            raise
        else:
            if progress is not None:
                progress.record_timing("cold", None, elapsed_ms)
                progress.complete("cold")
    return values


def _run_recovery(
    session: AdapterSession,
    iterations: int,
    *,
    progress: SloProgress | None = None,
    adapter_values: list[float] | None = None,
    enclosing_values: list[float] | None = None,
) -> list[float]:
    values: list[float] = []
    for index in range(iterations):
        precondition_pending = progress is not None
        observation_pending = False
        precondition_returned = False
        observation_returned = False
        failure_stage = "recovery_precondition"
        try:
            warm = (
                session.observe("claude-code", "PostToolUse", "1k")
                if progress is None
                else _observe_with_progress(
                    progress,
                    session,
                    "claude-code",
                    "PostToolUse",
                    "1k",
                    "recovery_precondition",
                    complete=False,
                )
            )
            precondition_returned = True
            _require(
                warm.allowed and warm.route == "native_resident",
                f"recovery sample {index} was not resident before stop",
            )
            if progress is not None:
                progress.complete("recovery_precondition")
                precondition_pending = False
                progress.activate("recovery", harness="claude-code", event="PostToolUse", size_class="1k")
            failure_stage = "recovery_stop"
            with preflight_operation(progress, "recovery_stop") if progress is not None else nullcontext():
                _require(
                    session.stop_resident(preserve_clients=True),
                    f"resident stop failed during recovery sample {index}",
                )
            started = time.perf_counter()
            failure_stage = "recovery"
            observation = (
                session.observe("claude-code", "PostToolUse", "1k")
                if progress is None
                else _observe_with_progress(
                    progress,
                    session,
                    "claude-code",
                    "PostToolUse",
                    "1k",
                    "recovery",
                    complete=False,
                )
            )
            observation_returned = True
            observation_pending = progress is not None
            elapsed_ms = (time.perf_counter() - started) * 1_000.0
            values.append(elapsed_ms)
            if adapter_values is not None:
                adapter_values.append(observation.latency_ms)
            if enclosing_values is not None:
                enclosing_values.append(elapsed_ms)
            print(
                json.dumps(
                    {
                        "schema": "hol-guard.native-recovery-sample.v1",
                        "sample": index,
                        "adapter_ms": round(observation.latency_ms, 3),
                        "elapsed_ms": round(elapsed_ms, 3),
                        "route": observation.route if observation.route in SAFE_ROUTE_NAMES else "unknown",
                        "allowed": observation.allowed,
                    },
                    sort_keys=True,
                ),
                file=sys.stderr,
                flush=True,
            )
            _require(observation.allowed and observation.route == "native_resident", f"recovery sample {index} failed")
            if progress is not None:
                progress.record_timing("recovery", None, elapsed_ms)
                progress.complete("recovery")
                observation_pending = False
        except Exception as error:
            if progress is not None:
                if precondition_pending and precondition_returned:
                    progress.fail_request("recovery_precondition")
                if observation_pending and observation_returned:
                    progress.fail_request("recovery")
                progress.record_failure(error, stage=failure_stage)
            raise
    return values


def _run_serialized_warmup(
    session: AdapterSession,
    harness: str,
    event: str,
    *,
    progress: SloProgress | None = None,
) -> None:
    observation = (
        session.observe(harness, event, "1k")
        if progress is None
        else _observe_with_progress(progress, session, harness, event, "1k", "serialized_warmup", complete=False)
    )
    passed = observation.allowed and observation.route == "native_resident"
    if not passed:
        from codex_plugin_scanner.guard.native_approval_errors import NATIVE_COMMAND_CONTROL_ERROR_CODES

        publisher = session.daemon._server.hook_worker.policy_snapshot_publisher
        error = publisher.last_error
        reasons = NATIVE_COMMAND_CONTROL_ERROR_CODES | {
            "native_policy_snapshot_resident_changed",
            "native_policy_snapshot_expired",
            "native_policy_snapshot_runtime_unavailable",
            "native_policy_snapshot_publish_failed",
            "native_policy_snapshot_native_disabled",
            "native_policy_snapshot_protocol_unsupported",
        }
        binding = publisher.current_snapshot_binding()
        generation = binding.get("generation") if isinstance(binding, dict) else None
        print(
            json.dumps(
                {
                    "schema": "hol-guard.native-serialized-warmup-failure.v1",
                    "route": observation.route if observation.route in SAFE_ROUTE_NAMES else "unknown",
                    "allowed": observation.allowed,
                    "adapter_ms": round(observation.latency_ms, 3),
                    "publisher_error": error if error in reasons else None,
                    "publisher_ready": binding is not None,
                    "policy_generation": generation if type(generation) is int and 0 <= generation < 2**64 else None,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
            flush=True,
        )
    try:
        _require(passed, "serialized resident pool warmup did not stay on the allowed native route")
    except Exception as error:
        if progress is not None:
            progress.fail_request("serialized_warmup")
            progress.record_failure(error, stage="serialized_warmup", labels={"harness": harness, "event": event})
        raise
    else:
        if progress is not None:
            progress.complete("serialized_warmup")


__all__ = [
    "_observe_with_progress",
    "_run_cold",
    "_run_recovery",
    "_run_serialized_warmup",
    "_wire_request",
]
