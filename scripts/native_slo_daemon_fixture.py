"""Private subprocess fixture for daemon-only resource and startup measurements.

The fixture runs production AdapterSession in an installed interpreter. Only a
bounded private control pipe crosses into the load generator. Hook requests
still cross the production authenticated HTTP adapter, never that control pipe.
"""

from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import threading
import time
from collections.abc import Mapping
from contextlib import suppress
from http.client import HTTPConnection
from pathlib import Path
from types import SimpleNamespace
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.append(str(_ROOT))

from codex_plugin_scanner.guard.codex_hook_launch_runtime import _kill_hook_process, _spawn_hook_process  # noqa: E402
from codex_plugin_scanner.guard.codex_hook_windows_job import close_windows_hook_job  # noqa: E402
from scripts.native_probe_receipts import wait_for_route_corpus  # noqa: E402
from scripts.native_slo_adapter import Observation, is_allowed, payload, route_counts  # noqa: E402
from scripts.native_slo_contract import assert_privacy_safe, clear_proof_environment  # noqa: E402
from scripts.native_slo_failure import FixtureFailureError, failure_evidence  # noqa: E402
from scripts.native_slo_observation_failure import retain_failed_recovery_observation  # noqa: E402
from scripts.native_slo_session import _is_explicit_capacity_response, _request  # noqa: E402
from scripts.native_slo_startup import PROGRESS_STAGES, StartupDiagnostic  # noqa: E402

_CONTROL_LIMIT = 256 * 1024


def witnessed_route(before: Mapping[str, int], after: Mapping[str, int], *, expected: int = 1) -> str:
    """Require exact counter conservation; an engine bypass is its own outcome."""
    delta = {name: after.get(name, 0) - before.get(name, 0) for name in set(before) | set(after)}
    if any(value < 0 for value in delta.values()):
        raise RuntimeError("qualification route counters regressed")
    changed = {name: value for name, value in delta.items() if value}
    if not changed:
        return "engine_bypassed"
    if len(changed) != 1 or sum(changed.values()) != expected:
        raise RuntimeError("qualification route accounting was ambiguous")
    return next(iter(changed))


class _RemoteMetrics:
    def __init__(self, session: DaemonFixture) -> None:
        self.session = session

    def snapshot(self) -> Mapping[str, object]:
        return self.session.control("snapshot")


class DaemonFixture:
    """Daemon/helper/resident tree independent of the benchmark load generator."""

    def __init__(self, runtime: Path, *, setup: str | None = None, policy: str | None = None) -> None:
        self.runtime = runtime
        self.setup = setup
        self.policy = policy
        self.process: subprocess.Popen[bytes] | None = None
        self._job: Any = None
        self._lock = threading.Lock()
        self._responses: queue.Queue[bytes | None] = queue.Queue(maxsize=1)
        self._readers: list[threading.Thread] = []
        self._connection: HTTPConnection | None = None
        self._owner_thread_id = 0
        self._closed = False
        self.startup_ms = 0.0
        self.readiness_ms = 0.0
        self._stage = "spawn"
        self._startup_stack: list[object] = []

    @property
    def pid(self) -> int:
        if self.process is None:
            raise RuntimeError("daemon fixture not started")
        return self.process.pid

    def _read_stdout(self) -> None:
        assert self.process is not None and self.process.stdout is not None
        while True:
            value = self.process.stdout.readline(_CONTROL_LIMIT + 1)
            if not value or len(value) > _CONTROL_LIMIT:
                with suppress(queue.Full):
                    self._responses.put_nowait(None)
                return
            try:
                self._responses.put(value, timeout=1.0)
            except queue.Full:
                return

    def _drain_stderr(self) -> None:
        assert self.process is not None and self.process.stderr is not None
        while self.process.stderr.read(4096):
            pass  # Never publish raw fixture diagnostics or retain unbounded bytes.

    def _receive(self, timeout: float) -> Mapping[str, object]:
        deadline = time.monotonic() + timeout
        while True:
            try:
                line = self._responses.get(timeout=max(0, deadline - time.monotonic()))
            except queue.Empty as error:
                if self._startup_stack:
                    detail = failure_evidence(RuntimeError("daemon fixture deadline at " + self._stage))
                    detail["startup_stack"] = self._startup_stack
                    raise FixtureFailureError(detail) from error
                raise RuntimeError("daemon fixture deadline at " + self._stage) from error
            if line is None:
                raise RuntimeError("daemon fixture stream unavailable at " + self._stage)
            result = json.loads(line)
            if not isinstance(result, Mapping):
                raise RuntimeError("daemon fixture operation failed")
            if result.get("state") in {"progress", "startup_diagnostic"}:
                stage = result.get("stage")
                if stage not in PROGRESS_STAGES:
                    raise RuntimeError("daemon fixture invalid progress stage")
                self._stage = str(stage)
                if result.get("state") == "startup_diagnostic":
                    stack = result.get("stack")
                    if (
                        not isinstance(stack, list)
                        or len(stack) > 8
                        or any(
                            not isinstance(item, dict)
                            or set(item) != {"origin", "line"}
                            or not isinstance(item["origin"], str)
                            or not isinstance(item["line"], int)
                            or isinstance(item["line"], bool)
                            for item in stack
                        )
                    ):
                        raise RuntimeError("daemon fixture invalid startup evidence")
                    assert_privacy_safe({"stack": stack})
                    self._startup_stack = list(stack)
                continue  # Progress cannot extend the fixed operation deadline.
            if result.get("error"):
                detail = result.get("detail")
                if not isinstance(detail, Mapping):
                    raise RuntimeError("daemon fixture invalid failure evidence")
                raise FixtureFailureError(detail)
            return result

    def control(self, operation: str, **arguments: object) -> Mapping[str, object]:
        with self._lock:
            if self.process is None or self.process.stdin is None:
                raise RuntimeError("daemon fixture unavailable")
            request = json.dumps({"op": operation, **arguments}, separators=(",", ":")).encode() + b"\n"
            if len(request) > 4096:
                raise ValueError("daemon fixture control request exceeded bound")
            self.process.stdin.write(request)
            self.process.stdin.flush()
            return self._receive(30.0)

    def __enter__(self) -> DaemonFixture:
        environment = dict(os.environ)
        clear_proof_environment(environment)
        started = time.perf_counter()
        self.process, self._job, _ = _spawn_hook_process(
            (
                sys.executable,
                "-u",
                str(Path(__file__).resolve()),
                "--serve",
                str(self.runtime),
                self.setup or "none",
                self.policy or "none",
            ),
            cwd=_ROOT,
            environment=environment,
            allow_windows_breakaway=False,
            windows_kill_on_job_close=True,
            parent_liveness=False,
        )
        for target in (self._read_stdout, self._drain_stderr):
            thread = threading.Thread(target=target, daemon=True)
            thread.start()
            self._readers.append(thread)
        try:
            ready = self._receive(30.0)
            if ready.get("state") != "ready":
                raise RuntimeError("daemon fixture did not acknowledge readiness")
            self.root = Path(str(ready["root"]))
            self.workspace = Path(str(ready["workspace"]))
            self.guard_home = Path(str(ready["guard_home"]))
            self.readiness_ms = float(ready["readiness_ms"])
            self.daemon = SimpleNamespace(
                port=int(ready["port"]),
                _server=SimpleNamespace(
                    auth_token=str(ready["auth_token"]),
                    hook_worker=SimpleNamespace(metrics=_RemoteMetrics(self)),
                ),
            )
            self._connection = HTTPConnection("127.0.0.1", self.daemon.port, timeout=5)
            self._owner_thread_id = threading.get_ident()
            self.startup_ms = (time.perf_counter() - started) * 1000
        except BaseException:
            self.close()
            raise
        return self

    def request(self, harness: str, request_payload: Mapping[str, object]) -> tuple[Mapping[str, object], float]:
        started = time.perf_counter()
        response = _request(
            self.daemon,
            guard_home=self.guard_home,
            workspace=self.workspace,
            harness=harness,
            request_payload=request_payload,
            connection=self._connection if threading.get_ident() == self._owner_thread_id else None,
        )
        return response, (time.perf_counter() - started) * 1000

    def observe(
        self, harness: str, event: str, size_class: str, request_payload: Mapping[str, object] | None = None
    ) -> Observation:
        metrics = self.daemon._server.hook_worker.metrics
        before = route_counts(metrics.snapshot())
        response, latency = self.request(
            harness, request_payload if request_payload is not None else payload(event, size_class)
        )
        after = route_counts(wait_for_route_corpus(metrics, expected=sum(before.values()) + 1))
        observation = Observation(
            harness,
            event,
            size_class,
            latency,
            witnessed_route(before, after),
            is_allowed(event, response),
            _is_explicit_capacity_response(response),
        )
        retain_failed_recovery_observation(observation, response, before, after)
        return observation

    def observe_unattributed(self, harness: str, event: str, size_class: str) -> Observation:
        response, latency = self.request(harness, payload(event, size_class))
        return Observation(
            harness,
            event,
            size_class,
            latency,
            "pending_batch_validation",
            is_allowed(event, response),
            _is_explicit_capacity_response(response),
        )

    def stop_resident(self) -> bool:
        return self.control("stop_resident").get("contained") is True

    def native_overload_count(self) -> int:
        return int(self.control("native_overloads")["count"])

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._connection is not None:
            self._connection.close()
        if self.process is None:
            return
        acknowledged = False
        try:
            if self.process.poll() is None:
                acknowledged = self.control("close").get("closed") is True
                self.process.wait(timeout=5)
        except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired):
            pass
        finally:
            contained = _kill_hook_process(self.process, self._job)
            with suppress(subprocess.TimeoutExpired):
                self.process.wait(timeout=5)
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                if stream is not None:
                    stream.close()
            for thread in self._readers:
                thread.join(timeout=1.0)
            if self._job is not None:
                close_windows_hook_job(self._job)
                self._job = None
        if not contained or self.process.poll() is None:
            raise RuntimeError("daemon fixture process containment failed")
        if not acknowledged and self.startup_ms:
            raise RuntimeError("daemon fixture cleanup was not acknowledged")

    def __exit__(self, *_args: object) -> None:
        self.close()


def _emit(result: Mapping[str, object]) -> None:
    encoded = json.dumps(result, separators=(",", ":")).encode() + b"\n"
    if len(encoded) > _CONTROL_LIMIT:
        raise RuntimeError("daemon fixture response exceeded bound")
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()


def _native_samples(session: Any, count: int) -> dict[str, object]:
    from codex_plugin_scanner.guard.native_hook_edge import review_raw_hook_native
    from scripts.native_benchmark_oracle import synthetic_payload, validate_semantic_response

    if not 1 <= count <= 100:
        raise ValueError("native sample batch outside bound")
    values: list[float] = []
    for index in range(-2, count):
        case = "secret" if index == -1 else "benign"
        snapshot = session.daemon._server.hook_worker.prepare_workspace_policy(
            session.workspace, deadline=time.monotonic() + 0.4
        )
        if snapshot is None:
            raise RuntimeError("native timing policy was not acknowledged")
        request = synthetic_payload(index, case=case)
        started = time.perf_counter()
        edge = review_raw_hook_native(
            payload=request,
            harness="claude-code",
            event="PostToolUse",
            guard_home=session.guard_home,
            home_dir=session.root,
            cwd=session.workspace,
            source_ref_external_allowed=False,
            observe_mode=False,
            deadline=time.monotonic() + 5,
            policy_snapshot=snapshot,
        )
        elapsed = (time.perf_counter() - started) * 1000
        if not isinstance(edge, Mapping) or edge.get("authority") != "rust":
            raise RuntimeError("native timing did not return Rust authority")
        validate_semantic_response(
            edge.get("result"), route="native_resident", expected_route="native_resident", case=case
        )
        if index >= 0:
            values.append(elapsed)
    return {"values": values, "benign_and_block_validated": True}


def _serve(runtime: Path, setup: str = "none", policy: str = "none") -> int:
    from contextlib import ExitStack, nullcontext

    from scripts.native_slo_faults import FaultFixture
    from scripts.native_slo_session import AdapterSession

    configuration = None
    if setup != "none" or policy != "none":
        from scripts.native_slo_workloads import configuration_text

        configuration = configuration_text(setup if setup != "none" else policy)
    with ExitStack() as lifetime:
        with StartupDiagnostic(_emit) as diagnostic:
            diagnostic.progress("construct")
            adapter = AdapterSession(runtime, configuration=configuration, progress=diagnostic.progress)
            diagnostic.progress("start")
            session = lifetime.enter_context(adapter)
        _emit({"state": "progress", "stage": "fault"})
        fault_context = FaultFixture(session, setup) if setup != "none" else nullcontext()
        with fault_context as fault:
            _serve_session(session, fault)
    _emit({"closed": True})
    return 0


def _serve_session(session: Any, fault: Any) -> None:
    from scripts.native_slo_launcher_review import LauncherReviewFixture
    from scripts.native_slo_mixed_server import MixedScenarioFixture
    from scripts.native_slo_phases import PhaseProfiler

    profiler: PhaseProfiler | None = None
    mixed = MixedScenarioFixture(session)
    launcher_review = LauncherReviewFixture(session)
    posture: Any = None
    try:
        _emit(
            {
                "state": "ready",
                "root": str(session.root),
                "workspace": str(session.workspace),
                "guard_home": str(session.guard_home),
                "port": session.daemon.port,
                "auth_token": session.daemon._server.auth_token,
                "readiness_ms": session.readiness_ms,
            }
        )
        while True:
            raw = sys.stdin.buffer.readline(4097)
            if not raw or len(raw) > 4096:
                break
            request = json.loads(raw)
            operation = request.get("op")
            if operation == "snapshot":
                # Only the bounded route counters are required by this fixture.
                _emit({"routes": dict(route_counts(session.daemon._server.hook_worker.metrics.snapshot()))})
            elif operation == "case_before" and fault is not None:
                fault.before_case()
                _emit({"reset": True})
            elif operation == "case_result" and fault is not None:
                _emit(fault.result())
            elif operation == "native_samples":
                _emit(_native_samples(session, int(request["count"])))
            elif operation == "stop_resident":
                _emit({"contained": session.stop_resident()})
            elif operation == "native_overloads":
                _emit({"count": session.native_overload_count()})
            elif operation == "phases_start" and profiler is None:
                profiler = PhaseProfiler()
                profiler.__enter__()
                _emit({"started": True})
            elif operation == "phases_finish" and profiler is not None:
                profiler.__exit__(None, None, None)
                _emit(profiler.report())
                profiler = None
            elif isinstance(operation, str) and operation.startswith("mixed_"):
                _emit(mixed.dispatch(operation, request))
            elif isinstance(operation, str) and operation.startswith("launcher_approval_"):
                _emit(launcher_review.dispatch(operation, request))
            elif isinstance(operation, str) and operation.startswith("posture_"):
                if posture is None:
                    from scripts.native_slo_posture_server import PostureScenarioFixture

                    posture = PostureScenarioFixture(session)
                _emit(posture.dispatch(operation, request))
            elif operation == "close":
                if profiler is not None:
                    profiler.__exit__(None, None, None)
                break
            else:
                raise RuntimeError("unsupported daemon fixture operation")
    finally:
        try:
            launcher_review.close()
        finally:
            try:
                if posture is not None:
                    posture.close()
            finally:
                mixed.close()
                _emit({"state": "progress", "stage": "cleanup"})


if __name__ == "__main__":
    try:
        if len(sys.argv) != 5 or sys.argv[1] != "--serve":
            raise ValueError("private daemon fixture invocation required")
        raise SystemExit(_serve(Path(sys.argv[2]).resolve(strict=True), sys.argv[3], sys.argv[4]))
    except Exception as error:
        _emit({"error": "fixture_failed", "detail": failure_evidence(error)})
        raise SystemExit(1) from None
