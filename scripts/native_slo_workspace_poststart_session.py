"""Own one disposable home across two explicitly contained Linux service instances.

This diagnostic uses installed product APIs. It never changes HOME, publisher
deadlines, service capacity or native authority selection. Initial construction
and compilation precede the observer and cannot provide startup SLO evidence.
"""

from __future__ import annotations

import copy
import os
import shutil
import stat
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from scripts.native_slo_command_fixture import prepare_empty_command_authority
from scripts.native_slo_contract import MAX_READINESS_P95_MS
from scripts.native_slo_expiry import _authenticated_readback, _readback_matches
from scripts.native_slo_failure import failure_evidence
from scripts.native_slo_mixed_witness import writer_drained
from scripts.native_slo_session import stop_native_resident
from scripts.native_slo_workloads import configuration_text
from scripts.native_slo_workspace_observer import public_binding

COUNTS = (1, 10, 100)
MAX_RETAINED_THREADS = 512


def diagnostic_failure(error: BaseException) -> dict[str, object]:
    if isinstance(error, Exception):
        return failure_evidence(error)
    return {"type": type(error).__name__, "base_exception": True}


def private_identity(path: Path) -> dict[str, int]:
    info = path.lstat()
    assert path.resolve(strict=True) == path and not path.is_symlink()
    assert stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
    assert stat.S_IMODE(info.st_mode) == 0o700
    return {"device": info.st_dev, "inode": info.st_ino, "uid": info.st_uid, "mode": stat.S_IMODE(info.st_mode)}


def thread_owners(daemon: Any, publisher: Any) -> list[tuple[str, Any]]:
    server = daemon._server
    result = [("service", daemon), ("http", server), ("publisher", publisher)]
    for label, owner, name in (
        ("writer", server, "runtime_hook_evidence_writer"),
        ("runner", server, "hook_process_runner"),
        ("heartbeat", server, "runtime_heartbeat"),
        ("attention", server, "approval_attention"),
        ("general", server, "general_request_executor"),
        ("control", server, "control_request_executor"),
        ("diagnostics", daemon, "_diagnostics"),
        ("command_queue", daemon, "_command_queue_worker"),
        ("cloud_review", daemon, "_cloud_review_sync_worker"),
    ):
        value = getattr(owner, name, None)
        if value is not None:
            result.append((label, value))
    return result


def retain_threads(owners: list[tuple[str, Any]], previous: dict[int, tuple[str, threading.Thread]]) -> None:
    for label, owner in owners:
        if label == "runner":
            with owner._state_lock:
                attributes = {
                    name: tuple(value) if isinstance(value, (tuple, list, set, frozenset)) else value
                    for name, value in vars(owner).items()
                }
        else:
            attributes = vars(owner).copy()
        for attribute, value in attributes.items():
            values = value if isinstance(value, (tuple, list, set, frozenset)) else (value,)
            for item in tuple(values):
                if isinstance(item, threading.Thread):
                    previous.setdefault(id(item), (label + "." + attribute, item))
                    if len(previous) > MAX_RETAINED_THREADS:
                        raise RuntimeError("owned thread observation exceeded the fixed bound")


class PersistentWorkspaceHome:
    """Keep one private root until every constructed service is contained."""

    def __init__(self, runtime: Path, count: int) -> None:
        from codex_plugin_scanner.guard.native_runtime import native_runtime_status

        if sys.platform != "linux" or type(count) is not int or count not in COUNTS:
            raise ValueError("poststart fixture requires a declared Linux workspace count")
        status = native_runtime_status()
        if (
            status.mode != "auto"
            or not status.available
            or not status.compatible
            or status.reason != "native_ready"
            or status.identity is None
            or status.identity.path.resolve(strict=True) != runtime.resolve(strict=True)
        ):
            raise RuntimeError("poststart fixture requires the actual installed native authority")
        self.runtime = runtime.resolve(strict=True)
        self.root = Path(tempfile.mkdtemp(prefix="hol-guard-workspace-poststart-")).resolve(strict=True)
        self.guard_home = self.root / ".hol-guard"
        self.guard_home.mkdir(mode=0o700)
        self.workspaces = tuple(self.root / ("workspace-" + str(index)) for index in range(count))
        for workspace in self.workspaces:
            workspace.mkdir(mode=0o700)
        assert self.root.parent == Path(tempfile.gettempdir()).resolve(strict=True)
        assert not self.root.is_relative_to(Path.home().resolve(strict=True))
        self.root_identity = private_identity(self.root)
        self.guard_identity = private_identity(self.guard_home)
        (self.guard_home / "config.toml").write_text(configuration_text("normal"), encoding="utf-8")
        self.instances: list[PostStartService] = []
        self.construction_failed = False
        self.construction_stage = "not_offered"
        self.construction_failure: dict[str, object] | None = None
        self.removed = False
        self.command_authority_prepared = False

    def start_instance(self) -> PostStartService:
        if self.removed or self.construction_failed or len(self.instances) >= 2:
            raise RuntimeError("same-home service construction is no longer admitted")
        if self.instances and self.instances[-1].retirement.get("passed") is not True:
            raise RuntimeError("previous same-home service retirement is not verified")
        assert private_identity(self.root) == self.root_identity
        assert private_identity(self.guard_home) == self.guard_identity
        try:
            instance = PostStartService(self)
        except BaseException as error:
            self.construction_failed = True
            self.construction_failure = {
                "stage": self.construction_stage,
                "failure": diagnostic_failure(error),
                "partial_service_containment_unproven": self.construction_stage == "service",
            }
            raise
        self.instances.append(instance)
        if len(self.instances) == 2 and instance.publisher is self.instances[0].publisher:
            raise RuntimeError("replacement reused the previous publisher object")
        return instance

    def finish(self) -> dict[str, object]:
        if self.instances and not self.instances[-1].stop_called:
            self.instances[-1].stop()
        contained = not self.construction_failed and all(
            instance.retirement.get("passed") is True for instance in self.instances
        )
        result: dict[str, object] = {
            "contained": contained,
            "constructed_instances": len(self.instances),
            "construction_failure": self.construction_failure,
            "same_root_identity_preserved": private_identity(self.root) == self.root_identity,
            "same_guard_home_identity_preserved": private_identity(self.guard_home) == self.guard_identity,
            "instance_retirements": [instance.retirement for instance in self.instances],
            "root_removed": False,
            "qualification_complete": False,
        }
        if contained:
            shutil.rmtree(self.root)
            self.removed = True
            result["root_removed"] = True
        return result


class PostStartService:
    """One real service, with one explicit stop and retained first failures."""

    def __init__(self, owner: PersistentWorkspaceHome) -> None:
        from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
        from codex_plugin_scanner.guard.store import GuardStore

        self.owner = owner
        self.root, self.guard_home, self.runtime = owner.root, owner.guard_home, owner.runtime
        self.workspaces = owner.workspaces
        self.workspace = self.workspaces[-1]
        self.stop_called = False
        self.retirement: dict[str, object] = {"passed": False, "status": "not_stopped"}
        self.construction_stage = owner.construction_stage = "store"
        self.store = GuardStore(self.guard_home)
        if not owner.command_authority_prepared:
            prepare_empty_command_authority(self.store)
            owner.command_authority_prepared = True
        self.construction_stage = owner.construction_stage = "service"
        self.daemon = GuardDaemonServer(self.store, host="127.0.0.1", port=0, home_dir=self.root)
        self.worker = self.daemon._server.hook_worker
        self.publisher = self.worker.policy_snapshot_publisher
        self.threads: dict[int, tuple[str, threading.Thread]] = {}
        self.owned_processes: dict[int, Any] = {}
        self.ready_report: dict[str, object] = {}
        self.construction_stage = owner.construction_stage = "constructed"

    def ready(self) -> dict[str, object]:
        self.daemon.start()
        if self.worker.test_oracle is not None:
            raise RuntimeError("poststart fixture refuses a Python decision oracle")
        deadline = time.monotonic() + MAX_READINESS_P95_MS / 1000
        while True:
            prepared = self.worker.prepare_workspace_policy(None, deadline=deadline)
            snapshot = self.publisher.current_snapshot()
            binding, accepted = _authenticated_readback(self.store)
            if (
                prepared is not None
                and snapshot is not None
                and public_binding(prepared) == public_binding(snapshot)
                and _readback_matches(binding, accepted, snapshot)
                and self.daemon._owned_service_ready is True
                and self.publisher.is_ready()
                and time.monotonic() <= deadline
            ):
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("poststart global readiness deadline")
            time.sleep(0.005)
        with self.publisher._condition:
            registered = tuple(self.publisher._workspace_paths)
        if registered:
            raise RuntimeError("workspaces were already registered before poststart observation")
        if self.publisher._thread is None or not self.publisher._thread.is_alive():
            raise RuntimeError("ready publisher does not have its actual running thread")
        self.ready_report = {
            "global_ready": True,
            "owned_service_ready": True,
            "registered_before_explicit_admission": 0,
            "publisher_thread_already_running": True,
            "initial_construction_and_compilation_observed": False,
            "startup_slo_credit": False,
            "initial_binding": public_binding(snapshot),
            "readiness_gate_ms": MAX_READINESS_P95_MS,
            "qualification_complete": False,
        }
        self.retain_owned_work()
        return dict(self.ready_report)

    def retain_owned_work(self) -> None:
        retain_threads(thread_owners(self.daemon, self.publisher), self.threads)
        runner = self.daemon._server.hook_process_runner
        with runner._state_lock:
            for slot in runner._all_slots.values():
                self.owned_processes.setdefault(id(slot.process), slot.process)
        if len(self.owned_processes) > 128:
            raise RuntimeError("owned worker process observation exceeded its fixed bound")

    def drain(self) -> dict[str, object]:
        writer = self.daemon._server.runtime_hook_evidence_writer
        deadline = time.monotonic() + 5.0
        while True:
            with writer._condition:
                stats = {**writer.stats(), "in_flight": writer._in_flight}
            if writer_drained(stats):
                self.retain_owned_work()
                return stats
            if time.monotonic() >= deadline:
                raise RuntimeError("original bounded writer drain deadline")
            time.sleep(0.025)

    def stop(self) -> dict[str, object]:
        if self.stop_called:
            return dict(self.retirement)
        self.stop_called = True
        errors, native_stops, failures = [], [], []
        try:
            self.retain_owned_work()
        except BaseException as error:
            errors.append("before_stop_observation:" + type(error).__name__)
            failures.append({"stage": "before_stop_observation", "failure": diagnostic_failure(error)})
        for stage in ("before_service_stop", "after_service_stop"):
            try:
                native = stop_native_resident(self.runtime, self.guard_home, write_diagnostic=False)
                native_stops.append(
                    {
                        "stage": stage,
                        "contained": bool(native),
                        "diagnostic": copy.deepcopy(native.diagnostic),
                    }
                )
                if not native:
                    errors.append(stage + ":native_containment_failed")
            except BaseException as error:
                native_stops.append(
                    {
                        "stage": stage,
                        "contained": False,
                        "error_type": type(error).__name__,
                        "failure": diagnostic_failure(error),
                    }
                )
                errors.append(stage + ":" + type(error).__name__)
            if stage == "before_service_stop":
                try:
                    self.daemon.stop()
                except BaseException as error:
                    errors.append("service_stop:" + type(error).__name__)
                    failures.append({"stage": "service_stop", "failure": diagnostic_failure(error)})
        try:
            self.retain_owned_work()
        except BaseException as error:
            errors.append("after_stop_observation:" + type(error).__name__)
            failures.append({"stage": "after_stop_observation", "failure": diagnostic_failure(error)})
        try:
            self.retirement = self.retirement_snapshot(errors, native_stops, failures)
        except BaseException as error:
            errors.append("retirement_observation:" + type(error).__name__)
            failures.append({"stage": "retirement_observation", "failure": diagnostic_failure(error)})
            self.retirement = {
                "passed": False,
                "status": "observation_incomplete",
                "explicit_service_stop_calls": 1,
                "native_stop_observations": native_stops,
                "errors": errors,
                "failures": failures,
                "qualification_complete": False,
            }
        return dict(self.retirement)

    def retirement_snapshot(
        self,
        errors: list[str],
        native_stops: list[dict[str, object]],
        failures: list[dict[str, object]],
    ) -> dict[str, object]:
        server, runner = self.daemon._server, self.daemon._server.hook_process_runner
        writer = server.runtime_hook_evidence_writer
        with runner._state_lock:
            runner_state = {
                "closed": runner._closed,
                "started": runner._started,
                "slots": len(runner._all_slots),
                "spawn_threads": len(runner._spawn_threads),
                "retirement_threads": len(runner._retirement_threads),
                "active_reviews": len(runner._active_reviews),
                "supervisor_alive": runner._supervisor_thread is not None and runner._supervisor_thread.is_alive(),
            }
        thread_rows = [{"owner_field": label, "alive": thread.is_alive()} for label, thread in self.threads.values()]
        process_rows: list[dict[str, object]] = []
        for process in self.owned_processes.values():
            pid, returncode = process.pid, process.exitcode
            process_rows.append({"pid": pid, "returncode": returncode, "reaped": returncode is not None})
        checks = {
            "service_finish_completed": self.daemon._finish_service_completed is True,
            "service_not_quarantined": self.daemon._is_quarantined() is False,
            "service_not_ready": self.daemon._owned_service_ready is False,
            "serve_thread_cleared": self.daemon._thread is None,
            "owner_lock_released": self.daemon._owner_lock is None,
            "publisher_closed": self.publisher.closed is True,
            "publisher_thread_retired": self.publisher._thread is None or not self.publisher._thread.is_alive(),
            "writer_thread_retired": not writer._thread.is_alive(),
            "request_executors_stopped": server.request_executors_stopped is True,
            "no_active_hook_requests": server.active_hook_requests == 0,
            "retained_threads_retired": all(row["alive"] is False for row in thread_rows),
            "retained_direct_workers_reaped": all(row["reaped"] is True for row in process_rows),
            "runner_closed_and_empty": runner_state
            == {
                "closed": True,
                "started": False,
                "slots": 0,
                "spawn_threads": 0,
                "retirement_threads": 0,
                "active_reviews": 0,
                "supervisor_alive": False,
            },
            "same_root_preserved": private_identity(self.root) == self.owner.root_identity,
            "same_guard_home_preserved": private_identity(self.guard_home) == self.owner.guard_identity,
        }
        return {
            "passed": not errors and all(checks.values()),
            "status": "observed",
            "explicit_service_stop_calls": 1,
            "native_stop_observations": native_stops,
            "errors": errors,
            "failures": failures,
            "checks": checks,
            "runner": runner_state,
            "last_native_stop_contained": native_stops[-1]["contained"] is True,
            "retained_threads": thread_rows,
            "retained_direct_workers": process_rows,
            "scope": (
                "Actual service state, owned registries and every retained object; "
                "not a complete escaped-descendant census."
            ),
            "qualification_complete": False,
        }
