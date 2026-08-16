from __future__ import annotations

import importlib.util
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Protocol, cast

import pytest

from codex_plugin_scanner.guard.daemon.runtime_hook_scheduler import RuntimeHookScheduler
from tests.guard_daemon_acceptance_fixtures import (
    WorkloadSpec,
    assert_adversarial_nodeids_resolve,
    load_correctness_workloads,
    load_soak_workload,
    run_workload,
)


def _fixture_id(workload: WorkloadSpec) -> str:
    return workload["id"]


def test_adversarial_workload_nodeids_resolve() -> None:
    assert_adversarial_nodeids_resolve()


@pytest.mark.parametrize("workload", load_correctness_workloads(), ids=_fixture_id)
def test_packaged_correctness_workloads(workload: WorkloadSpec, tmp_path: Path) -> None:
    result = run_workload(workload, root=tmp_path)
    expected_secrets = sum(
        (client["requests"] + workload["secret_stride"] - 1) // workload["secret_stride"]
        for client in workload["clients"]
    )
    assert result.requests in {240, 480, 960}
    assert result.secrets_denied == expected_secrets
    assert result.secrets_denied >= result.requests * 0.10
    assert result.routine_allowed + result.secrets_denied == result.requests
    assert result.capacity_denials == 0
    assert result.generic_failures == 0
    assert result.pid_stable
    assert result.workers_stable
    assert result.queue_bounded
    assert result.rss_growth_bytes < 128 * 1024 * 1024
    # Codex requests add an authenticated challenge round trip in the mixed-harness profile.
    p95_limit_ms = 1_000 if workload["id"] == "mixed-harness-fairness" else 750
    assert result.p95_ms < p95_limit_ms
    assert result.p99_ms < 2_500
    assert result.browser_launches == 0
    assert result.inbox_requests == 0
    if len(result.dispatch_counts) == 4:
        shares = [count / result.requests for count in result.dispatch_counts.values()]
        assert max(shares) - min(shares) <= 0.10


def test_twice_capacity_overload_is_typed_bounded_and_recovers() -> None:
    scheduler = RuntimeHookScheduler(
        active_limit=0,
        queued_limit=8,
        per_harness_queued_limit=8,
        per_client_queued_limit=8,
        retained_bytes_limit=128,
    )
    deadline = time.monotonic() + 2
    with ThreadPoolExecutor(max_workers=8) as executor:
        queued = [
            executor.submit(
                scheduler.acquire,
                harness="pi",
                client_key=f"client-{index}",
                lane="decision",
                payload_bytes=16,
                deadline=deadline,
            )
            for index in range(8)
        ]
        wait_deadline = time.monotonic() + 5
        while scheduler.stats()["queued"] != 8:
            assert time.monotonic() < wait_deadline, "queued admissions never reached capacity"
            time.sleep(0.001)
        rejected = [
            scheduler.acquire(
                harness="pi",
                client_key=f"overload-{index}",
                lane="decision",
                payload_bytes=16,
                deadline=deadline,
            )
            for index in range(8)
        ]
        assert {item.reason_code for item in rejected} == {"daemon_hook_queue_capacity"}
        stats = scheduler.stats()
        assert stats["queued"] == stats["queued_limit"]
        assert stats["retained_bytes"] == stats["retained_bytes_limit"]
        scheduler.set_active_limit(8)
        admitted = [future.result(timeout=1) for future in queued]
    for item in admitted:
        assert item.permit is not None
        item.permit.release()
    recovered = scheduler.acquire(
        harness="pi",
        client_key="recovered",
        lane="decision",
        payload_bytes=8,
        deadline=time.monotonic() + 1,
    )
    assert recovered.permit is not None
    recovered.permit.release()
    assert scheduler.stats()["retained_bytes"] == 0


def test_worker_crash_releases_capacity_and_recovers() -> None:
    scheduler = RuntimeHookScheduler(active_limit=1)
    with pytest.raises(RuntimeError, match="fixture worker crash"):
        admission = scheduler.acquire(
            harness="codex",
            client_key="crashing-worker",
            lane="decision",
            payload_bytes=8,
            deadline=time.monotonic() + 1,
        )
        assert admission.permit is not None
        with admission.permit:
            raise RuntimeError("fixture worker crash")
    recovered = scheduler.acquire(
        harness="codex",
        client_key="replacement-worker",
        lane="decision",
        payload_bytes=8,
        deadline=time.monotonic() + 1,
    )
    assert recovered.permit is not None
    recovered.permit.release()
    assert scheduler.stats()["completed"] == 2


def test_clock_jump_expires_work_without_corrupting_scheduler() -> None:
    clock = {"now": 10.0}
    scheduler = RuntimeHookScheduler(active_limit=0, monotonic=lambda: clock["now"])
    with ThreadPoolExecutor(max_workers=1) as executor:
        waiting = executor.submit(
            scheduler.acquire,
            harness="opencode",
            client_key="clock-jump",
            lane="decision",
            payload_bytes=8,
            deadline=20.0,
        )
        wait_deadline = time.monotonic() + 5
        while scheduler.stats()["queued"] != 1:
            assert time.monotonic() < wait_deadline, "clock-jump admission was never queued"
            time.sleep(0.001)
        clock["now"] = 21.0
        scheduler.set_active_limit(1)
        result = waiting.result(timeout=1)
    assert result.reason_code == "daemon_hook_deadline_exhausted"
    assert scheduler.stats()["queued"] == 0
    assert scheduler.stats()["retained_bytes"] == 0


def test_shutdown_restart_starts_with_clean_capacity() -> None:
    first = RuntimeHookScheduler(active_limit=1)
    admission = first.acquire(
        harness="claude-code",
        client_key="before-restart",
        lane="decision",
        payload_bytes=8,
        deadline=time.monotonic() + 1,
    )
    assert admission.permit is not None
    admission.permit.release()
    assert first.stats()["completed"] == 1

    restarted = RuntimeHookScheduler(active_limit=1)
    assert restarted.stats()["active"] == 0
    assert restarted.stats()["queued"] == 0
    after_restart = restarted.acquire(
        harness="claude-code",
        client_key="after-restart",
        lane="decision",
        payload_bytes=8,
        deadline=time.monotonic() + 1,
    )
    assert after_restart.permit is not None
    after_restart.permit.release()
    assert restarted.stats()["completed"] == 1


def test_sqlite_lock_is_bounded_and_recovers(tmp_path: Path) -> None:
    database = tmp_path / "acceptance.sqlite"
    owner = sqlite3.connect(database, timeout=1, check_same_thread=False)
    _ = owner.execute("create table fixture(value integer)")
    _ = owner.execute("begin exclusive")
    started = threading.Event()

    def contend() -> str:
        started.set()
        connection = sqlite3.connect(database, timeout=0.5)
        try:
            _ = connection.execute("insert into fixture values (1)")
            connection.commit()
            return "committed"
        finally:
            connection.close()

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(contend)
        assert started.wait(timeout=1)
        time.sleep(0.25)
        owner.commit()
        assert future.result(timeout=1) == "committed"
    assert owner.execute("select count(*) from fixture").fetchone() == (1,)
    owner.close()


def test_aggregate_report_drops_sensitive_and_unbounded_fields() -> None:
    module = _load_report_module()
    payload: dict[str, object] = {
        "package_version": "2.2.0a1",
        "git_sha": "a" * 40,
        "profile": "correctness",
        "passed": True,
        "results": [
            {
                "fixture_id": "pi-240-24",
                "requests": 240,
                "secrets_denied": 24,
                "command": "do not persist",
                "workspace": "/private/path",
                "raw_payload": {"token": "do not persist"},
            }
        ],
    }
    report = module.sanitize_report(payload)
    serialized = repr(report)
    assert report["schema_version"] == 1
    assert "pi-240-24" in serialized
    assert "command" not in serialized
    assert "workspace" not in serialized
    assert "token" not in serialized


@pytest.mark.slow
@pytest.mark.soak
def test_opt_in_soak_profile_is_separate_from_correctness(tmp_path: Path) -> None:
    # The release runner replaces this bounded smoke duration with the manifest's
    # 1,800-second duration; marking it slow keeps it out of routine PR checks.
    workload = load_soak_workload()
    result = run_workload(workload, root=tmp_path)
    assert result.generic_failures == 0
    assert result.pid_stable
    assert result.workers_stable


class _ReportModule(Protocol):
    def sanitize_report(self, payload: dict[str, object]) -> dict[str, object]: ...


def _load_report_module() -> _ReportModule:
    path = Path(__file__).parents[1] / "scripts" / "generate_guard_daemon_acceptance_report.py"
    spec = importlib.util.spec_from_file_location("guard_daemon_acceptance_report", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return cast(_ReportModule, cast(object, module))
