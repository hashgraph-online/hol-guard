from __future__ import annotations

import importlib.util
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Protocol, cast

import pytest

from tests.coverage_ci import under_coverage_scale
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
@pytest.mark.usefixtures("native_hook_force")
def test_packaged_correctness_workloads(
    workload: WorkloadSpec,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    native_hook_force: Path,
    pytestconfig: pytest.Config,
) -> None:
    # Coverage tracing inflates every request round trip; scale the transport
    # admission deadline and the latency SLA budgets so the workload verdicts
    # (deny/allow/fairness) stay the assertion target, not tracer overhead.
    coverage_scale = under_coverage_scale(3.0)
    result = run_workload(workload, root=tmp_path)
    reporter = pytestconfig.pluginmanager.get_plugin("terminalreporter")
    if reporter is not None:
        # Passing runs hide their latency; keep the headroom visible in CI logs.
        reporter.write_line(f"\nworkload {workload['id']}: p95_ms={result.p95_ms:.1f} p99_ms={result.p99_ms:.1f}")
    expected_secrets = sum(
        (client["requests"] + workload["secret_stride"] - 1) // workload["secret_stride"]
        for client in workload["clients"]
    )
    assert result.requests in {240, 480, 960}
    assert result.secrets_denied == expected_secrets
    assert result.secrets_denied >= result.requests * 0.10
    assert result.routine_allowed + result.secrets_denied == result.requests, result.failure_reasons
    assert result.capacity_denials == 0
    assert result.generic_failures == 0
    assert result.pid_stable
    assert result.workers_stable
    assert result.queue_bounded
    assert result.rss_growth_bytes < 128 * 1024 * 1024
    # Codex requests add an authenticated challenge round trip in the mixed-harness profile.
    # The bound also absorbs real native review latency: this test previously
    # ran the stub fail-safe surface, and real evaluation plus the challenge
    # round trip lands near 1.1s on scheduling-sensitive runners.
    p95_limit_ms = (1_500 if workload["id"] == "mixed-harness-fairness" else 750) * coverage_scale
    assert result.p95_ms < p95_limit_ms
    assert result.p99_ms < 2_500 * coverage_scale
    assert result.browser_launches == 0
    assert result.inbox_requests == 0
    if len(result.dispatch_counts) == 4:
        shares = [count / result.requests for count in result.dispatch_counts.values()]
        assert max(shares) - min(shares) <= 0.10


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
