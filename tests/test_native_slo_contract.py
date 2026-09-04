from __future__ import annotations

import json
import os
import re
from pathlib import Path
from types import SimpleNamespace
from typing import TypedDict, cast

import pytest

from codex_plugin_scanner.guard.runtime.hook_review_engine import HOOK_ENGINE_NORMAL_BUDGET_MS
from scripts.bench_guard_native_installed_slo import (
    _safe_failure_rate,
    _stabilize_ready_hook_workers,
)
from scripts.native_slo_adapter import Observation, payload, process_resources, route_matrix, source_payloads
from scripts.native_slo_contract import (
    MAX_EVIDENCE_BYTES,
    MAX_INSTALLED_ADAPTER_P95_MS,
    MAX_INSTALLED_ADAPTER_P99_MS,
    SIZE_CLASSES,
    all_gates_pass,
    assert_privacy_safe,
    clear_proof_environment,
    gate_results,
    percentile,
    proof_environment_violations,
    sanitize_aggregate,
    summarize,
)
from scripts.native_slo_reporting import SloMeasurements, slo_gates, summarize_measurements
from scripts.native_slo_session import AdapterSession, _is_explicit_capacity_response


class _ConcurrencyGateKwargs(TypedDict):
    resident_share: float
    safe_fail_rate: float
    warm_p95_ms: float
    size_p95_ms: dict[str, float]
    cold_p95_ms: float
    readiness_p95_ms: float
    concurrent_p99_ms: float
    rss_growth: float
    rss_baseline_bytes: int
    python_fallback_decisions: int


class _PythonSemanticGateKwargs(TypedDict):
    resident_share: float
    safe_fail_rate: float
    warm_p95_ms: float
    size_p95_ms: dict[str, float]
    cold_p95_ms: float
    readiness_p95_ms: float
    concurrent_p99_ms: float
    rss_growth: float
    rss_baseline_bytes: int
    errors: int
    errors_64: int
    python_fallback_decisions: int


def test_percentiles_use_deterministic_nearest_rank() -> None:
    samples = [1.0, 2.0, 3.0, 4.0]
    assert percentile(samples, 0.5) == 2.0
    assert percentile(samples, 0.95) == 4.0
    assert summarize(samples) == {
        "count": 4,
        "p50_ms": 2.5,
        "p95_ms": 4.0,
        "p99_ms": 4.0,
        "max_ms": 4.0,
    }


def test_sanitizer_drops_payload_bearing_fields_and_bounds_collections() -> None:
    value = {
        "schema": "aggregate",
        "command": "printf private",
        "nested": {"raw_payload": {"token": "private"}, "count": 3},
        "items": list(range(300)),
    }
    sanitized = sanitize_aggregate(value)
    assert sanitized == {
        "schema": "aggregate",
        "nested": {"count": 3},
        "items": list(range(256)),
    }


def test_sanitizer_handles_camel_case_fields_and_redacts_free_form_values() -> None:
    sanitized = sanitize_aggregate(
        {
            "rawPayload": "private",
            "safe_label": "contains spaces and a path /Users/private",
            "safe_secret": "secret:abc",
            "schema": "hol-guard.native-installed-slo.v1",
        }
    )
    assert sanitized == {
        "safe_label": "redacted",
        "schema": "hol-guard.native-installed-slo.v1",
    }


def test_privacy_contract_bounds_unbounded_evidence() -> None:
    report = assert_privacy_safe({"safe": "x" * (MAX_EVIDENCE_BYTES + 1)})
    assert len(json.dumps(report).encode("utf-8")) < MAX_EVIDENCE_BYTES


def test_privacy_contract_returns_json_safe_aggregate() -> None:
    report = assert_privacy_safe(
        {
            "schema": "hol-guard.native-installed-slo.v1",
            "size_classes": {size: {"count": 1, "p95_ms": 1.0} for size in SIZE_CLASSES},
            "routes": {"native_resident": 4},
        }
    )
    assert json.loads(json.dumps(report)) == report


def test_slo_gates_are_fixed_and_require_all_measurements() -> None:
    passing = gate_results(
        resident_share=1.0,
        safe_fail_rate=0.0,
        warm_p95_ms=20.0,
        size_p95_ms={"250k": 50.0, "1m": 120.0, "5m": 350.0},
        cold_p95_ms=100.0,
        readiness_p95_ms=250.0,
        concurrent_p99_ms=100.0,
        rss_growth=0.10,
        rss_baseline_bytes=1,
        errors=0,
        errors_64=0,
        python_fallback_decisions=0,
    )
    assert all_gates_pass(passing)
    failing = gate_results(
        resident_share=0.98,
        safe_fail_rate=0.01,
        warm_p95_ms=MAX_INSTALLED_ADAPTER_P95_MS + 0.1,
        size_p95_ms={},
        cold_p95_ms=100.1,
        readiness_p95_ms=250.1,
        concurrent_p99_ms=MAX_INSTALLED_ADAPTER_P99_MS + 0.1,
        rss_growth=0.11,
        rss_baseline_bytes=1,
        errors=1,
        errors_64=1,
        python_fallback_decisions=1,
    )
    assert not all_gates_pass(failing)
    assert all(not result for result in failing.values())
    noisy = gate_results(
        resident_share=1.0,
        safe_fail_rate=0.0,
        warm_p95_ms=20.0,
        size_p95_ms={"250k": 50.0, "1m": 120.0, "5m": 350.0},
        cold_p95_ms=100.0,
        readiness_p95_ms=250.0,
        concurrent_p99_ms=100.0,
        rss_growth=0.101827,
        rss_baseline_bytes=1,
        errors=0,
        errors_64=0,
        python_fallback_decisions=0,
    )
    assert noisy["rss"] is True
    assert gate_results(
        resident_share=1.0,
        safe_fail_rate=0.0,
        warm_p95_ms=20.0,
        size_p95_ms={"250k": 50.0, "1m": 120.0, "5m": 350.0},
        cold_p95_ms=100.0,
        readiness_p95_ms=250.0,
        concurrent_p99_ms=100.0,
        rss_growth=0.11,
        rss_baseline_bytes=1,
        errors=0,
        errors_64=0,
        python_fallback_decisions=0,
    )["rss"] is False


def test_installed_latency_budget_is_the_existing_normal_hook_budget() -> None:
    assert float(HOOK_ENGINE_NORMAL_BUDGET_MS) == MAX_INSTALLED_ADAPTER_P95_MS
    assert MAX_INSTALLED_ADAPTER_P99_MS == MAX_INSTALLED_ADAPTER_P95_MS
    passing = gate_results(
        resident_share=1.0,
        safe_fail_rate=0.0,
        warm_p95_ms=MAX_INSTALLED_ADAPTER_P95_MS,
        size_p95_ms={
            "250k": MAX_INSTALLED_ADAPTER_P95_MS,
            "1m": MAX_INSTALLED_ADAPTER_P95_MS,
            "5m": MAX_INSTALLED_ADAPTER_P95_MS,
        },
        cold_p95_ms=100.0,
        readiness_p95_ms=250.0,
        concurrent_p99_ms=MAX_INSTALLED_ADAPTER_P99_MS,
        rss_growth=0.10,
        rss_baseline_bytes=1,
        errors=0,
        errors_64=0,
        python_fallback_decisions=0,
    )
    assert passing["warm_latency"]
    assert passing["250k_latency"]
    assert passing["1m_latency"]
    assert passing["5m_latency"]
    assert passing["concurrency"]


def test_safe_failure_rate_counts_only_native_fail_safe_routes() -> None:
    observations = (
        Observation("codex", "PostToolUse", "1k", 1.0, "native_resident", True),
        Observation("codex", "PostToolUse", "5m", 1.0, "native_resident", False),
        Observation("codex", "PostToolUse", "1k", 1.0, "native_fail_safe", False),
    )

    assert _safe_failure_rate(observations) == pytest.approx(1 / 3)


def test_overloaded_fail_safe_is_reported_as_bounded_security_denial() -> None:
    measurements = SloMeasurements(
        warm=[Observation("codex", "PostToolUse", "1k", 1.0, "native_resident", True)],
        sizes=[],
        recovery=[],
        cold=[],
        concurrent_16=[Observation("codex", "PostToolUse", "1k", 1.0, "native_resident", True)],
        concurrent_64=[Observation("codex", "PostToolUse", "1k", 1.0, "native_fail_safe", False, overloaded=True)],
        errors_16=0,
        errors_64=0,
        readiness=[],
        rss_baseline=1,
        rss_peak=1,
    )

    summary = summarize_measurements(measurements)

    assert summary.safe_failures == 0
    assert summary.security_denials == 1
    assert dict(summary.security_denials_by_size) == {"1k": 1}


def test_summary_separates_expected_denials_from_warm_fail_safe_gate() -> None:
    measurements = SloMeasurements(
        warm=[Observation("codex", "PostToolUse", "1k", 1.0, "native_resident", True)],
        sizes=[Observation("codex", "PostToolUse", "5m", 1.0, "native_resident", False)],
        recovery=[],
        cold=[],
        concurrent_16=[Observation("codex", "PostToolUse", "1k", 1.0, "native_fail_safe", False)],
        concurrent_64=[Observation("codex", "PostToolUse", "1k", 1.0, "native_fail_safe", False)],
        errors_16=0,
        errors_64=0,
        readiness=[],
        rss_baseline=1,
        rss_peak=1,
    )

    summary = summarize_measurements(measurements)

    assert summary.safe_failure_rate == 0.0
    assert summary.safe_failures == 2
    assert dict(summary.safe_failures_by_size) == {"1k": 2}
    assert summary.security_denials == 1
    assert dict(summary.security_denials_by_size) == {"5m": 1}


def test_proof_environment_clears_native_diagnostic_oracle_and_test_overrides() -> None:
    environment = {
        "HOL_GUARD_NATIVE_ORACLE": "1",
        "HOL_GUARD_HOOK_FAST_PATH_SHADOW": "1",
        "HOL_GUARD_TEST_CUSTOM": "1",
        "HOL_GUARD_RUN_SYSTEM_KEYCHAIN_TEST": "1",
        "GUARD_DIAGNOSTIC_MODE": "1",
        "PYTEST_ADDOPTS": "-q",
        "PYTHONPATH": "src",
        "UNRELATED_SETTING": "preserve",
    }
    removed = clear_proof_environment(environment)
    assert set(removed) == {
        "HOL_GUARD_NATIVE_ORACLE",
        "HOL_GUARD_HOOK_FAST_PATH_SHADOW",
        "HOL_GUARD_TEST_CUSTOM",
        "HOL_GUARD_RUN_SYSTEM_KEYCHAIN_TEST",
        "GUARD_DIAGNOSTIC_MODE",
        "PYTEST_ADDOPTS",
        "PYTHONPATH",
    }
    assert proof_environment_violations(environment) == ()
    assert environment == {"UNRELATED_SETTING": "preserve"}


def test_concurrency_gate_only_applies_error_and_deadline_to_sixteen() -> None:
    kwargs: _ConcurrencyGateKwargs = {
        "resident_share": 1.0,
        "safe_fail_rate": 0.0,
        "warm_p95_ms": 20.0,
        "size_p95_ms": {"250k": 50.0, "1m": 120.0, "5m": 350.0},
        "cold_p95_ms": 100.0,
        "readiness_p95_ms": 250.0,
        "concurrent_p99_ms": 100.0,
        "rss_growth": 0.10,
        "rss_baseline_bytes": 1,
        "python_fallback_decisions": 0,
    }
    assert gate_results(errors=0, errors_64=0, **kwargs)["concurrency"]
    assert not gate_results(errors=1, errors_64=0, **kwargs)["concurrency"]
    assert gate_results(errors=0, errors_64=1, **kwargs)["concurrency"]


def test_sixty_four_gate_accepts_explicit_overload_without_latency_ceiling() -> None:
    measurements = SloMeasurements(
        warm=[Observation("codex", "PostToolUse", "1k", 1.0, "native_resident", True)],
        sizes=[],
        recovery=[],
        cold=[],
        concurrent_16=[Observation("codex", "PostToolUse", "1k", 1.0, "native_resident", True)],
        concurrent_64=[Observation("codex", "PostToolUse", "1k", 60_000.0, "native_fail_safe", False, overloaded=True)],
        errors_16=0,
        errors_64=0,
        readiness=[],
        rss_baseline=1,
        rss_peak=1,
    )
    summary = summarize_measurements(measurements)
    gates = slo_gates(
        measurements,
        summary,
        {
            "routes": 1,
            "resident": 1,
            "oneshot": 0,
            "fail_safe": 0,
            "python_semantic_decisions": 0,
        },
        1,
        include_capacity=True,
    )

    assert summary.concurrent_64_overloads == 1
    assert gates["concurrency"]
    assert gates["concurrency_64_bounded"]


def test_sixty_four_gate_rejects_unclassified_fail_safe() -> None:
    measurements = SloMeasurements(
        warm=[Observation("codex", "PostToolUse", "1k", 1.0, "native_resident", True)],
        sizes=[],
        recovery=[],
        cold=[],
        concurrent_16=[Observation("codex", "PostToolUse", "1k", 1.0, "native_resident", True)],
        concurrent_64=[Observation("codex", "PostToolUse", "1k", 1.0, "native_fail_safe", False)],
        errors_16=0,
        errors_64=0,
        readiness=[],
        rss_baseline=1,
        rss_peak=1,
    )
    summary = summarize_measurements(measurements)
    gates = slo_gates(
        measurements,
        summary,
        {"routes": 1, "resident": 1, "oneshot": 0, "fail_safe": 0, "python_semantic_decisions": 0},
        1,
        include_capacity=True,
    )

    assert not gates["concurrency_64_bounded"]


def test_capacity_classifier_accepts_only_explicit_daemon_or_native_overload() -> None:
    assert _is_explicit_capacity_response({"reason_code": "daemon_capacity"})
    assert _is_explicit_capacity_response({"reason_code": "native_overloaded"})
    assert not _is_explicit_capacity_response({"reason_code": "native_fail_safe"})
    assert not _is_explicit_capacity_response({"reason_code": "policy_denied"})


def test_python_semantic_gate_includes_installed_corpus_count() -> None:
    kwargs: _PythonSemanticGateKwargs = {
        "resident_share": 1.0,
        "safe_fail_rate": 0.0,
        "warm_p95_ms": 20.0,
        "size_p95_ms": {"250k": 50.0, "1m": 120.0, "5m": 350.0},
        "cold_p95_ms": 100.0,
        "readiness_p95_ms": 250.0,
        "concurrent_p99_ms": 100.0,
        "rss_growth": 0.10,
        "rss_baseline_bytes": 1,
        "errors": 0,
        "errors_64": 0,
        "python_fallback_decisions": 0,
    }
    assert gate_results(installed_python_fallback_decisions=0, **kwargs)["python_fallback"]
    assert not gate_results(installed_python_fallback_decisions=1, **kwargs)["python_fallback"]


@pytest.mark.skipif(os.name == "nt", reason="process resource measurement is not implemented on Windows")
def test_rss_measurement_is_current_and_requires_ten_percent_bound() -> None:
    resources = process_resources()
    assert resources is not None
    assert resources.rss_bytes > 0
    assert resources.threads > 0
    assert resources.file_descriptors > 0
    passing = gate_results(
        resident_share=1.0,
        safe_fail_rate=0.0,
        warm_p95_ms=20.0,
        size_p95_ms={"250k": 50.0, "1m": 120.0, "5m": 350.0},
        cold_p95_ms=100.0,
        readiness_p95_ms=250.0,
        concurrent_p99_ms=100.0,
        rss_growth=0.10,
        rss_baseline_bytes=resources.rss_bytes,
        errors=0,
        errors_64=0,
        python_fallback_decisions=0,
    )
    assert passing["rss"]
    assert not gate_results(
        resident_share=1.0,
        safe_fail_rate=0.0,
        warm_p95_ms=20.0,
        size_p95_ms={"250k": 50.0, "1m": 120.0, "5m": 350.0},
        cold_p95_ms=100.0,
        readiness_p95_ms=250.0,
        concurrent_p99_ms=100.0,
        rss_growth=0.11,
        rss_baseline_bytes=resources.rss_bytes,
        errors=0,
        errors_64=0,
        python_fallback_decisions=0,
    )["rss"]


def test_worker_stabilization_forces_and_verifies_ready_target() -> None:
    events: list[tuple[str, object]] = []

    class FakeRunner:
        def notify_queued_work(self) -> None:
            events.append(("notify", None))

        def enable_full_capacity(self, *, delay_seconds: float, active_deferral_seconds: float) -> None:
            events.append(("enable", (delay_seconds, active_deferral_seconds)))

        def wait_for_capacity(self, *, minimum_workers: int, timeout_seconds: float) -> bool:
            events.append(("wait", (minimum_workers, timeout_seconds)))
            return True

        def stats(self) -> dict[str, object]:
            return {"target": 4, "workers": 4, "ready": 4, "busy": 0}

    def fake_session() -> object:
        return SimpleNamespace(daemon=SimpleNamespace(_server=SimpleNamespace(hook_process_runner=FakeRunner())))

    session = cast(AdapterSession, fake_session())

    assert _stabilize_ready_hook_workers(session) == 4
    assert events == [
        ("notify", None),
        ("enable", (0.0, 0.0)),
        ("wait", (4, 30.0)),
    ]


def test_installed_adapter_corpus_covers_all_declared_routes_and_sizes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    routes = route_matrix()
    assert len(routes) == 21
    assert len({harness for harness, _ in routes}) == 13
    assert {event for _, event in routes} == {"PreToolUse", "PostToolUse"}
    for size_class in SIZE_CLASSES:
        encoded = json.dumps(payload("PostToolUse", size_class), separators=(",", ":"))
        assert (
            len(encoded.encode("utf-8")) >= {"1k": 1_000, "250k": 250_000, "1m": 1_000_000, "5m": 5_000_000}[size_class]
        )


def test_large_classes_use_bounded_local_source_references(tmp_path: Path) -> None:
    fixtures = source_payloads(tmp_path)
    for size_class, expected_bytes in (("250k", 250 * 1024), ("1m", 1 * 1024 * 1024), ("5m", 5 * 1024 * 1024)):
        fixture = fixtures[size_class]
        reference = fixture["guard_source_ref"]
        assert isinstance(reference, dict)
        assert Path(str(reference["path"])).stat().st_size == expected_bytes
        assert reference["version"] == 1
        assert reference["output_chars"] == expected_bytes
        assert "tool_response" not in fixture


def test_installed_proof_and_soak_contract_are_wired_without_force_defaults() -> None:
    workflow = Path(".github/workflows/native-wheel-ci.yml").read_text(encoding="utf-8")
    documentation = Path("docs/guard/native-runtime-slo-proof.md").read_text(encoding="utf-8").lower()
    assert "--enforce" in workflow
    assert "--requests 100000" in workflow
    assert "--receipts 250000" in workflow
    assert "--enforce-soak" in workflow
    assert "native-installed-slo.json" in workflow
    assert "native-soak.json" in workflow
    assert re.search(r"\bforce\b", documentation) is None
    assert "installed_wheel_ownership_contract" in Path("scripts/bench_guard_native_installed_slo.py").read_text(
        encoding="utf-8"
    )
