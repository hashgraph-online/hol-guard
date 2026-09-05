from __future__ import annotations

import pytest

import scripts.native_slo_adapter as native_slo_adapter
from scripts import native_slo_baseline
from scripts.bench_guard_native_installed_slo import _steady_state_rss_baseline
from scripts.native_slo_contract import assert_privacy_safe


def test_linux_rss_measurement_does_not_fallback_to_root_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root_reads: list[int] = []
    monkeypatch.setattr(native_slo_adapter.sys, "platform", "linux")
    monkeypatch.setattr(native_slo_adapter, "process_tree_rss_bytes", lambda _process_ids: None)
    monkeypatch.setattr(
        native_slo_adapter,
        "_single_process_rss_bytes",
        lambda pid: root_reads.append(pid) or 128 * 1024 * 1024,
    )

    assert native_slo_adapter.process_resources(123) is None
    assert root_reads == []


def test_non_linux_rss_measurement_retains_root_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(native_slo_adapter.sys, "platform", "darwin")
    monkeypatch.setattr(native_slo_adapter, "process_tree_rss_bytes", lambda _process_ids: None)
    monkeypatch.setattr(native_slo_adapter, "_single_process_rss_bytes", lambda _pid: 128 * 1024 * 1024)
    monkeypatch.setattr(native_slo_adapter, "_process_threads", lambda _pid: 2)
    monkeypatch.setattr(native_slo_adapter, "_process_file_descriptors", lambda _pid: 3)

    assert native_slo_adapter.process_resources(123) == native_slo_adapter.ProcessResources(
        rss_bytes=128 * 1024 * 1024,
        threads=2,
        file_descriptors=3,
    )


def test_rss_evidence_remains_aggregate_only() -> None:
    report = assert_privacy_safe(
        {
            "rss": {
                "baseline_bytes": 128 * 1024 * 1024,
                "peak_bytes": 129 * 1024 * 1024,
                "growth": 0.007812,
                "source": "process_tree",
            },
            "route_counts": {"native_resident": 12},
        }
    )

    assert report == {
        "rss": {"baseline_bytes": 128 * 1024 * 1024, "peak_bytes": 129 * 1024 * 1024, "growth": 0.007812},
        "route_counts": {"native_resident": 12},
    }


def _full_capacity(expected: int = 2) -> dict[str, int]:
    return {"target": expected, "workers": expected, "ready": expected, "busy": 0}


def test_rss_baseline_uses_bounded_waves_until_workers_and_rss_plateau() -> None:
    events: list[str] = []
    capacities = iter((_full_capacity(), _full_capacity(), _full_capacity(), _full_capacity()))
    rss_samples = iter((100, 101, 101))

    def run_capacity_wave() -> tuple[list[object], int]:
        events.append("wave")
        return [object(), object()], 0

    def sample_capacity() -> object:
        events.append("capacity")
        return next(capacities)

    def sample_rss() -> int:
        events.append("rss")
        return next(rss_samples)

    baseline = _steady_state_rss_baseline(
        run_capacity_wave,
        sample_capacity=sample_capacity,
        sample_rss=sample_rss,
        expected_warmup_count=2,
        interval_seconds=0.0,
    )

    assert baseline == 101
    assert events == [
        "capacity",
        "wave",
        "capacity",
        "rss",
        "wave",
        "capacity",
        "rss",
        "wave",
        "capacity",
        "rss",
    ]


def test_rss_baseline_fails_closed_when_process_tree_rss_is_unavailable() -> None:
    with pytest.raises(RuntimeError, match="resident RSS sample was unavailable"):
        _steady_state_rss_baseline(
            lambda: ([object(), object()], 0),
            sample_capacity=lambda: _full_capacity(),
            sample_rss=lambda: 0,
            expected_warmup_count=2,
            interval_seconds=0.0,
        )


def test_rss_baseline_fails_closed_when_worker_capacity_changes() -> None:
    capacities = iter((_full_capacity(), {"target": 2, "workers": 1, "ready": 1, "busy": 1}))

    with pytest.raises(RuntimeError, match="worker capacity changed"):
        _steady_state_rss_baseline(
            lambda: ([object(), object()], 0),
            sample_capacity=lambda: next(capacities),
            sample_rss=lambda: 100,
            expected_warmup_count=2,
            interval_seconds=0.0,
        )


def test_rss_baseline_fails_closed_when_plateau_deadline_expires(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = iter((0.0, 0.2, 0.4, 0.6, 0.8))
    monkeypatch.setattr(native_slo_baseline.time, "monotonic", lambda: next(clock))

    with pytest.raises(RuntimeError, match="RSS did not reach a bounded plateau"):
        _steady_state_rss_baseline(
            lambda: ([object(), object()], 0),
            sample_capacity=lambda: _full_capacity(),
            sample_rss=lambda: 100,
            expected_warmup_count=2,
            timeout_seconds=0.5,
            interval_seconds=0.0,
        )
