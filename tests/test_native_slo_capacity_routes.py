from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from scripts import native_slo_capacity as capacity
from scripts.native_slo_adapter import Observation
from scripts.native_slo_reporting import SloMeasurements, slo_gates, slo_result, summarize_measurements


def _observation(*, allowed: bool, overloaded: bool = False) -> Observation:
    # This is the misleading per-hook counter span from the real c64 failure.
    return Observation("codex", "PostToolUse", "1k", 2.0, "native_fail_safe", allowed, overloaded)


def _wave(
    monkeypatch,
    observations,
    after,
    *,
    before=None,
    native_overloads=0,
    overloads_before=10,
    errors=0,
    attempted=None,
):
    snapshots = iter((dict(before or {}), dict(after)))
    metrics = SimpleNamespace(snapshot=lambda: {"routes": next(snapshots)})
    overloads = iter((overloads_before, overloads_before + native_overloads))
    session = SimpleNamespace(
        daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=SimpleNamespace(metrics=metrics))),
        native_overload_count=lambda: next(overloads),
    )
    monkeypatch.setattr(capacity, "_run_concurrent", lambda *_args: (observations, errors))
    monkeypatch.setattr(capacity, "wait_for_route_corpus", lambda recorder, **_kwargs: recorder.snapshot())
    return capacity._run_capacity_wave(
        session,
        (("codex", "PostToolUse"),),
        len(observations) + errors if attempted is None else attempted,
        object(),
    )


def _measurements(wave):
    resident = replace(_observation(allowed=True), route="native_resident")
    return SloMeasurements(
        warm=[resident],
        sizes=[],
        recovery=[1.0],
        cold=[1.0],
        concurrent_16=[resident],
        concurrent_64=wave.observations,
        errors_16=0,
        errors_64=wave.errors,
        readiness=[1.0],
        rss_baseline=100,
        rss_peak=100,
        routes_16={"native_resident": 1},
        routes_64=wave.routes,
        native_overloads_16=0,
        native_overloads_64=wave.native_overloads,
    )


_INSTALLED = {"routes": 1, "resident": 1, "oneshot": 0, "fail_safe": 0, "python_semantic_decisions": 0}


def _report(wave):
    measurements = _measurements(wave)
    summary = summarize_measurements(measurements)
    gates = slo_gates(measurements, summary, _INSTALLED, 1, include_capacity=True)
    return summary, gates, slo_result({}, (("codex", "PostToolUse"),), _INSTALLED, measurements, summary, gates)


def test_overlapping_c64_spans_do_not_turn_successful_allows_into_fail_safes(monkeypatch):
    items = [_observation(allowed=True) for _ in range(32)] + [
        _observation(allowed=False, overloaded=True) for _ in range(32)
    ]
    wave = _wave(
        monkeypatch,
        items,
        {"native_resident": 132, "native_fail_safe": 26},
        before={"native_resident": 100, "native_fail_safe": 10},
        native_overloads=16,
    )
    assert wave.routes == {"native_resident": 32, "native_fail_safe": 16, "engine_bypassed": 16}
    assert [item.route for item in wave.observations[:32]] == ["native_resident"] * 32
    assert [item.route for item in wave.observations[32:]] == ["overload_batch_validated"] * 32
    assert sum(item.overloaded for item in wave.observations) == 32
    assert all(item.route == "native_fail_safe" for item in items)  # Input witnesses remain intact.
    summary, gates, report = _report(wave)
    assert summary.safe_failures == 0
    assert summary.security_denials == 32
    assert gates["concurrency_64_bounded"] is True
    assert report["routes"] == {"native_resident": 34, "native_fail_safe": 16, "engine_bypassed": 16}
    sixty_four = report["concurrency"]["sixty_four"]
    assert sixty_four["routes"] == wave.routes
    assert sixty_four["fail_safe"] == sixty_four["native_overloads"] == 16
    assert sixty_four["overloaded"] == 32
    assert sixty_four["route_attribution"] == "isolated_batch_counter_conservation"
    assert "overload_batch_validated" not in report["routes"]


def test_exact_native_health_delta_classifies_only_denied_observations(monkeypatch):
    items = [_observation(allowed=True)] * 32 + [_observation(allowed=False)] * 32
    wave = _wave(monkeypatch, items, {"native_resident": 32, "native_fail_safe": 32}, native_overloads=32)
    assert sum(item.allowed for item in wave.observations) == 32
    assert sum(item.overloaded for item in wave.observations) == 32
    assert all(not item.overloaded for item in wave.observations[:32])
    assert wave.routes == {"native_resident": 32, "native_fail_safe": 32}
    assert _report(wave)[1]["concurrency_64_bounded"] is True


def test_all_explicit_daemon_capacity_keeps_zero_native_decisions(monkeypatch):
    wave = _wave(monkeypatch, [_observation(allowed=False, overloaded=True)] * 64, {})
    assert wave.routes == {"engine_bypassed": 64}
    summary, gates, report = _report(wave)
    assert summary.concurrent_64_routes["native_resident"] == 0
    assert gates["concurrency_64_bounded"] is True
    assert report["concurrency"]["sixty_four"]["fail_safe"] == 0


def test_explicit_overload_cannot_lend_native_health_to_an_unknown_denial(monkeypatch):
    with pytest.raises(RuntimeError, match="unexpected semantic decision"):
        _wave(
            monkeypatch,
            [_observation(allowed=False), _observation(allowed=False, overloaded=True)],
            {"native_fail_safe": 1},
            native_overloads=1,
        )


def test_explicit_capacity_does_not_hide_unaccounted_native_failure(monkeypatch):
    with pytest.raises(RuntimeError, match="native overload route evidence did not match"):
        _wave(monkeypatch, [_observation(allowed=False, overloaded=True)], {"native_fail_safe": 1})


@pytest.mark.parametrize(
    ("after", "native_overloads", "reason"),
    [
        ({"native_resident": 1, "native_fail_safe": 1}, 0, "unexpected semantic decision"),
        ({"native_resident": 2}, 0, "unexpected semantic decision"),
        ({"native_resident": 1, "native_fail_safe": 1}, 2, "unexpected semantic decision"),
        ({"native_resident": 1, "python_semantic": 1}, 1, "left native execution authority"),
        ({"native_resident": 1, "native_oneshot": 1}, 1, "left native execution authority"),
    ],
)
def test_unknown_denial_or_fallback_never_becomes_accepted_capacity(monkeypatch, after, native_overloads, reason):
    with pytest.raises(RuntimeError, match=reason):
        _wave(
            monkeypatch,
            [_observation(allowed=True), _observation(allowed=False)],
            after,
            native_overloads=native_overloads,
        )


@pytest.mark.parametrize("count", [1, 3])
def test_missing_or_extra_resident_decision_fails_wave_conservation(monkeypatch, count):
    with pytest.raises(RuntimeError, match="does not match delivered decisions"):
        _wave(monkeypatch, [_observation(allowed=True)] * 2, {"native_resident": count})


def test_counter_regression_remains_failure(monkeypatch):
    with pytest.raises(RuntimeError, match="counters regressed"):
        _wave(monkeypatch, [_observation(allowed=True)], {"native_resident": 1}, before={"native_resident": 2})


def test_failed_conservation_retains_independent_counts_and_delivery_errors(monkeypatch):
    with pytest.raises(RuntimeError, match="does not match delivered decisions") as raised:
        _wave(
            monkeypatch,
            [_observation(allowed=True)],
            {"native_resident": 42, "native_fail_safe": 3},
            before={"native_resident": 40, "native_fail_safe": 3},
            errors=1,
        )
    detail = raised.value.detail
    assert detail["concurrency"] == 2
    assert detail["routes_before"] == {"native_resident": 40, "native_fail_safe": 3}
    assert detail["routes_after"] == {"native_resident": 42, "native_fail_safe": 3}
    assert detail["delivered_count"] == detail["delivered_allowed"] == detail["transport_errors"] == 1
    assert detail["delivered_overloaded"] == 0
    assert detail["native_overloads_before"] == detail["native_overloads_after"] == 10


@pytest.mark.parametrize("native_overloads", [-1, 2])
def test_invalid_native_overload_delta_remains_failure(monkeypatch, native_overloads):
    with pytest.raises(RuntimeError, match="native overload counters were invalid"):
        _wave(monkeypatch, [_observation(allowed=True)], {"native_resident": 1}, native_overloads=native_overloads)


@pytest.mark.parametrize("value", [True, -1, 1.5])
def test_invalid_initial_route_counter_is_not_silently_normalized(monkeypatch, value):
    with pytest.raises(RuntimeError, match="route counters were invalid"):
        _wave(monkeypatch, [_observation(allowed=True)], {"native_resident": 1}, before={"native_resident": value})


def test_missing_attempt_is_not_hidden_by_matching_delivered_routes(monkeypatch):
    with pytest.raises(RuntimeError, match="accounting was incomplete"):
        _wave(monkeypatch, [_observation(allowed=True)], {"native_resident": 1}, attempted=2)


def test_request_errors_are_retained_and_fail_c64_gate(monkeypatch):
    wave = _wave(monkeypatch, [_observation(allowed=True)], {"native_resident": 1}, errors=1)
    assert wave.errors == 1
    assert _report(wave)[1]["concurrency_64_bounded"] is False
    assert _report(wave)[2]["errors_64"] == 1


def test_allowed_and_overloaded_response_is_rejected(monkeypatch):
    with pytest.raises(RuntimeError, match="both allowed and overloaded"):
        _wave(monkeypatch, [_observation(allowed=True, overloaded=True)], {"native_resident": 1})


@pytest.mark.parametrize("change", ["absent", "extra", "wrong_bypass", "invalid_count", "wrong_native_health"])
def test_report_cannot_claim_batch_routes_without_matching_evidence(monkeypatch, change):
    wave = _wave(
        monkeypatch,
        [_observation(allowed=True), _observation(allowed=False, overloaded=True)],
        {"native_resident": 1},
    )
    measurements = _measurements(wave)
    if change == "absent":
        measurements = replace(measurements, routes_64=None)
    elif change == "extra":
        measurements = replace(measurements, routes_64={"native_resident": 2, "engine_bypassed": 1})
    elif change == "wrong_bypass":
        measurements = replace(measurements, routes_64={"native_resident": 1, "engine_bypassed": 2})
    elif change == "invalid_count":
        measurements = replace(measurements, routes_64={"native_resident": True, "engine_bypassed": 1})
    else:
        measurements = replace(measurements, native_overloads_64=1)
    with pytest.raises(RuntimeError):
        summarize_measurements(measurements)


def test_denied_resident_decision_cannot_pass_benign_capacity_gate():
    wave = capacity.CapacityWave([replace(_observation(allowed=False), route="native_resident")], 0, {}, 0)
    measurements = replace(_measurements(wave), routes_64=None, native_overloads_64=None)
    summary = summarize_measurements(measurements)
    assert slo_gates(measurements, summary, _INSTALLED, 1, include_capacity=True)["concurrency_64_bounded"] is False


@pytest.mark.parametrize("route", ["native_oneshot", "python_semantic"])
def test_overload_flag_does_not_make_a_fallback_route_acceptable(route):
    item = replace(_observation(allowed=False, overloaded=True), route=route)
    wave = capacity.CapacityWave([item], 0, {}, 0)
    measurements = replace(_measurements(wave), routes_64=None, native_overloads_64=None)
    summary = summarize_measurements(measurements)
    assert slo_gates(measurements, summary, _INSTALLED, 1, include_capacity=True)["concurrency_64_bounded"] is False
