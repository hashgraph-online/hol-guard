from __future__ import annotations

import json
import threading
from collections import Counter
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from codex_plugin_scanner.guard.daemon.hook_metrics import HookMetricsRecorder
from scripts import native_slo_capacity as capacity
from scripts import native_slo_session as session_module
from scripts.native_slo_adapter import Observation
from scripts.native_slo_session import AdapterSession


def _mixed_observations() -> list[Observation]:
    # Concurrent per-request windows can each see both route counters advance.
    return [Observation("codex", "PreToolUse", "1k", 1.0, "native_fail_safe", True) for _ in range(32)] + [
        Observation("pi", "PreToolUse", "1k", 1.0, "native_fail_safe", False, overloaded=True) for _ in range(32)
    ]


def test_mixed_wave_requires_exact_counter_proof_for_every_response() -> None:
    observations = _mixed_observations()
    before = Counter({"native_resident": 100, "native_fail_safe": 3})
    after = before + Counter({"native_resident": 32, "native_fail_safe": 32})

    reconciled = capacity._reconcile_wave_routes(observations, errors=0, before=before, after=after)

    assert len(reconciled) == 64
    assert Counter(item.route for item in reconciled) == {"native_resident": 32, "native_fail_safe": 32}
    assert sum(item.overloaded for item in reconciled) == 32
    assert [item.allowed for item in reconciled] == [item.allowed for item in observations]
    assert [item.latency_ms for item in reconciled] == [item.latency_ms for item in observations]
    assert all(item.route == "native_fail_safe" for item in observations)


@pytest.mark.parametrize("overload_delta", [32, 64])
def test_native_counter_cannot_reuse_explicit_overload_events(overload_delta: int) -> None:
    observations = [replace(item, allowed=False) for item in _mixed_observations()]

    classified = capacity._classify_native_overloads(observations, overload_delta=overload_delta)

    assert sum(item.overloaded for item in classified) == 32
    assert all(not item.overloaded for item in classified[:32])


def test_native_counter_cannot_label_allowed_response_as_overload() -> None:
    observations = _mixed_observations()[:32]
    classified = capacity._classify_native_overloads(observations, overload_delta=32)
    assert not any(item.overloaded for item in classified)


def test_native_counter_preserves_unambiguous_denied_overload_cohort() -> None:
    observations = [replace(item, allowed=False) for item in _mixed_observations()[:32]]
    classified = capacity._classify_native_overloads(observations, overload_delta=32)
    assert all(item.overloaded and not item.allowed for item in classified)


@pytest.mark.parametrize(
    "delta",
    [
        {"native_resident": 31, "native_fail_safe": 32},
        {"native_resident": 33, "native_fail_safe": 32},
        {"native_resident": 32, "native_fail_safe": 31},
        {"native_resident": 32, "native_fail_safe": 33},
        {"native_resident": 32, "native_fail_safe": 31, "python_semantic": 1},
        {"native_resident": 31, "native_fail_safe": 32, "native_oneshot": 1},
        {"native_resident": 31, "native_fail_safe": 32, "native_degraded": 1},
        {"native_resident": 31, "native_fail_safe": 32, "unknown": 1},
    ],
)
def test_incomplete_extra_or_other_route_counter_keeps_wave_fail_closed(delta: dict[str, int]) -> None:
    observations = _mixed_observations()
    reconciled = capacity._reconcile_wave_routes(observations, errors=0, before=Counter(), after=Counter(delta))
    assert reconciled is observations


@pytest.mark.parametrize("failure", ["request_error", "generic_denial", "allowed_overload", "legacy_route", "reset"])
def test_unexplained_response_error_or_counter_reset_keeps_wave_fail_closed(failure: str) -> None:
    observations = _mixed_observations()
    before: Counter[str] = Counter()
    after = Counter({"native_resident": 32, "native_fail_safe": 32})
    errors = 0
    if failure == "request_error":
        errors = 1
    elif failure == "generic_denial":
        observations[0] = replace(observations[0], allowed=False)
    elif failure == "allowed_overload":
        observations[-1] = replace(observations[-1], allowed=True)
    elif failure == "legacy_route":
        observations[0] = replace(observations[0], route="python_semantic")
    else:
        before["native_oneshot"] = 1

    assert capacity._reconcile_wave_routes(observations, errors=errors, before=before, after=after) is observations


def test_real_interleaving_preserves_explicit_overload_and_proves_other_response_resident(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    metrics = HookMetricsRecorder()
    barrier = threading.Barrier(2, timeout=1)

    def request(_daemon: object, *, harness: str, **_kwargs: object) -> dict[str, str]:
        # Both observations have taken their initial snapshots. Both route
        # records must also exist before either observation takes its final one.
        barrier.wait()
        if harness == "codex":
            metrics.record_route("native_resident")
            response = {"decision": "allow"}
        else:
            metrics.record_route("native_fail_safe")
            response = {"decision": "deny", "reason_code": "daemon_capacity"}
        barrier.wait()
        return response

    session = cast(
        AdapterSession,
        cast(
            object,
            SimpleNamespace(
                daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=SimpleNamespace(metrics=metrics))),
                guard_home=tmp_path,
                workspace=tmp_path,
                _connection=None,
                _owner_thread_id=threading.get_ident(),
                native_overload_count=lambda: 0,
            ),
        ),
    )

    def observe(
        harness: str,
        event: str,
        size_class: str,
        request_payload: Mapping[str, object] | None = None,
    ) -> Observation:
        return AdapterSession.observe(session, harness, event, size_class, request_payload)

    session.observe = observe
    monkeypatch.setattr(session_module, "_request", request)

    with ThreadPoolExecutor(max_workers=2) as executor:
        observations, errors = capacity._measure_classified_wave(
            session, (("codex", "PreToolUse"), ("pi", "PreToolUse")), 2, executor
        )

    assert errors == 0
    assert observations[0].route == "native_resident"
    assert observations[0].allowed and not observations[0].overloaded
    assert observations[1].route == "native_fail_safe"
    assert not observations[1].allowed and observations[1].overloaded
    diagnostic = json.loads(capsys.readouterr().err)
    assert diagnostic["observed_routes"] == {"native_fail_safe": 2}
    assert diagnostic["route_counters_after"] == {"native_fail_safe": 1, "native_resident": 1}
    assert diagnostic["reconciled_routes"] == {"native_fail_safe": 1, "native_resident": 1}
    assert diagnostic["native_overloads_before"] == diagnostic["native_overloads_after"] == 0
    assert diagnostic["explicit_overload_responses"] == 1
    assert diagnostic["classified_overload_responses"] == 1
    assert str(tmp_path) not in json.dumps(diagnostic)
