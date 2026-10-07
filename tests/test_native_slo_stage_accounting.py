from __future__ import annotations

from types import SimpleNamespace

import pytest

from scripts import native_slo_capacity as capacity
from scripts.native_slo_adapter import Observation
from scripts.native_slo_benchmark_stages import _run_recovery
from scripts.native_slo_progress import SloProgress, incomplete_slo_result


def test_recovery_stop_failure_is_counted_without_fabricating_a_request_attempt() -> None:
    progress = SloProgress()
    progress.configure(
        (("codex", "PostToolUse"),),
        warm_iterations=1,
        cold_iterations=1,
        recovery_iterations=2,
        readiness_samples=1,
        include_capacity=False,
    )
    session = SimpleNamespace(
        observe=lambda *_: Observation("codex", "PostToolUse", "1k", 1.0, "native_resident", True),
        stop_resident=lambda **_: False,
    )
    with pytest.raises(RuntimeError, match="resident stop failed"):
        _run_recovery(session, 2, progress=progress)

    report = incomplete_slo_result(progress, include_capacity=False)
    stages = report["corpus"]["denominators"]
    assert report["failure"]["stage"] == "recovery_stop"
    assert stages["recovery_stop"]["planned"] == 2
    assert stages["recovery_stop"]["attempted"] == stages["recovery_stop"]["failed"] == 1
    assert stages["recovery_stop"]["missing"] == 1
    assert stages["recovery_precondition"]["completed"] == 1
    assert stages["recovery"]["attempted"] == stages["recovery"]["failed"] == 0
    assert stages["recovery"]["missing"] == 2


def test_prewarm_postcondition_failure_has_its_own_operation_denominator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    progress = SloProgress()
    progress.configure(
        (("codex", "PreToolUse"),),
        warm_iterations=1,
        cold_iterations=1,
        recovery_iterations=1,
        readiness_samples=1,
        include_capacity=True,
    )
    observations = [Observation("codex", "PreToolUse", "1k", 1.0, "native_resident", True)] * 16
    monkeypatch.setattr(capacity, "_prime_load_executor", lambda *_: None)
    monkeypatch.setattr(capacity, "_run_concurrent", lambda *_args, **_kwargs: (observations, 0))

    def fail_ready(*_args: object) -> None:
        raise RuntimeError("native_installed_slo_failed: fixture pool readiness changed")

    monkeypatch.setattr(capacity, "_require_ready_hook_workers", fail_ready)
    with pytest.raises(RuntimeError):
        capacity._prewarm_capacity_workers(
            object(),
            (("codex", "PreToolUse"),),
            16,
            on_deferred_complete=progress.complete,
            on_deferred_failure=progress.fail_request,
            progress=progress,
        )
    report = incomplete_slo_result(progress, include_capacity=True)
    stages = report["corpus"]["denominators"]
    assert stages["capacity_prewarm"]["completed"] == 16
    assert report["failure"]["stage"] == "capacity_prewarm_ready"
    assert stages["capacity_prewarm_ready"]["planned"] == 1
    assert stages["capacity_prewarm_ready"]["attempted"] == stages["capacity_prewarm_ready"]["failed"] == 1
    assert stages["capacity_prewarm_ready"]["completed"] == stages["capacity_prewarm_ready"]["missing"] == 0
