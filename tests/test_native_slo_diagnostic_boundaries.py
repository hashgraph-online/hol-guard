from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from scripts import native_slo_capacity as capacity
from scripts.native_slo_adapter import Observation
from scripts.native_slo_progress import SloProgress


@pytest.mark.parametrize("stage", ["concurrent_16", "capacity_prewarm"])
def test_executor_setup_failure_keeps_stage_without_inventing_requests(
    monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    def fail(*_args: object) -> None:
        raise FileNotFoundError("synthetic private runtime path")

    progress = SloProgress()
    progress.activate(stage, harness="codex", event="PreToolUse", size_class="1k")
    monkeypatch.setattr(capacity, "_prime_load_executor", fail)
    with pytest.raises(FileNotFoundError):
        if stage == "concurrent_16":
            capacity._measure_c16(None, (), include_capacity=True, progress=progress)
        else:
            capacity._prewarm_capacity_workers(None, (), 2, progress=progress)
    wave = "sixteen" if stage == "concurrent_16" else "prewarm"
    assert progress.snapshot_failure() == {"stage": stage, "category": "environment_error", "wave": wave}
    assert all(value["attempted"] == 0 for value in progress.stage_snapshot().values())


@pytest.mark.parametrize("failed_stage", ["concurrent_64", "rss_peak"])
def test_failure_after_rss_readiness_keeps_its_stage(monkeypatch: pytest.MonkeyPatch, failed_stage: str) -> None:
    def fail(*_args: object, **_kwargs: object) -> object:
        raise ConnectionResetError("synthetic private endpoint")

    progress = SloProgress()
    monkeypatch.setattr(capacity, "_prime_load_executor", lambda *_: None)
    monkeypatch.setattr(capacity, "_steady_state_rss_baseline", lambda *_args, **_kwargs: 10)
    monkeypatch.setattr(
        capacity,
        "_measure_classified_wave",
        fail if failed_stage == "concurrent_64" else lambda *_args, **_kwargs: ([], 0),
    )
    monkeypatch.setattr(capacity, "process_rss_bytes", fail)
    session = SimpleNamespace(
        daemon=SimpleNamespace(_server=SimpleNamespace(hook_process_runner=SimpleNamespace(stats=lambda: {})))
    )
    with pytest.raises(ConnectionResetError):
        capacity._measure_rss_and_c64(session, (), 2, include_capacity=True, progress=progress)
    expected = {"stage": failed_stage, "category": "transport_error"}
    if failed_stage == "concurrent_64":
        expected["wave"] = "sixty_four"
    assert progress.snapshot_failure() == expected
    baseline = progress.stage_snapshot()["rss_baseline"]
    assert baseline["attempted"] == baseline["completed"] == 1
    assert baseline["failed"] == 0


def test_baseline_requests_do_not_keep_the_enclosing_failure_stage(monkeypatch: pytest.MonkeyPatch) -> None:
    progress = SloProgress()

    def observe(harness: str, event: str, size_class: str, stage: str) -> Observation:
        progress.activate(stage, harness=harness, event=event, size_class=size_class)
        return Observation(harness, event, size_class, 1.0, "native_resident", True)

    def baseline(run_wave, **_kwargs: object) -> int:
        observations, errors = run_wave()
        assert errors == 0 and len(observations) == 1
        return 10

    def run_concurrent(*_args: object, observer=None, stage: str = "concurrent", **_kwargs: object):
        assert observer is not None
        return [observer("codex", "PreToolUse", "1k", stage)], 0

    monkeypatch.setattr(capacity, "_prime_load_executor", lambda *_args: None)
    monkeypatch.setattr(capacity, "_steady_state_rss_baseline", baseline)
    monkeypatch.setattr(capacity, "_run_concurrent", run_concurrent)
    monkeypatch.setattr(capacity, "_require_ready_hook_workers", lambda *_args: None)
    monkeypatch.setattr(capacity, "process_rss_bytes", lambda: 10)
    session = SimpleNamespace(
        daemon=SimpleNamespace(_server=SimpleNamespace(hook_process_runner=SimpleNamespace(stats=lambda: {})))
    )
    capacity._measure_rss_and_c64(
        session,
        (("codex", "PreToolUse"),),
        1,
        include_capacity=False,
        observer=observe,
        progress=progress,
    )
    assert progress.active_stage == "rss_baseline"
    assert progress.active_labels == {}
    progress.record_failure(RuntimeError("fixture readiness sample failed"), stage="readiness")
    failure = progress.snapshot_failure()
    assert failure["stage"] == "readiness"
    assert "harness" not in failure
    assert "event" not in failure
    assert "size_class" not in failure


def test_capacity_stderr_normalizes_actual_observation_routes(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    private_route = "/synthetic/private/route"
    observation = Observation("codex", "PreToolUse", "1k", 1.0, private_route, False)
    session = SimpleNamespace(
        daemon=SimpleNamespace(
            _server=SimpleNamespace(hook_worker=SimpleNamespace(metrics=SimpleNamespace(snapshot=lambda: {})))
        ),
        native_overload_count=lambda: 0,
    )
    monkeypatch.setattr(capacity, "_run_concurrent", lambda *_args, **_kwargs: ([observation], 1))
    returned, errors = capacity._measure_classified_wave(session, (("codex", "PreToolUse"),), 1, None)
    diagnostic = capsys.readouterr().err
    assert private_route not in diagnostic
    parsed = json.loads(diagnostic)
    assert parsed["observed_routes"] == parsed["reconciled_routes"] == {"unknown": 1}
    assert returned[0].route == private_route and errors == 1
