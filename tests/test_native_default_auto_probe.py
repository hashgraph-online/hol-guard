from __future__ import annotations

import time
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.native_probe_receipts import receipt_corpus_is_complete, wait_for_receipt_corpus, wait_for_route_corpus


def test_receipt_corpus_complete_requires_processed_count() -> None:
    stats: Mapping[str, object] = {
        "receipt_accepted": 21,
        "receipt_processed": 20,
        "receipt_dropped": 0,
        "receipt_failures": 1,
        "receipt_durable_pending": 1,
    }
    assert not receipt_corpus_is_complete(stats, expected=21)
    assert receipt_corpus_is_complete(
        {
            "receipt_accepted": 21,
            "receipt_processed": 21,
            "receipt_dropped": 0,
            "receipt_failures": 2,
            "receipt_durable_pending": 0,
        },
        expected=21,
    )


def test_wait_for_receipt_corpus_polls_until_processed() -> None:
    snapshots = iter(
        (
            {
                "receipt_accepted": 21,
                "receipt_processed": 20,
                "receipt_dropped": 0,
                "receipt_failures": 1,
                "receipt_durable_pending": 1,
            },
            {
                "receipt_accepted": 21,
                "receipt_processed": 21,
                "receipt_dropped": 0,
                "receipt_failures": 2,
                "receipt_durable_pending": 0,
            },
        )
    )

    class FakeWriter:
        def stats(self) -> Mapping[str, object]:
            return next(snapshots)

    started = time.monotonic()
    complete = wait_for_receipt_corpus(FakeWriter(), expected=21, timeout_seconds=1.0)
    assert complete["receipt_processed"] == 21
    assert time.monotonic() - started < 1.0


def test_installed_corpus_waits_before_mode_changes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from ci.native_runtime import probe_native_default_auto as probe

    events: list[str] = []

    class DelayedMetrics:
        reads = 0

        def snapshot(self) -> Mapping[str, object]:
            self.reads += 1
            return {"routes": {"native_resident": min(19 + self.reads, 21)}}

    class CompleteWriter:
        def stats(self) -> Mapping[str, object]:
            return {
                "receipt_accepted": 21,
                "receipt_processed": 21,
                "receipt_dropped": 0,
                "receipt_durable_pending": 0,
                "receipt_deduped": 0,
                "receipt_failures": 0,
            }

    metrics = DelayedMetrics()
    worker = SimpleNamespace(
        metrics=metrics,
        policy_snapshot_publisher=SimpleNamespace(),
        prepare_workspace_policy=lambda *args, **kwargs: object(),
        test_oracle=None,
    )

    class FakeDaemon:
        def __init__(self, *args: object, **kwargs: object) -> None:
            self._server = SimpleNamespace(hook_worker=worker, runtime_hook_evidence_writer=CompleteWriter())

        def start(self) -> None:
            events.append("started")

        def stop(self) -> None:
            events.append("stopped")

    def exercise_routes(daemon, guard_home, workspace, routes, route_receipts, reason_codes) -> None:
        route_receipts.extend({"route": "native_resident"} for _ in range(21))

    def exercise_modes(*args: object) -> dict[str, object]:
        assert metrics.reads >= 2, "Mode changes started before the last route was recorded"
        events.append("modes")
        return {}

    monkeypatch.setattr(probe, "GuardStore", lambda *args: object())
    monkeypatch.setattr(probe, "GuardDaemonServer", FakeDaemon)
    monkeypatch.setattr(probe, "_ownership_routes", lambda: {})
    monkeypatch.setattr(probe, "_exercise_installed_routes", exercise_routes)
    monkeypatch.setattr(probe, "_exercise_mode_invariants", exercise_modes)
    result = probe._installed_hook_corpus(tmp_path)
    assert result["native_resident_decisions"] == 21
    assert result["route_count"] == 21
    assert events == ["started", "modes", "stopped"]


def test_wait_for_route_corpus_observes_completion_before_snapshot() -> None:
    snapshots = iter(
        (
            {"routes": {"native_resident": 20}},
            {"routes": {"native_resident": 21}},
        )
    )

    class FakeMetrics:
        def snapshot(self) -> Mapping[str, object]:
            return next(snapshots)

    complete = wait_for_route_corpus(FakeMetrics(), expected=21, timeout_seconds=1.0)
    assert complete["routes"] == {"native_resident": 21}


def test_wait_for_route_corpus_does_not_hide_a_wrong_route() -> None:
    class FakeMetrics:
        def snapshot(self) -> Mapping[str, object]:
            return {"routes": {"native_resident": 20, "native_fail_safe": 1}}

    complete = wait_for_route_corpus(FakeMetrics(), expected=21)
    assert complete["routes"] == {"native_resident": 20, "native_fail_safe": 1}


def test_wait_for_route_corpus_timeout_preserves_incomplete_evidence() -> None:
    class FakeMetrics:
        def snapshot(self) -> Mapping[str, object]:
            return {"routes": {"native_resident": 20}}

    incomplete = wait_for_route_corpus(FakeMetrics(), expected=21, timeout_seconds=0)
    assert incomplete["routes"] == {"native_resident": 20}


@pytest.mark.parametrize(
    "snapshot",
    [
        None,
        {},
        {"routes": []},
        {"routes": {"native_resident": "21"}},
        {"routes": {"native_resident": True}},
        {"routes": {"native_resident": -1}},
    ],
)
def test_wait_for_route_corpus_rejects_invalid_metric_shapes(snapshot: object) -> None:
    class FakeMetrics:
        def snapshot(self) -> object:
            return snapshot

    with pytest.raises(RuntimeError, match="invalid route"):
        wait_for_route_corpus(FakeMetrics(), expected=21, timeout_seconds=0)


def test_wait_for_route_corpus_requires_a_snapshot_method() -> None:
    with pytest.raises(RuntimeError, match="snapshot"):
        wait_for_route_corpus(object(), expected=21)


@pytest.mark.parametrize("expected", [0, -1])
def test_wait_for_route_corpus_rejects_empty_inventory(expected: int) -> None:
    with pytest.raises(ValueError, match="positive"):
        wait_for_route_corpus(object(), expected=expected)
