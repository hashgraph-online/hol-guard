"""Unmarked refreshes stay isolated while service-worker tests can opt in."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.daemon import command_queue_worker as decision_workers
from codex_plugin_scanner.guard.runtime import cloud_review_sync_worker as event_workers
from codex_plugin_scanner.guard.store import GuardStore


def _exercise_refresh(
    kind: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> SimpleNamespace:
    started: list[object] = []

    class RecordingThread:
        def __init__(
            self, *, target: object, kwargs: dict[str, object], daemon: bool,
            name: str | None = None,
        ) -> None:
            self.target = target
            self.kwargs = kwargs
            self.daemon = daemon
            self.name = name
            self.alive = False

        def start(self) -> None:
            self.alive = True
            started.append(self)

        def is_alive(self) -> bool:
            return self.alive

        def join(self, timeout: float) -> None:
            assert timeout > 0
            self.alive = False

    store = GuardStore(tmp_path)
    if kind == "commands":
        monkeypatch.setattr(decision_workers, "command_queue_should_poll", lambda _store: True)
        monkeypatch.setattr(
            decision_workers, "threading",
            SimpleNamespace(**{**vars(decision_workers.threading), "Thread": RecordingThread}),
        )
        command_worker, running = decision_workers.refresh_command_queue_worker(
            store, None, shutting_down=False,
        )

        def cleanup_commands() -> None:
            assert decision_workers.stop_command_queue_worker(command_worker) is None

        return SimpleNamespace(
            worker=command_worker, running=running, started=started, cleanup=cleanup_commands,
            target=decision_workers.command_queue_loop, store=store,
        )

    assert kind == "events"
    monkeypatch.setattr(
        event_workers, "threading",
        SimpleNamespace(**{**vars(event_workers.threading), "Thread": RecordingThread}),
    )
    event_worker, running = event_workers.refresh_cloud_review_sync_worker(
        store, None, shutting_down=False,
    )

    def cleanup_events() -> None:
        assert event_workers.stop_cloud_sync_sync_worker(event_worker) is None

    return SimpleNamespace(
        worker=event_worker, running=running, started=started, cleanup=cleanup_events,
        target=event_workers._cloud_sync_sync_loop, store=store,
    )


@pytest.mark.parametrize("kind", ["commands", "events"])
def test_unmarked_refresh_does_not_start_background_workers(
    kind: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    probe = _exercise_refresh(kind, tmp_path, monkeypatch)
    try:
        assert probe.worker is None
        assert probe.running is False
        assert probe.started == []
    finally:
        probe.cleanup()


@pytest.mark.daemon_service_workers
@pytest.mark.parametrize("kind", ["commands", "events"])
def test_marked_refresh_preserves_background_worker_opt_in(
    kind: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    probe = _exercise_refresh(kind, tmp_path, monkeypatch)
    try:
        assert probe.worker is not None
        assert probe.running is True
        assert len(probe.started) == 1
        thread = probe.started[0]
        assert probe.worker.thread is thread
        assert thread.target is probe.target
        assert thread.kwargs["store"] is probe.store
        assert thread.daemon is True
        assert probe.worker.stop_event.is_set() is False
    finally:
        probe.cleanup()
    assert probe.worker.stop_event.is_set() is True
    assert thread.is_alive() is False
