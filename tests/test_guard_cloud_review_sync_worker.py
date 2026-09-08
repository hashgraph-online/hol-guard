"""Behavioral coverage for durable Cloud Review event synchronization."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import cloud_review_sync as cloud_review_sync_module
from codex_plugin_scanner.guard.runtime import cloud_review_sync_worker
from codex_plugin_scanner.guard.runtime.cloud_review_event_delivery import CLOUD_REVIEW_EVENT_PROTOCOL_VERSION
from codex_plugin_scanner.guard.runtime.cloud_review_sync import (
    start_cloud_sync_sync_worker,
    stop_cloud_sync_sync_worker,
)


class Store:
    """Minimal GuardStore stand-in for event and worker contracts."""

    def __init__(self, guard_home: Path) -> None:
        self.guard_home = guard_home
        self.path = guard_home / "guard.db"
        self._payloads: dict[str, object] = {}

    def get_sync_payload(self, key: str) -> object | None:
        return self._payloads.get(key)

    def set_sync_payload(self, key: str, payload: object, now: str) -> None:
        self._payloads[key] = payload

    def get_cloud_sync_profile(self) -> dict[str, str]:
        return {
            "auth_mode": "oauth",
            "sync_url": "https://hol.test/api/guard/receipts/sync",
            "workspace_id": "workspace-1",
        }

    def get_oauth_local_credentials(self, *, allow_primary: bool = False) -> dict[str, object]:
        return {
            "grant_id": "grant-1",
            "machine_id": "machine-1",
            "runtime_id": "runtime-1",
            "workspace_id": "workspace-1",
        }

    def get_or_create_installation_id(self) -> str:
        return "22222222-2222-4222-8222-222222222222"

    def get_guard_operation_for_approval_request(self, request_id: str) -> dict[str, object]:
        return {"operation_id": request_id, "metadata": {"workspace_path": "/workspace/repo"}}


class TestIndependentWorker:
    def test_worker_owns_live_review_sync(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        store = Store(tmp_path)
        calls: list[tuple[str, dict[str, object]]] = []

        class StopAfterOneIteration:
            stopped = False

            def is_set(self) -> bool:
                return self.stopped

        class StopAfterOneWait:
            def generation(self) -> int:
                return 0

            def wait(self, generation: int, timeout: float) -> int:
                del generation, timeout
                stop.stopped = True
                return 0

        stop = StopAfterOneIteration()

        monkeypatch.setattr(
            cloud_review_sync_module,
            "_resolve_cloud_review_sync_auth_context",
            lambda _store: {"access_token": "token-1", "workspace_id": "workspace-1"},
        )
        monkeypatch.setattr(
            cloud_review_sync_module,
            "sync_cloud_review_events_once",
            lambda _store, auth: calls.append(("review", auth)) or {"synced": 0},
        )

        cloud_review_sync_worker._cloud_sync_sync_loop(
            store,
            stop,
            StopAfterOneWait(),
            poll_interval=1,
            error_backoff=1,
        )

        assert calls == [
            ("review", {"access_token": "token-1", "workspace_id": "workspace-1"}),
        ]

    def test_connected_daemon_starts_cloud_review_worker(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        store = Store(tmp_path)

        class FakeThread:
            def __init__(self, *args: object, **kwargs: object) -> None:
                self.started = False

            def is_alive(self) -> bool:
                return True

            def start(self) -> None:
                self.started = True

        created_thread = FakeThread()

        def fake_thread(*args: object, **kwargs: object) -> FakeThread:
            return created_thread

        monkeypatch.setattr(cloud_review_sync_worker.threading, "Thread", fake_thread)
        worker = start_cloud_sync_sync_worker(store)
        assert worker is not None
        assert worker.thread is created_thread
        assert created_thread.started is True

    def test_stop_worker_signals_stop_event(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        store = Store(tmp_path)

        class FakeThread:
            def __init__(self) -> None:
                self.started = False
                self.joined = False
                self.join_timeout: float | None = -1

            def is_alive(self) -> bool:
                return not self.joined

            def start(self) -> None:
                self.started = True

            def join(self, timeout: float | None = None) -> None:
                self.join_timeout = timeout
                self.joined = True

        class FakeEvent:
            def __init__(self, stopped: bool = False) -> None:
                self.stopped = stopped

            def is_set(self) -> bool:
                return self.stopped

            def set(self) -> None:
                self.stopped = True

        created_thread = FakeThread()
        created_event = FakeEvent(False)

        def fake_thread(*args: object, **kwargs: object) -> FakeThread:
            return created_thread

        monkeypatch.setattr(
            "codex_plugin_scanner.guard.runtime.cloud_review_sync_worker.threading.Thread",
            fake_thread,
        )
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.runtime.cloud_review_sync_worker.threading.Event",
            lambda: created_event,
        )

        worker = start_cloud_sync_sync_worker(store)
        assert worker is not None
        assert created_event.is_set() is False

        new_worker = stop_cloud_sync_sync_worker(worker)
        assert new_worker is None  # dead worker returns None
        assert created_event.is_set() is True
        assert created_thread.join_timeout == 1.0

    def test_start_worker_skips_alive_existing(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        store = Store(tmp_path)

        class FakeThread:
            def is_alive(self) -> bool:
                return True

            def start(self) -> None:
                pass

        class FakeEvent:
            def is_set(self) -> bool:
                return False

        existing = type("Worker", (), {"thread": FakeThread(), "stop_event": FakeEvent()})()
        monkeypatch.delenv("GUARD_CLOUD_REVIEW_POLL_INTERVAL", raising=False)

        new_worker = start_cloud_sync_sync_worker(store, existing=existing)  # type: ignore[arg-type]
        assert new_worker is existing

    def test_start_worker_returns_none_without_cloud_profile(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        store = Store(tmp_path)
        monkeypatch.setattr(store, "get_cloud_sync_profile", lambda: {})

        assert start_cloud_sync_sync_worker(store) is None

    def test_start_worker_with_existing_stopped_thread(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        store = Store(tmp_path)

        class FakeThread:
            def __init__(self, *_args: object, **_kwargs: object) -> None:
                self.started = False

            def is_alive(self) -> bool:
                return False

            def start(self) -> None:
                self.started = True

        class FakeEvent:
            def is_set(self) -> bool:
                return True

        existing = type("Worker", (), {"thread": FakeThread(), "stop_event": FakeEvent()})()
        monkeypatch.delenv("GUARD_CLOUD_REVIEW_POLL_INTERVAL", raising=False)
        monkeypatch.setattr(cloud_review_sync_worker.threading, "Thread", FakeThread)

        new_worker = start_cloud_sync_sync_worker(store, existing=existing)  # type: ignore[arg-type]
        assert new_worker is not existing

    def test_stop_worker_none_noop(self, tmp_path: Path) -> None:
        assert stop_cloud_sync_sync_worker(None) is None


class TestSyncStatus:
    def test_status_returns_protocol_version(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.store import GuardStore

        store = GuardStore(tmp_path)
        from codex_plugin_scanner.guard.runtime.cloud_review_sync import cloud_review_sync_status

        status = cloud_review_sync_status(store)
        assert isinstance(status, dict)
        assert status["protocolVersion"] == CLOUD_REVIEW_EVENT_PROTOCOL_VERSION
