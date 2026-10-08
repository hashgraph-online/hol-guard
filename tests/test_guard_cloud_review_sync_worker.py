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

    guard_source = "default"

    def __init__(self, guard_home: Path) -> None:
        self.guard_home = guard_home
        self.path = guard_home / "guard.db"
        self._payloads: dict[str, object] = {}

    def get_sync_payload(self, key: str) -> object | None:
        return self._payloads.get(key)

    def get_review_event_oauth_binding(self) -> None:
        return None

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
    def test_queue_start_retries_after_contended_lifecycle_lock(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import threading

        from codex_plugin_scanner.guard.runtime import native_workspace_review_enrollment

        store = Store(tmp_path)
        stop = threading.Event()
        enrollments: list[bool] = []
        queue_attempts: list[bool] = []

        class Wake:
            def generation(self) -> int:
                return 0

            def wait(self, generation: int, timeout: float) -> int:
                del generation, timeout
                if len(queue_attempts) == 2:
                    stop.set()
                return 0

        def enroll(_store: object, _auth: object) -> bool:
            enrolled = not enrollments
            enrollments.append(enrolled)
            return enrolled

        def start_queue() -> bool:
            ready = bool(queue_attempts)
            queue_attempts.append(ready)
            return ready

        monkeypatch.setattr(cloud_review_sync_module, "_resolve_cloud_review_sync_auth_context", lambda _store: {})
        monkeypatch.setattr(native_workspace_review_enrollment, "refresh_native_workspace_review_authority", enroll)
        monkeypatch.setattr(cloud_review_sync_module, "sync_cloud_review_events_once", lambda *_args: {"synced": 0})
        cloud_review_sync_worker._cloud_sync_sync_loop(
            store, stop, Wake(), poll_interval=1, error_backoff=1, on_authority_changed=start_queue
        )
        assert enrollments == [True, False]
        assert queue_attempts == [False, True]

    def test_new_authority_reprobes_pending_review_before_upload(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from codex_plugin_scanner.guard.runtime import native_workspace_review_enrollment

        store = Store(tmp_path)
        binding = {"workspace_id": "workspace-1", "machine_installation_id": "installation-1"}
        calls: list[str] = []

        class StopAfterOne:
            stopped = False

            def is_set(self) -> bool:
                return self.stopped

        class Wake:
            def generation(self) -> int:
                return 0

            def wait(self, generation: int, timeout: float) -> int:
                del generation, timeout
                stop.stopped = True
                return 0

        stop = StopAfterOne()
        monkeypatch.setattr(store, "get_review_event_oauth_binding", lambda: binding)
        monkeypatch.setattr(cloud_review_sync_module, "_resolve_cloud_review_sync_auth_context", lambda _store: {})
        monkeypatch.setattr(
            native_workspace_review_enrollment,
            "refresh_native_workspace_review_authority",
            lambda _store, _auth: calls.append("enroll") or True,
        )
        monkeypatch.setattr(cloud_review_sync_worker, "prepare_retry_identity_replay", lambda *_args, **_kwargs: None)

        def replay(_store: object, *, binding: object, force_probe: bool) -> None:
            assert binding == {"workspace_id": "workspace-1", "machine_installation_id": "installation-1"}
            assert force_probe
            calls.append("reprobe")

        monkeypatch.setattr(cloud_review_sync_worker, "prepare_native_workspace_review_replay", replay)
        monkeypatch.setattr(
            cloud_review_sync_module,
            "sync_cloud_review_events_once",
            lambda _store, _auth: calls.append("upload") or {"synced": 0},
        )
        cloud_review_sync_worker._cloud_sync_sync_loop(
            store,
            stop,
            Wake(),
            poll_interval=1,
            error_backoff=1,
            on_authority_changed=lambda: calls.append("start-command-queue") or True,
        )
        assert calls == ["enroll", "start-command-queue", "reprobe", "upload"]

    def test_late_connection_wakes_delivery_without_restarting_daemon(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import threading

        store = Store(tmp_path)
        profile = store.get_cloud_sync_profile()
        connected = False
        stop = threading.Event()
        uploads: list[str] = []

        class ConnectOnWait:
            def generation(self) -> int:
                return 0

            def wait(self, generation: int, timeout: float) -> int:
                nonlocal connected
                del generation, timeout
                if connected:
                    stop.set()
                connected = True
                return 1

        monkeypatch.setattr(store, "get_cloud_sync_profile", lambda: profile if connected else {})
        monkeypatch.setattr(cloud_review_sync_module, "_resolve_cloud_review_sync_auth_context", lambda _store: {})
        monkeypatch.setattr(
            cloud_review_sync_module,
            "sync_cloud_review_events_once",
            lambda _store, _auth: uploads.append("uploaded") or {"synced": 0},
        )
        cloud_review_sync_worker._cloud_sync_sync_loop(store, stop, ConnectOnWait(), poll_interval=30, error_backoff=30)
        assert uploads == ["uploaded"]

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

    def test_start_worker_waits_for_late_cloud_connection(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        store = Store(tmp_path)
        monkeypatch.setattr(store, "get_cloud_sync_profile", lambda: {})

        worker = start_cloud_sync_sync_worker(store)
        try:
            assert worker is not None
            assert worker.thread.is_alive()
        finally:
            stop_cloud_sync_sync_worker(worker)

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
