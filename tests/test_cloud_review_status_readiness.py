"""Readiness requires fresh worker liveness for the current source and identity."""

from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.cli import commands_dispatch_cloud_review as cli
from codex_plugin_scanner.guard.daemon.cloud_review_worker_status import observe_cloud_review_workers
from codex_plugin_scanner.guard.runtime.cloud_review_status import cloud_review_status, review_connection_binding_id
from codex_plugin_scanner.guard.runtime.exact_cloud_review import enable_exact_cloud_review
from tests.guard_exact_cloud_review_support import connected_exact_review_store
from tests.test_cloud_review_status_parity import _cli_status


def _observation(store, now: datetime, **changes: object) -> dict[str, object]:
    return {
        "running": True,
        "sync_running": True,
        "source": store.guard_source,
        "connection_binding_id": review_connection_binding_id(store.get_review_event_oauth_binding()),
        "observed_at": now.isoformat(),
        **changes,
    }


@pytest.mark.parametrize(
    "running,sync_running,expected",
    [(True, True, True), (True, False, False), (False, True, False), (True, "true", None)],
)
def test_status_requires_both_observed_workers(
    tmp_path: Path, running: object, sync_running: object, expected: bool | None
) -> None:
    store = connected_exact_review_store(tmp_path)
    enable_exact_cloud_review(store)
    now = datetime.now(timezone.utc)
    status = cloud_review_status(
        store, now=now, worker_observation=_observation(store, now, running=running, sync_running=sync_running)
    )
    assert status["delivery_ready"] is expected
    assert status["consent_enabled"] is True


@pytest.mark.parametrize("change", ["old", "future", "source", "binding", "missing"])
def test_stale_or_wrong_identity_observation_cannot_claim_ready(tmp_path: Path, change: str) -> None:
    store = connected_exact_review_store(tmp_path)
    enable_exact_cloud_review(store)
    now = datetime.now(timezone.utc)
    observation = _observation(store, now)
    if change == "old":
        observation["observed_at"] = (now - timedelta(seconds=6)).isoformat()
    elif change == "future":
        observation["observed_at"] = (now + timedelta(seconds=1)).isoformat()
    elif change == "source":
        observation["source"] = "other"
    elif change == "binding":
        observation["connection_binding_id"] = "sha256:" + "0" * 64
    else:
        observation = {}
    result = cloud_review_status(store, now=now, worker_observation=observation)
    assert result["delivery_ready"] is None
    assert result["delivery_readiness_reason"] == "worker_status_unavailable"


def test_cli_uses_fresh_observation_but_still_requires_local_consent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    store = connected_exact_review_store(tmp_path)
    monkeypatch.setattr(
        cli, "read_cloud_review_worker_observation", lambda _home: _observation(store, datetime.now(timezone.utc))
    )
    assert _cli_status(store, capsys)["delivery_ready"] is False
    enable_exact_cloud_review(store)
    assert _cli_status(store, capsys)["delivery_ready"] is True


def test_worker_observation_does_not_restart_workers_or_wait_for_lifecycle_lock(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    finish = threading.Event()
    thread = threading.Thread(target=finish.wait, daemon=True)
    thread.start()
    decision_stop = threading.Event()
    lifecycle = SimpleNamespace(
        _finish_service_lock=threading.Lock(),
        _server=SimpleNamespace(store=store),
        _owned_service_ready=True,
        _shutdown_started=threading.Event(),
        _command_queue_worker=SimpleNamespace(thread=thread, stop_event=decision_stop),
        _cloud_review_sync_worker=SimpleNamespace(thread=thread, stop_event=threading.Event()),
    )
    try:
        first = observe_cloud_review_workers(store, lifecycle)
        assert first["running"] is True and first["sync_running"] is True
        decision_stop.set()
        second = observe_cloud_review_workers(store, lifecycle)
        assert second["running"] is False and second["sync_running"] is True
        with lifecycle._finish_service_lock:
            assert observe_cloud_review_workers(store, lifecycle) is None
        lifecycle._shutdown_started.set()
        stopped = observe_cloud_review_workers(store, lifecycle)
        assert stopped["running"] is False and stopped["sync_running"] is False
    finally:
        finish.set()
        thread.join(timeout=1)
