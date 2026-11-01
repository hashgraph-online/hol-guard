"""The workspace_assessment_enabled setting stops the worker and deletes nothing."""

from __future__ import annotations

import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import config as guard_config
from codex_plugin_scanner.guard import workspace_assessment_store as assessments
from codex_plugin_scanner.guard import workspace_assessment_worker as worker
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore
from tests.workspace_fix_support import KEYS, T0, admit_worktree


def _settings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, enabled: bool) -> dict[str, bool]:
    state = {"enabled": enabled}

    def load(guard_home: Path, *_: object, **__: object) -> GuardConfig:
        return GuardConfig(guard_home=guard_home, workspace=None, workspace_assessment_enabled=state["enabled"])

    monkeypatch.setattr(guard_config, "load_guard_config", load)
    return state


def _polls(monkeypatch: pytest.MonkeyPatch) -> threading.Semaphore:
    polled = threading.Semaphore(0)
    monkeypatch.setattr(worker, "poll_once", lambda *args, **kwargs: polled.release() or 0)
    return polled


def test_the_setting_is_on_by_default() -> None:
    assert GuardConfig(guard_home=Path("home"), workspace=None).workspace_assessment_enabled is True


def test_worker_does_not_poll_while_the_setting_is_off_and_resumes_when_it_is_on(tmp_path: Path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "home")
    setting = _settings(monkeypatch, tmp_path, enabled=False)
    polled = _polls(monkeypatch)
    stop = threading.Event()

    thread = worker.start_workspace_assessment_worker(store, stop=stop, on_error=pytest.fail, interval=0.01)
    try:
        assert not polled.acquire(timeout=0.2)
        setting["enabled"] = True
        assert polled.acquire(timeout=5)
    finally:
        stop.set()
        thread.join(timeout=5)


def test_worker_starts_and_polls_while_the_setting_is_on(tmp_path: Path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "home")
    _settings(monkeypatch, tmp_path, enabled=True)
    polled = _polls(monkeypatch)
    stop = threading.Event()

    thread = worker.start_workspace_assessment_worker(store, stop=stop, on_error=pytest.fail, interval=0.01)
    try:
        assert thread.is_alive()
        assert polled.acquire(timeout=5)
    finally:
        stop.set()
        thread.join(timeout=5)


def test_turning_the_setting_off_stops_a_running_worker_without_deleting_anything(tmp_path: Path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "home")
    admit_worktree(store, KEYS, root=str(tmp_path), now_ms=T0)
    assessments.enqueue(store, KEYS, trigger_kind="manual", detector_set_digest="d" * 64, now_ms=T0)
    state = _settings(monkeypatch, tmp_path, enabled=True)
    polled = _polls(monkeypatch)
    stop = threading.Event()
    thread = worker.start_workspace_assessment_worker(store, stop=stop, on_error=pytest.fail, interval=0.01)
    try:
        assert polled.acquire(timeout=5)
        state["enabled"] = False
        # A poll already under way may finish; after that none starts.
        while polled.acquire(timeout=0.2):
            pass
        assert not polled.acquire(timeout=0.2)
    finally:
        stop.set()
        thread.join(timeout=5)

    assert [item["worktree_key"] for item in assessments.list_worktrees(store)] == [KEYS.worktree_key]
    assert len(assessments.recent_runs(store)) == 1


def test_an_unreadable_configuration_leaves_the_worker_on(tmp_path: Path, monkeypatch) -> None:
    def broken(*_: object, **__: object) -> GuardConfig:
        raise guard_config.ConfigFileTrustError("native_guard_config_unavailable")

    monkeypatch.setattr(guard_config, "load_guard_config", broken)

    assert worker.workspace_assessment_enabled(tmp_path) is True


def test_the_daemon_starts_the_worker_while_the_setting_is_off_so_turning_it_on_needs_no_restart(
    tmp_path: Path, monkeypatch
) -> None:
    _settings(monkeypatch, tmp_path, enabled=False)
    _polls(monkeypatch)
    daemon = SimpleNamespace(
        _workspace_assessment_thread=None,
        _server=SimpleNamespace(store=SimpleNamespace(guard_home=tmp_path)),
        _shutdown_started=threading.Event(),
        _diagnostics=SimpleNamespace(record_exception=lambda *_: None),
    )
    try:
        GuardDaemonServer._start_workspace_assessment_worker(daemon)  # type: ignore[arg-type]
        assert daemon._workspace_assessment_thread.is_alive()
    finally:
        daemon._shutdown_started.set()
        daemon._workspace_assessment_thread.join(timeout=5)
