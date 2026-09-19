"""Resource ownership controls around the unchanged native-authority tests."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_policy_snapshot
from codex_plugin_scanner.guard.daemon import hook_worker
from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.store import GuardStore
from tests import test_rust_pretool_authority as authority_tests
from tests import test_rust_pretool_authority_worker as worker_tests

OriginalTest = Callable[[Path, pytest.MonkeyPatch], None]


def _exercise_original_test(
    original_test: OriginalTest,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    explicit_close: bool = False,
) -> dict[str, bool]:
    guard_home = tmp_path / "guard-home"
    registry_key = native_policy_snapshot._publisher_key(guard_home)
    with native_policy_snapshot._PUBLISHER_LOCK:
        home_initially_unowned = not native_policy_snapshot._PUBLISHERS.get(registry_key)
    assert home_initially_unowned
    original_factory = hook_worker.get_native_policy_snapshot_publisher
    captured: list[tuple[NativePolicySnapshotPublisher, GuardStore]] = []

    def capture_actual_publisher(store: GuardStore) -> NativePolicySnapshotPublisher:
        publisher = original_factory(store)
        captured.append((publisher, store))
        return publisher

    with monkeypatch.context() as scoped:
        scoped.setattr(hook_worker, "get_native_policy_snapshot_publisher", capture_actual_publisher)
        try:
            original_test(tmp_path, scoped)
            original_assertions_completed = True
            if explicit_close:
                for publisher, _store in captured:
                    publisher.close()
            with native_policy_snapshot._PUBLISHER_LOCK:
                home_registry_empty = not native_policy_snapshot._PUBLISHERS.get(registry_key)
            return {
                "original_assertions_completed": original_assertions_completed,
                "captured_one_publisher": len(captured) == 1,
                "factory_preserved_store": all(publisher.store is store for publisher, store in captured),
                "publisher_owned_by_home": all(publisher.guard_home == guard_home for publisher, _ in captured),
                "publisher_started_thread": all(publisher._thread is not None for publisher, _ in captured),
                "publishers_closed": all(publisher.closed for publisher, _ in captured),
                "publisher_threads_stopped": all(
                    publisher._thread is not None and not publisher._thread.is_alive() for publisher, _ in captured
                ),
                "home_registry_empty": home_registry_empty,
            }
        finally:
            for publisher, _store in captured:
                publisher.close()


@pytest.mark.parametrize(
    "original_test",
    (
        authority_tests.test_hook_worker_fails_closed_when_forced_native_is_missing,
        worker_tests.test_hook_worker_fails_closed_when_forced_native_is_missing,
    ),
    ids=("authority_module", "worker_module"),
)
def test_original_native_authority_case_releases_its_publisher(
    original_test: OriginalTest, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observation = _exercise_original_test(original_test, tmp_path, monkeypatch)
    assert observation == dict.fromkeys(observation, True)


def test_explicit_close_releases_the_same_real_publisher(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    observation = _exercise_original_test(
        worker_tests.test_hook_worker_fails_closed_when_forced_native_is_missing,
        tmp_path,
        monkeypatch,
        explicit_close=True,
    )
    assert observation == dict.fromkeys(observation, True)
