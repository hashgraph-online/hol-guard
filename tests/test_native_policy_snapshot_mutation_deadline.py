from __future__ import annotations

import contextvars
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from codex_plugin_scanner.guard import native_policy_snapshot as snapshot
from codex_plugin_scanner.guard import native_policy_snapshot_mutation as mutation
from codex_plugin_scanner.guard import native_policy_snapshot_publisher as publisher_module
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.sqlite_deadline import (
    DeadlineConnection,
    sqlite_deadline_monotonic,
    sqlite_maintenance_deadline,
)
from codex_plugin_scanner.guard.store import GuardStore


def _publisher(tmp_path, monkeypatch):
    monkeypatch.setattr(publisher_module, "refresh_source_requirement", lambda _: None)
    home = tmp_path / "guard"
    home.mkdir(mode=0o700)
    publisher = publisher_module.NativePolicySnapshotPublisher(
        store=cast(GuardStore, cast(object, SimpleNamespace(guard_home=home)))
    )
    lookup = mutation.capture_native_publisher_lookup(home, deadline_monotonic=time.monotonic() + 1)
    publisher._acked = True
    return home, publisher, lookup


def _hold(lock):
    entered = threading.Event()
    release = threading.Event()

    def hold():
        with lock:
            entered.set()
            assert release.wait(2)

    thread = threading.Thread(target=hold)
    thread.start()
    assert entered.wait(1)
    return release, thread


def test_actual_registry_lock_does_not_get_a_fresh_wait(tmp_path, monkeypatch):
    home, publisher, lookup = _publisher(tmp_path, monkeypatch)
    release, thread = _hold(snapshot._PUBLISHER_LOCK)
    began = time.monotonic()
    try:
        with pytest.raises(NativePolicySnapshotError, match="deadline_exceeded"):
            mutation.notify_native_policy_mutation_before_deadline(
                lookup, guard_home=home, deadline_monotonic=began + 0.03
            )
        assert time.monotonic() - began < 0.15
        assert publisher._acked is True
    finally:
        release.set()
        thread.join(1)
    publisher.close()


def test_actual_publisher_condition_does_not_get_a_fresh_wait(tmp_path, monkeypatch):
    home, publisher, lookup = _publisher(tmp_path, monkeypatch)
    release, thread = _hold(publisher._condition)
    began = time.monotonic()
    try:
        with pytest.raises(NativePolicySnapshotError, match="deadline_exceeded"):
            mutation.notify_native_policy_mutation_before_deadline(
                lookup, guard_home=home, deadline_monotonic=began + 0.03
            )
        assert time.monotonic() - began < 0.15
        assert publisher._acked is True
    finally:
        release.set()
        thread.join(1)
    mutation.notify_native_policy_mutation_before_deadline(
        lookup, guard_home=home, deadline_monotonic=time.monotonic() + 1
    )
    assert publisher._acked is False
    assert publisher._epoch == 1
    publisher.close()


def test_final_wake_does_not_resolve_again_and_expired_cleanup_is_best_effort(tmp_path, monkeypatch):
    home, publisher, lookup = _publisher(tmp_path, monkeypatch)
    original = Path.resolve
    monkeypatch.setattr(Path, "resolve", lambda *a, **k: pytest.fail("fresh cleanup resolve"))
    with pytest.raises(NativePolicySnapshotError, match="deadline_exceeded"):
        mutation.notify_native_policy_mutation_before_deadline(
            lookup, guard_home=home, deadline_monotonic=time.monotonic() - 1
        )
    assert publisher._acked is False
    assert publisher._epoch == 1
    monkeypatch.setattr(Path, "resolve", original)
    publisher.close()


def test_delayed_resolution_never_supplies_a_late_lookup(tmp_path, monkeypatch):
    original = Path.resolve
    finished = threading.Event()

    def resolve(path, *args, **kwargs):
        try:
            if path == tmp_path:
                time.sleep(0.12)
            return original(path, *args, **kwargs)
        finally:
            finished.set()

    monkeypatch.setattr(Path, "resolve", resolve)
    start = time.monotonic()
    with pytest.raises(NativePolicySnapshotError, match="deadline_exceeded"):
        mutation.capture_native_publisher_lookup(tmp_path, deadline_monotonic=start + 0.03)
    assert time.monotonic() - start < 0.10
    assert finished.wait(1)


def test_existing_key_owner_transfers_only_the_deadline_context(tmp_path):
    unrelated = contextvars.ContextVar("unrelated-maintenance-context", default="default")
    unrelated.set("caller")
    deadline = time.monotonic() + 1
    observed = []

    def material(*, create):
        observed.append((create, sqlite_deadline_monotonic(), unrelated.get()))
        return b"k" * 32, "test-key"

    store = cast(GuardStore, cast(object, SimpleNamespace(_policy_integrity_secret_material=material)))
    with sqlite_maintenance_deadline(deadline):
        assert mutation.existing_native_policy_key(store, deadline_monotonic=deadline) == b"k" * 32
    assert observed == [(False, deadline, "default")]


def test_late_existing_key_result_never_reaches_authority_control():
    finished = threading.Event()
    observed = []

    def material(*, create):
        try:
            observed.append(create)
            time.sleep(0.12)
            return b"k" * 32, "test-key"
        finally:
            finished.set()

    store = cast(GuardStore, cast(object, SimpleNamespace(_policy_integrity_secret_material=material)))
    start = time.monotonic()
    with pytest.raises(NativePolicySnapshotError, match="deadline_exceeded"):
        mutation.existing_native_policy_key(store, deadline_monotonic=start + 0.03)
    assert time.monotonic() - start < 0.10
    assert finished.wait(1)
    assert observed == [False]


def test_actual_commit_before_wake_timeout_is_not_rollback(tmp_path, monkeypatch):
    home, publisher, lookup = _publisher(tmp_path, monkeypatch)
    store = GuardStore(home)
    original = store.get_device_metadata()["installation_id"]
    release, thread = _hold(snapshot._PUBLISHER_LOCK)
    deadline = time.monotonic() + 0.05
    try:
        with pytest.raises(NativePolicySnapshotError, match="deadline_exceeded"):
            with sqlite_maintenance_deadline(deadline), store._connect() as connection:
                assert isinstance(connection, DeadlineConnection)
                connection.begin_immediate()
                connection.execute("update guard_devices set installation_id='committed-maintenance'")
            mutation.notify_native_policy_mutation_before_deadline(lookup, guard_home=home, deadline_monotonic=deadline)
    finally:
        release.set()
        thread.join(1)
    assert store.get_device_metadata()["installation_id"] == "committed-maintenance"
    assert original != "committed-maintenance"
    publisher.close()


def test_lookup_subject_mismatch_never_invalidates_another_home(tmp_path, monkeypatch):
    home, publisher, lookup = _publisher(tmp_path, monkeypatch)
    with pytest.raises(NativePolicySnapshotError, match="subject_changed"):
        mutation.notify_native_policy_mutation_before_deadline(
            lookup, guard_home=home / "other", deadline_monotonic=time.monotonic() + 1
        )
    assert publisher._acked is True
    publisher.close()
