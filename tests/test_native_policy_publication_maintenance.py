from __future__ import annotations

import multiprocessing
import threading
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_policy_publication_lock as ordinary
from codex_plugin_scanner.guard import native_policy_publication_maintenance as maintenance
from codex_plugin_scanner.guard.native_policy_control_transport import run_native_control_worker
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_maintenance import capture_store_maintenance_lookup, store_maintenance_scope
from tests.test_native_policy_control_owned_operations import _lock_competitor


def _binding(home):
    return maintenance.capture_publication_mutation_binding(
        home, cancelled=threading.Event(), deadline_monotonic=time.monotonic() + 1
    )


def test_bound_lock_preserves_existing_reentrant_process_identity(tmp_path, monkeypatch):
    binding = _binding(tmp_path)
    original = ordinary.hold_storage_file_lock
    calls = []

    def hold(*args, **kwargs):
        calls.append(kwargs)
        return original(*args, **kwargs)

    monkeypatch.setattr(ordinary, "hold_storage_file_lock", hold)
    monkeypatch.setattr(maintenance, "hold_storage_file_lock", hold)
    deadline = time.monotonic() + 1
    for first in ("ordinary", "bound"):
        contexts = [
            ordinary.hold_policy_publication_mutation(tmp_path),
            maintenance.hold_bound_policy_publication_mutation(
                binding, guard_home=tmp_path, cancelled=threading.Event(), deadline_monotonic=deadline
            ),
        ]
        if first == "bound":
            contexts.reverse()
        with contexts[0], contexts[1]:
            pass
    assert len(calls) == 2
    assert calls[1]["deadline_monotonic"] == deadline
    assert calls[1]["timeout_seconds"] <= 1


def test_bound_lock_does_not_resolve_again(tmp_path, monkeypatch):
    binding = _binding(tmp_path)
    monkeypatch.setattr(Path, "resolve", lambda *a, **k: pytest.fail("fresh resolution"))
    with maintenance.hold_bound_policy_publication_mutation(
        binding, guard_home=tmp_path, cancelled=threading.Event(), deadline_monotonic=time.monotonic() + 1
    ):
        pass


def test_replaced_directory_cannot_reuse_captured_binding(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    binding = _binding(home)
    home.rename(tmp_path / "old")
    home.mkdir()
    with (
        pytest.raises(NativePolicySnapshotError, match="subject_changed"),
        maintenance.hold_bound_policy_publication_mutation(
            binding, guard_home=home, cancelled=threading.Event(), deadline_monotonic=time.monotonic() + 1
        ),
    ):
        pytest.fail("redirected directory admitted")
    assert not (home / "native-policy-publication.lock").exists()


def test_delayed_setup_never_enters_lock_after_caller_expiry(tmp_path, monkeypatch):
    original = Path.resolve
    finished = threading.Event()

    def resolve(path, *a, **k):
        try:
            time.sleep(0.1)
            return original(path, *a, **k)
        finally:
            finished.set()

    monkeypatch.setattr(Path, "resolve", resolve)
    monkeypatch.setattr(maintenance, "hold_storage_file_lock", lambda *a, **k: pytest.fail("late lock"))
    deadline = time.monotonic() + 0.03

    def run(cancelled):
        binding = maintenance.capture_publication_mutation_binding(
            tmp_path, cancelled=cancelled, deadline_monotonic=deadline
        )
        with maintenance.hold_bound_policy_publication_mutation(
            binding, guard_home=tmp_path, cancelled=cancelled, deadline_monotonic=deadline
        ):
            pytest.fail("late SQL")

    assert run_native_control_worker(run, deadline_monotonic=deadline) is None
    assert finished.wait(1)
    assert not (tmp_path / "native-policy-publication.lock").exists()


@pytest.mark.parametrize("stage", ["permission", "integrity-notification"])
def test_real_postcommit_cleanup_retains_serialization(tmp_path, monkeypatch, stage):
    store = GuardStore(tmp_path / "guard")
    context = multiprocessing.get_context("spawn")
    parent_channel, child_channel = context.Pipe()
    child = context.Process(target=_lock_competitor, args=(str(store.guard_home), child_channel))
    child.start()
    assert parent_channel.poll(5) and parent_channel.recv() == "ready"
    entered = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    original = store._repair_store_permissions

    def repair():
        entered.set()
        assert release.wait(2)
        original()

    if stage == "permission":
        monkeypatch.setattr(store, "_repair_store_permissions", repair)
    else:
        store.set_policy_integrity_state_listener(lambda payload: repair())
    deadline = time.monotonic() + 0.1

    def run(cancelled):
        try:
            binding = maintenance.capture_publication_mutation_binding(
                store.guard_home, cancelled=cancelled, deadline_monotonic=deadline
            )
            lookup = capture_store_maintenance_lookup(store.path, cancelled=cancelled, deadline_monotonic=deadline)
            with (
                maintenance.hold_bound_policy_publication_mutation(
                    binding, guard_home=store.guard_home, cancelled=cancelled, deadline_monotonic=deadline
                ),
                store_maintenance_scope(store.path, lookup, deadline_monotonic=deadline),
                store._connect() as connection,
            ):
                connection.execute("update guard_devices set installation_id='committed-before-timeout'")
                if stage == "integrity-notification":
                    store._queue_policy_integrity_state_notification(connection, {"test": True})
        finally:
            finished.set()

    try:
        assert run_native_control_worker(run, deadline_monotonic=deadline) is None
        assert entered.is_set()
        parent_channel.send("try")
        assert parent_channel.poll(1) and parent_channel.recv() is False
        release.set()
        assert finished.wait(1)
        parent_channel.send("try")
        assert parent_channel.poll(1) and parent_channel.recv() is True
        monkeypatch.setattr(store, "_repair_store_permissions", original)
        assert store.get_device_metadata()["installation_id"] == "committed-before-timeout"
    finally:
        release.set()
        parent_channel.send("stop")
        child.join(2)
        if child.is_alive():
            child.terminate()
            child.join(2)
        parent_channel.close()
        child_channel.close()
