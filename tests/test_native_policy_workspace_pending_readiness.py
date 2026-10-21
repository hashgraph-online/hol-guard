"""A new workspace gates only its own hooks until its overlay is ACKed."""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import hook_worker as worker_module
from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.store import GuardStore

from .native_policy_snapshot_test_fixtures import _ack, _status


class _Resident:
    """Fake resident that ACKs every push and can hold one push open."""

    def __init__(self) -> None:
        self.calls = 0
        self.hold = False
        self.entered = threading.Event()
        self.release = threading.Event()

    def __call__(self, **kwargs: object) -> bytes:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        self.calls += 1
        if self.hold:
            self.entered.set()
            assert self.release.wait(2.0)
        return _ack(payload, guard_home=kwargs.get("guard_home"))


def _published(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[NativePolicySnapshotPublisher, _Resident, Path]:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda *, create: (b"w" * 32, "master-id"))
    resident = _Resident()
    publisher = NativePolicySnapshotPublisher(
        store=store, status_provider=_status, client_request=resident, poll_interval_seconds=0.05
    )
    existing = tmp_path / "existing"
    existing.mkdir()
    assert publisher.register_workspace(existing)
    publisher._publish_once()
    assert publisher.current_snapshot_binding() is not None
    return publisher, resident, existing


def _overlay(workspace: Path) -> None:
    """Give a new workspace its own overlay, so its hooks need its own ACK."""

    (workspace / ".hol-guard.toml").write_text('sandbox_analysis = "strict"\n', encoding="utf-8")


def test_new_workspace_keeps_existing_workspace_ready_and_epoch_stable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    publisher, _resident, existing = _published(tmp_path, monkeypatch)
    try:
        binding = publisher.current_snapshot_binding()
        epoch = publisher._epoch
        new = tmp_path / "new"
        new.mkdir()
        _overlay(new)
        assert publisher.register_workspace(new)

        assert publisher._epoch == epoch, "Registering a workspace must not discard in-flight ACKs"
        assert publisher.current_snapshot_binding() == binding, "Existing workspaces keep the ACKed binding"
        assert publisher.wait_until_ready(time.monotonic() + 0.05, workspace=existing)
        assert not publisher.workspace_policy_pending(existing)
        assert publisher.workspace_policy_pending(new)
        assert not publisher.wait_until_ready(time.monotonic() + 0.05, workspace=new)
    finally:
        publisher.close()


def test_in_flight_ack_without_new_workspace_does_not_release_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    publisher, resident, existing = _published(tmp_path, monkeypatch)
    publisher.request_publish()
    resident.hold = True
    new = tmp_path / "new"
    new.mkdir()
    _overlay(new)
    publish = threading.Thread(target=publisher._publish_once)
    publish.start()
    try:
        assert resident.entered.wait(2.0)
        assert publisher.register_workspace(new)
        resident.release.set()
        publish.join(timeout=2.0)
        assert not publish.is_alive()

        assert publisher.current_snapshot_binding() is not None, "The in-flight ACK must not be discarded"
        assert publisher.wait_until_ready(time.monotonic() + 0.05, workspace=existing)
        assert publisher.workspace_policy_pending(new), "An ACK compiled before registration lacks the overlay"
        assert publisher._publish_event.is_set(), "The missing overlay must be requeued"

        resident.hold = False
        publisher._publish_once()
        assert not publisher.workspace_policy_pending(new)
        assert publisher.wait_until_ready(time.monotonic() + 0.05, workspace=new)
    finally:
        resident.release.set()
        publish.join(timeout=2.0)
        publisher.close()


def test_hook_worker_admits_existing_workspace_and_holds_new_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    publisher, _resident, existing = _published(tmp_path, monkeypatch)
    monkeypatch.setattr(publisher, "start", lambda: None)
    monkeypatch.setattr(worker_module, "get_native_policy_snapshot_publisher", lambda store: publisher)
    worker = worker_module.HookWorker(store=publisher.store, wait_for_native_policy=False)
    new = tmp_path / "new"
    new.mkdir()
    _overlay(new)
    try:
        assert worker.prepare_workspace_policy(new, deadline=time.monotonic() + 0.1) is None
        started = time.monotonic()
        binding = worker.prepare_workspace_policy(existing, deadline=time.monotonic() + 2.0)
        assert binding is not None
        assert time.monotonic() - started < 0.5, "An existing workspace must not wait for another overlay"
        assert worker.prepare_workspace_policy(new, deadline=time.monotonic() + 0.1) is None

        publisher._publish_once()
        assert worker.prepare_workspace_policy(new, deadline=time.monotonic() + 0.5) is not None
    finally:
        publisher.close()


def test_stricter_pending_overlay_does_not_withdraw_ack_in_background_loop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    publisher, resident, existing = _published(tmp_path, monkeypatch)
    first, stricter = tmp_path / "first", tmp_path / "stricter"
    first.mkdir()
    stricter.mkdir()
    # An overlay makes `first` a workspace of its own, so it needs a publish.
    (first / ".hol-guard.toml").write_text("", encoding="utf-8")
    (stricter / ".hol-guard.toml").write_text('sandbox_analysis = "strict"\n', encoding="utf-8")
    publisher.start()
    try:
        assert publisher.wait_until_ready(time.monotonic() + 5.0, workspace=existing)
        republished: list[None] = []
        original_request_publish = publisher.request_publish

        def spy_request_publish() -> None:
            republished.append(None)
            original_request_publish()

        monkeypatch.setattr(publisher, "request_publish", spy_request_publish)
        epoch = publisher._epoch
        resident.hold = True
        assert publisher.register_workspace(first)
        assert resident.entered.wait(2.0)
        # Arrives while a publish is in flight, so it is still pending when
        # the loop reconciles effective inputs right after that ACK commits.
        assert publisher.register_workspace(stricter)
        with publisher._condition:
            publisher._reconcile_due_monotonic = 0.0
        resident.hold = False
        resident.release.set()

        assert publisher.wait_until_ready(time.monotonic() + 5.0, workspace=stricter)
        assert publisher.wait_until_ready(time.monotonic() + 0.05, workspace=existing)
        assert republished == [], "A pending overlay must not withdraw the ACK home-wide"
        assert publisher._epoch == epoch
    finally:
        resident.release.set()
        publisher.close()


def test_pending_overlay_paths_are_not_effective_input_changes_but_compiled_ones_are(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    publisher, _resident, existing = _published(tmp_path, monkeypatch)
    try:
        new = tmp_path / "new"
        new.mkdir()
        overlay = new / ".hol-guard.toml"
        overlay.write_text('sandbox_analysis = "strict"\n', encoding="utf-8")
        assert publisher.register_workspace(new)

        assert not publisher._policy_input_changed({str(overlay)})
        assert not publisher._policy_input_changed()
        assert publisher.wait_until_ready(time.monotonic() + 0.05, workspace=existing)

        existing_overlay = existing / ".hol-guard.toml"
        existing_overlay.write_text('sandbox_analysis = "strict"\n', encoding="utf-8")
        assert publisher._policy_input_changed({str(existing_overlay)})
        assert not publisher.wait_until_ready(time.monotonic() + 0.05, workspace=existing)
    finally:
        publisher.close()


def test_new_workspace_waits_for_its_publish_despite_a_stale_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    publisher, _resident, _existing = _published(tmp_path, monkeypatch)
    monkeypatch.setattr(publisher, "start", lambda: None)
    monkeypatch.setattr(worker_module, "get_native_policy_snapshot_publisher", lambda store: publisher)
    worker = worker_module.HookWorker(store=publisher.store, wait_for_native_policy=False)
    publisher._record_error("native_policy_snapshot_runtime_unavailable")
    new = tmp_path / "new"
    new.mkdir()
    _overlay(new)
    waiting = threading.Event()
    original_wait = publisher.wait_until_ready

    def wait(deadline: float, *, workspace: Path | None = None) -> bool:
        waiting.set()
        return original_wait(deadline, workspace=workspace)

    monkeypatch.setattr(publisher, "wait_until_ready", wait)

    def publish_when_waiting() -> None:
        if waiting.wait(2.0):
            publisher._publish_once()

    publish = threading.Thread(target=publish_when_waiting)
    publish.start()
    try:
        binding = worker.prepare_workspace_policy(new, deadline=time.monotonic() + 2.0)
        assert binding is not None, "The queued workspace publish supersedes the earlier error"
        assert not publisher.workspace_policy_pending(new)
    finally:
        waiting.set()
        publish.join(timeout=2.0)
        publisher.close()


def test_workspace_registered_after_capture_is_not_compiled_into_the_ack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    publisher, _resident, existing = _published(tmp_path, monkeypatch)
    late = tmp_path / "late"
    late.mkdir()
    (late / ".hol-guard.toml").write_text('sandbox_analysis = "strict"\n', encoding="utf-8")
    original_context = publisher._publication_context

    def register_during_publication(**kwargs: object) -> object:
        # Arrives after the publish captured its workspace set but before
        # the policy is compiled.
        assert publisher.register_workspace(late)
        return original_context(**kwargs)

    monkeypatch.setattr(publisher, "_publication_context", register_during_publication)
    publisher.request_publish()
    try:
        publisher._publish_once()
        assert publisher.workspace_policy_pending(late)
        assert not publisher._policy_input_changed(), "The ACK must match the settled-only reconcile"
        assert publisher.wait_until_ready(time.monotonic() + 0.05, workspace=existing)

        monkeypatch.setattr(publisher, "_publication_context", original_context)
        publisher._publish_once()
        assert not publisher.workspace_policy_pending(late)
        assert not publisher._policy_input_changed()
    finally:
        publisher.close()


def _subdirectory_worker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[NativePolicySnapshotPublisher, worker_module.HookWorker, Path]:
    publisher, _resident, existing = _published(tmp_path, monkeypatch)
    monkeypatch.setattr(publisher, "start", lambda: None)
    monkeypatch.setattr(worker_module, "get_native_policy_snapshot_publisher", lambda store: publisher)
    return publisher, worker_module.HookWorker(store=publisher.store, wait_for_native_policy=False), existing


def test_file_less_subdirectory_uses_the_current_ack_while_it_publishes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    publisher, worker, existing = _subdirectory_worker(tmp_path, monkeypatch)
    nested = existing / "src" / "pkg"
    nested.mkdir(parents=True)
    try:
        binding = publisher.current_snapshot_binding()
        started = time.monotonic()
        assert worker.prepare_workspace_policy(nested, deadline=time.monotonic() + 2.0) == binding
        assert time.monotonic() - started < 0.5, "A covered subdirectory must not wait for its own publish"
        assert publisher.workspace_policy_pending(nested), "The next publish still compiles the subdirectory"

        publisher._publish_once()
        assert not publisher.workspace_policy_pending(nested)
    finally:
        publisher.close()


def test_file_less_subdirectory_does_not_renew_the_acked_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    publisher, _resident, existing = _published(tmp_path, monkeypatch)
    monkeypatch.setattr(worker_module, "get_native_policy_snapshot_publisher", lambda store: publisher)
    worker = worker_module.HookWorker(store=publisher.store, wait_for_native_policy=False)
    publisher.start()
    nested = existing / "src" / "pkg"
    nested.mkdir(parents=True)
    try:
        assert publisher.wait_until_ready(time.monotonic() + 5.0, workspace=existing)
        binding = publisher.current_snapshot_binding()
        started = time.monotonic()
        assert worker.prepare_workspace_policy(nested, deadline=time.monotonic() + 2.0) == binding
        assert time.monotonic() - started < 0.5
        assert publisher._renewal_after_generation is None
        # The publisher thread is live. A queued renewal would replace this ACK.
        time.sleep(0.6)
        assert publisher.current_snapshot_binding() == binding
        assert publisher.workspace_policy_pending(nested)
    finally:
        publisher.close()


def test_deferred_subdirectory_that_gains_an_overlay_queues_its_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    publisher, worker, existing = _subdirectory_worker(tmp_path, monkeypatch)
    nested = existing / "src"
    nested.mkdir()
    try:
        assert worker.prepare_workspace_policy(nested, deadline=time.monotonic() + 2.0) is not None
        publisher._publish_event.clear()

        (nested / ".hol-guard.toml").write_text('sandbox_analysis = "strict"\n', encoding="utf-8")
        assert worker.prepare_workspace_policy(nested, deadline=time.monotonic() + 0.1) is None
        assert publisher._publish_event.is_set(), "The new overlay must queue its own publish"

        publisher._publish_once()
        assert not publisher.workspace_policy_pending(nested)
        assert worker.prepare_workspace_policy(nested, deadline=time.monotonic() + 0.5) is not None
    finally:
        publisher.close()


@pytest.mark.parametrize("overlay", [".hol-guard.toml", ".ai-plugin-scanner-guard.toml"])
def test_subdirectory_with_its_own_overlay_waits_for_its_ack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, overlay: str
) -> None:
    publisher, worker, existing = _subdirectory_worker(tmp_path, monkeypatch)
    nested = existing / "src"
    nested.mkdir()
    (nested / overlay).write_text('sandbox_analysis = "strict"\n', encoding="utf-8")
    try:
        assert worker.prepare_workspace_policy(nested, deadline=time.monotonic() + 0.1) is None
        assert not publisher.workspace_admissible_without_overlay(nested)
    finally:
        publisher.close()


def test_unrelated_file_less_workspace_uses_the_current_ack(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    publisher, worker, _existing = _subdirectory_worker(tmp_path, monkeypatch)
    sibling = tmp_path / "sibling"
    sibling.mkdir()
    try:
        binding = publisher.current_snapshot_binding()
        started = time.monotonic()
        assert worker.prepare_workspace_policy(sibling, deadline=time.monotonic() + 2.0) == binding
        assert time.monotonic() - started < 0.5, "A file-less workspace adds only the home config"
        assert publisher.workspace_policy_pending(sibling), "The next publish still compiles the workspace"

        publisher._publish_once()
        assert not publisher.workspace_policy_pending(sibling)
    finally:
        publisher.close()


@pytest.mark.parametrize("overlay", [".hol-guard.toml", ".ai-plugin-scanner-guard.toml"])
def test_workspace_below_an_unsettled_overlay_waits_for_its_ack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, overlay: str
) -> None:
    publisher, worker, _existing = _subdirectory_worker(tmp_path, monkeypatch)
    parent = tmp_path / "parent"
    nested = parent / "src"
    nested.mkdir(parents=True)
    (parent / overlay).write_text('sandbox_analysis = "strict"\n', encoding="utf-8")
    try:
        assert worker.prepare_workspace_policy(nested, deadline=time.monotonic() + 0.1) is None
        assert not publisher.workspace_admissible_without_overlay(nested)
    finally:
        publisher.close()


def test_subdirectory_of_a_pending_workspace_is_not_covered(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    publisher, worker, _existing = _subdirectory_worker(tmp_path, monkeypatch)
    parent = tmp_path / "parent"
    nested = parent / "src"
    nested.mkdir(parents=True)
    (parent / ".hol-guard.toml").write_text('sandbox_analysis = "strict"\n', encoding="utf-8")
    try:
        assert publisher.register_workspace(parent)
        assert worker.prepare_workspace_policy(nested, deadline=time.monotonic() + 0.1) is None
    finally:
        publisher.close()


def test_linked_subdirectory_still_waits_for_its_ack(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    publisher, worker, existing = _subdirectory_worker(tmp_path, monkeypatch)
    target = tmp_path / "elsewhere"
    target.mkdir()
    linked = existing / "linked"
    try:
        linked.symlink_to(target, target_is_directory=True)
    except OSError:
        publisher.close()
        pytest.skip("symlinks unavailable")
    try:
        assert worker.prepare_workspace_policy(linked, deadline=time.monotonic() + 0.1) is None
        assert worker.prepare_workspace_policy(existing / "linked" / "..", deadline=time.monotonic() + 0.1) is None
    finally:
        publisher.close()


def _windows_short_path(path: Path) -> str:
    import ctypes

    buffer = ctypes.create_unicode_buffer(1024)
    length = ctypes.windll.kernel32.GetShortPathNameW(str(path), buffer, len(buffer))
    return buffer.value if 0 < length < len(buffer) else str(path)


@pytest.mark.skipif(os.name != "nt", reason="Windows path spellings")
def test_windows_short_and_case_spellings_of_a_file_less_workspace_use_the_current_ack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    publisher, worker, _existing = _subdirectory_worker(tmp_path, monkeypatch)
    workspace = tmp_path / "file-less-workspace-with-a-long-name"
    workspace.mkdir()
    spellings = [Path(str(workspace).swapcase())]
    short = _windows_short_path(workspace)
    if short != str(workspace):
        spellings.append(Path(short))
    try:
        binding = publisher.current_snapshot_binding()
        for spelled in spellings:
            started = time.monotonic()
            assert worker.prepare_workspace_policy(spelled, deadline=time.monotonic() + 2.0) == binding, spelled
            assert time.monotonic() - started < 0.5, f"{spelled} names the same directory without a link"
    finally:
        publisher.close()


@pytest.mark.skipif(os.name != "nt", reason="Windows junctions")
def test_windows_junction_subdirectory_still_waits_for_its_ack(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import _winapi

    publisher, worker, existing = _subdirectory_worker(tmp_path, monkeypatch)
    target = tmp_path / "elsewhere"
    target.mkdir()
    junction = existing / "junction"
    _winapi.CreateJunction(str(target), str(junction))
    try:
        assert worker.prepare_workspace_policy(junction, deadline=time.monotonic() + 0.1) is None
        assert worker.prepare_workspace_policy(junction / "..", deadline=time.monotonic() + 0.1) is None
    finally:
        publisher.close()
