"""Complete native state writes and continuous Windows directory ownership."""

from __future__ import annotations

import errno
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_policy_snapshot as snapshot
from codex_plugin_scanner.guard import native_policy_snapshot_storage as storage
from codex_plugin_scanner.guard import native_policy_snapshot_windows_atomic as atomic
from codex_plugin_scanner.guard import native_policy_snapshot_windows_io as windows_io


@pytest.mark.skipif(os.name == "nt", reason="Exercises POSIX descriptor writes")
def test_generation_state_completes_actual_short_writes(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    actual_write = os.write
    accepted = []

    def short_write(descriptor, payload):
        count = actual_write(descriptor, payload[:7])
        accepted.append(count)
        return count

    monkeypatch.setattr(storage.os, "write", short_write)
    storage._write_v3_generation_state(tmp_path, generation=3, policy_digest="a" * 64)

    assert storage._read_v3_generation_state(tmp_path) == (3, "a" * 64)
    assert len(accepted) > 1
    assert sum(accepted) > 7
    assert not list(tmp_path.glob("*.tmp"))


@pytest.mark.skipif(os.name == "nt", reason="Exercises POSIX descriptor writes")
@pytest.mark.parametrize("failure", ("zero", "error", "interrupted"))
def test_incomplete_generation_write_preserves_prior_state(tmp_path, monkeypatch, failure):
    tmp_path.chmod(0o700)
    storage._write_v3_generation_state(tmp_path, generation=3, policy_digest="a" * 64)
    actual_write = os.write
    accepted = []

    def fail_after_prefix(descriptor, payload):
        if not accepted:
            count = actual_write(descriptor, payload[:7])
            accepted.append(count)
            return count
        if failure == "zero":
            return 0
        if failure == "interrupted":
            raise InterruptedError(errno.EINTR, "injected interrupted write")
        raise OSError(errno.ENOSPC, "injected full disk")

    monkeypatch.setattr(storage.os, "write", fail_after_prefix)
    with pytest.raises(snapshot.NativePolicySnapshotError, match="generation_state_write_failed"):
        storage._write_v3_generation_state(tmp_path, generation=4, policy_digest="b" * 64)

    assert accepted == [7]
    assert storage._read_v3_generation_state(tmp_path) == (3, "a" * 64)
    assert not list(tmp_path.glob("*.tmp"))


@pytest.mark.skipif(os.name == "nt", reason="Exercises POSIX file synchronization")
def test_generation_sync_failure_preserves_prior_state(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    storage._write_v3_generation_state(tmp_path, generation=3, policy_digest="a" * 64)
    synchronized_sizes = []

    def fail_sync(descriptor):
        synchronized_sizes.append(os.fstat(descriptor).st_size)
        raise OSError(errno.EIO, "injected synchronization failure")

    monkeypatch.setattr(storage.os, "fsync", fail_sync)
    with pytest.raises(snapshot.NativePolicySnapshotError, match="generation_state_write_failed"):
        storage._write_v3_generation_state(tmp_path, generation=4, policy_digest="b" * 64)

    assert len(synchronized_sizes) == 1
    assert synchronized_sizes[0] > 7
    assert storage._read_v3_generation_state(tmp_path) == (3, "a" * 64)
    assert not list(tmp_path.glob("*.tmp"))


def _information(identity):
    return SimpleNamespace(dwVolumeSerialNumber=7, nFileIndexHigh=0, nFileIndexLow=identity)


class _ParentHandoff:
    """Deterministic adversary replaces any parent with no retained barrier."""

    def __init__(
        self,
        *,
        wrong_initial=False,
        wrong_restoration=False,
        rename_failure=False,
        restore_failure=False,
        close_failure=False,
    ):
        self.current_identity = 11
        self.live = {1: 11}
        self.handles = [(self, 1)]
        self.next_handle = 2
        self.replacements = 0
        self.rename_identity = None
        self.closed = []
        self.wrong_restoration = wrong_restoration
        self.wrong_initial = wrong_initial
        self.rename_failure = rename_failure
        self.restore_failure = restore_failure
        self.close_failure = close_failure

    def _windows_open_handle(self, path, *, directory, rename_parent=False, **kwargs):
        assert directory
        if kwargs.get("lock") and self.restore_failure:
            raise snapshot.NativePolicySnapshotError("injected_restore_failure")
        wrong_identity = (rename_parent and self.wrong_initial) or (kwargs.get("lock") and self.wrong_restoration)
        identity = 99 if wrong_identity else self.current_identity
        handle = self.next_handle
        self.next_handle += 1
        self.live[handle] = identity
        return self, handle, _information(identity)

    def _windows_close_handle(self, kernel, handle):
        assert kernel is self
        del self.live[handle]
        self.closed.append(handle)
        if not self.live:
            self.current_identity += 1
            self.replacements += 1
        if handle == 2 and self.close_failure:
            raise snapshot.NativePolicySnapshotError("injected_close_failure")

    def rename(self, kernel, source, parent, name, *, replace_if_exists):
        assert kernel is self
        self.rename_identity = self.live[parent]
        if self.rename_failure:
            raise snapshot.NativePolicySnapshotError("injected_rename_failure")

    def run(self, monkeypatch):
        monkeypatch.setattr(atomic, "_windows_rename_file_handle", self.rename)
        monkeypatch.setattr(atomic, "_windows_parent_identity", lambda api, kernel, handle: (7, 0, self.live[handle]))
        atomic._windows_rename_releasing_barrier(
            api=self,
            kernel32=self,
            source_handle=100,
            parent_path=Path("C:/Guard/native-runtime"),
            parent_handle=1,
            destination_name="state.json",
            replace_existing=True,
            directory_handles=self.handles,
        )


def test_windows_parent_handoff_never_exposes_an_unbound_parent(monkeypatch):
    handoff = _ParentHandoff()
    handoff.run(monkeypatch)

    assert handoff.replacements == 0
    assert handoff.rename_identity == 11
    assert len(handoff.handles) == 1
    assert handoff.live[handoff.handles[0][1]] == 11


def test_windows_parent_handoff_rejects_wrong_restoration_identity(monkeypatch):
    handoff = _ParentHandoff(wrong_restoration=True)
    with pytest.raises(snapshot.NativePolicySnapshotError, match="parent_identity_failed"):
        handoff.run(monkeypatch)
    assert not handoff.handles
    assert not handoff.live


def test_windows_parent_handoff_rejects_redirected_initial_open_before_releasing_original(monkeypatch):
    handoff = _ParentHandoff(wrong_initial=True)
    with pytest.raises(snapshot.NativePolicySnapshotError, match="parent_identity_failed"):
        handoff.run(monkeypatch)
    assert handoff.rename_identity is None
    assert handoff.handles == [(handoff, 1)]
    assert handoff.live == {1: 11}
    assert handoff.closed == [2]


@pytest.mark.parametrize("kind", ("directory", "reparse", "file", "failure"))
def test_windows_original_parent_identity_reads_the_held_handle(kind):
    import ctypes
    from ctypes import wintypes

    information_type = snapshot._windows_file_information_type()
    api = SimpleNamespace(_windows_file_information_type=lambda: information_type)
    observed = []

    def read_information(handle, output):
        observed.append(handle)
        information = ctypes.cast(output, ctypes.POINTER(information_type)).contents
        information.dwVolumeSerialNumber = 7
        information.nFileIndexHigh = 8
        information.nFileIndexLow = 9
        information.dwFileAttributes = {
            "directory": snapshot._WINDOWS_FILE_ATTRIBUTE_DIRECTORY,
            "reparse": snapshot._WINDOWS_FILE_ATTRIBUTE_DIRECTORY | snapshot._WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT,
            "file": 0,
            "failure": 0,
        }[kind]
        return kind != "failure"

    kernel = SimpleNamespace(GetFileInformationByHandle=read_information)
    if kind == "directory":
        assert atomic._windows_parent_identity(api, kernel, 73) == (7, 8, 9)
    else:
        with pytest.raises(snapshot.NativePolicySnapshotError, match="parent_identity_failed"):
            atomic._windows_parent_identity(api, kernel, 73)
    assert observed == [73]
    assert read_information.argtypes == [wintypes.HANDLE, ctypes.POINTER(information_type)]
    assert read_information.restype is wintypes.BOOL


def test_windows_parent_handoff_preserves_rename_failure_when_restore_also_fails(monkeypatch):
    handoff = _ParentHandoff(rename_failure=True, restore_failure=True)
    with pytest.raises(snapshot.NativePolicySnapshotError, match="injected_rename_failure"):
        handoff.run(monkeypatch)
    assert not handoff.handles
    assert not handoff.live


def test_windows_parent_handoff_preserves_rename_failure_when_close_also_fails(monkeypatch):
    handoff = _ParentHandoff(rename_failure=True, close_failure=True)
    with pytest.raises(snapshot.NativePolicySnapshotError, match="injected_rename_failure"):
        handoff.run(monkeypatch)
    assert len(handoff.handles) == 1
    assert len(handoff.live) == 1


def test_windows_rename_parent_configuration_retains_no_delete_barrier():
    config = windows_io._windows_open_configuration(
        snapshot,
        directory=True,
        create_new=False,
        descriptor=None,
        repair=False,
        lock=False,
        rename_source=False,
        add_file=False,
        share_delete=False,
        rename_parent=True,
    )
    assert config.desired_access == snapshot._WINDOWS_FILE_TRAVERSE | snapshot._WINDOWS_FILE_READ_ATTRIBUTES
    assert config.share_mode == snapshot._WINDOWS_FILE_SHARE_READ | snapshot._WINDOWS_FILE_SHARE_WRITE
    assert config.flags & snapshot._WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT
    assert config.flags & snapshot._WINDOWS_FILE_FLAG_BACKUP_SEMANTICS


@pytest.mark.skipif(os.name != "nt", reason="Requires actual Windows directory sharing semantics")
def test_windows_actual_directory_replacement_is_refused_during_handoff(tmp_path, monkeypatch):
    parent = tmp_path / "state"
    parent.mkdir()
    kernel, initial, _ = snapshot._windows_open_handle(parent, directory=True, lock=True, add_file=True)
    handles = [(kernel, initial)]
    attempted = []
    actual_close = snapshot._windows_close_handle

    def close_and_attempt_replace(closed_kernel, handle):
        actual_close(closed_kernel, handle)
        if handle == initial:
            attempted.append(True)
            with pytest.raises(OSError):
                parent.rename(tmp_path / "moved-state")

    monkeypatch.setattr(snapshot, "_windows_close_handle", close_and_attempt_replace)
    monkeypatch.setattr(atomic, "_windows_rename_file_handle", lambda *_args, **_kwargs: None)
    try:
        atomic._windows_rename_releasing_barrier(
            api=snapshot,
            kernel32=kernel,
            source_handle=100,
            parent_path=parent,
            parent_handle=initial,
            destination_name="state.json",
            replace_existing=True,
            directory_handles=handles,
        )
    finally:
        for held_kernel, held_handle in handles:
            actual_close(held_kernel, held_handle)
    assert attempted == [True]
    assert parent.is_dir()
    assert not (tmp_path / "moved-state").exists()


@pytest.mark.skipif(os.name != "nt", reason="Requires actual Windows private atomic file replacement")
def test_windows_actual_atomic_replacement_with_overlapping_parent_handles(tmp_path):
    parent = tmp_path / "guard-home"
    for generation in (1, 2):
        storage._write_v3_generation_state(parent, generation=generation, policy_digest="a" * 64)
        assert storage._read_v3_generation_state(parent) == (generation, "a" * 64)
