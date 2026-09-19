"""Private directory barriers admit config reads without granting child writes."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_policy_snapshot as snapshot
from codex_plugin_scanner.guard import native_policy_snapshot_constants as constants
from codex_plugin_scanner.guard import native_policy_snapshot_windows_atomic as atomic
from codex_plugin_scanner.guard import native_policy_snapshot_windows_io as windows_io
from codex_plugin_scanner.guard import native_policy_snapshot_windows_state as windows_state
from codex_plugin_scanner.guard.config_source_io import capture_guard_config
from codex_plugin_scanner.guard.native_command_control_authority_io import hold_command_control_authority_lock

_WINDOWS = pytest.mark.skipif(os.name != "nt", reason="Actual Windows configuration, ACL and directory sharing")
_CONFIG = b'default_action = "block"\n'


class _DirectoryReadOracle:
    """Apply the observed Windows write-data sharing rule to real open masks."""

    def __init__(self, *, repair: bool = False) -> None:
        self.needs_repair = repair
        self.live: dict[int, windows_io._WindowsOpenConfiguration] = {}
        self.opened: list[windows_io._WindowsOpenConfiguration] = []
        self.owners: list[int] = []
        self.verified: list[int] = []
        self.repaired: list[int] = []

    def _windows_open_handle(
        self,
        path: Path,
        *,
        directory: bool,
        repair: bool = False,
        lock: bool = False,
        add_file: bool = False,
        rename_parent: bool = False,
    ) -> tuple[_DirectoryReadOracle, int, SimpleNamespace]:
        del path
        config = windows_io._windows_open_configuration(
            snapshot,
            directory=directory,
            create_new=False,
            descriptor=None,
            repair=repair,
            lock=lock,
            rename_source=False,
            add_file=add_file,
            share_delete=False,
            rename_parent=rename_parent,
        )
        assert config.share_mode == constants._WINDOWS_FILE_SHARE_READ | constants._WINDOWS_FILE_SHARE_WRITE
        assert config.flags & constants._WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT
        assert config.flags & constants._WINDOWS_FILE_FLAG_BACKUP_SEMANTICS
        handle = len(self.opened) + 1
        self.opened.append(config)
        self.live[handle] = config
        information = SimpleNamespace(dwVolumeSerialNumber=7, nFileIndexHigh=0, nFileIndexLow=11)
        return self, handle, information

    def _windows_close_handle(self, kernel: _DirectoryReadOracle, handle: int) -> None:
        assert kernel is self
        del self.live[handle]

    def _windows_verify_private_owner(self, handle: int, *, owner_sid: str) -> None:
        assert owner_sid == "owner"
        self.owners.append(handle)

    def _windows_verify_private_dacl(self, handle: int, *, owner_sid: str, directory: bool) -> None:
        assert owner_sid == "owner" and directory
        self.verified.append(handle)
        if self.needs_repair:
            self.needs_repair = False
            raise snapshot.NativePolicySnapshotError("native_policy_windows_acl_not_private")

    def _windows_apply_private_dacl(
        self, kernel: _DirectoryReadOracle, handle: int, descriptor: str, dacl: str, directory: bool
    ) -> None:
        assert kernel is self and descriptor == "descriptor" and dacl == "dacl" and directory
        assert self.live[handle].desired_access & constants._WINDOWS_WRITE_DAC
        self.repaired.append(handle)
        self.require_config_reader_compatible()

    def require_config_reader_compatible(self) -> None:
        # capture_guard_config's parent reader shares only READ. A live
        # FILE_ADD_FILE / write-data handle makes that open fail with error 32.
        write_data = constants._WINDOWS_FILE_ADD_FILE | constants._WINDOWS_GENERIC_WRITE
        assert not any(config.desired_access & write_data for config in self.live.values())


@pytest.mark.parametrize(
    ("created", "private", "repair"),
    [(True, True, False), (False, True, False), (False, True, True), (False, False, False)],
)
def test_directory_binding_and_acl_repair_keep_config_reader_compatible(
    monkeypatch: pytest.MonkeyPatch, created: bool, private: bool, repair: bool
) -> None:
    api = _DirectoryReadOracle(repair=repair)
    monkeypatch.setattr(windows_state, "_windows_create_directory", lambda *_args: created)

    actual_created, (kernel, handle) = windows_state._windows_bind_directory_component(
        Path("guard-home"), api=api, descriptor="descriptor", dacl="dacl", owner_sid="owner", private=private
    )
    try:
        assert actual_created is created
        api.require_config_reader_compatible()
        assert len(api.opened) == (3 if repair else 1)
        assert api.live[handle].desired_access == constants._WINDOWS_GENERIC_READ
        assert bool(api.owners) is (private and not created)
        assert bool(api.verified) is private
        assert bool(api.repaired) is repair
    finally:
        api._windows_close_handle(kernel, handle)
    assert not api.live


@pytest.mark.parametrize("rename_failure", [False, True])
def test_atomic_handoff_restores_reader_compatible_barrier_even_on_failure(
    monkeypatch: pytest.MonkeyPatch, rename_failure: bool
) -> None:
    api = _DirectoryReadOracle()
    kernel, handle, _ = api._windows_open_handle(Path("state"), directory=True, lock=True)
    handles = [(kernel, handle)]
    expected = snapshot.NativePolicySnapshotError("injected_rename_failure")
    renamed: list[bool] = []

    def rename(
        actual_kernel: _DirectoryReadOracle, source: int, parent: int, name: str, *, replace_if_exists: bool
    ) -> None:
        assert actual_kernel is kernel and source == 100 and parent in api.live
        assert name == "checkpoint.json" and replace_if_exists
        api.require_config_reader_compatible()
        renamed.append(True)
        if rename_failure:
            raise expected

    monkeypatch.setattr(atomic, "_windows_parent_identity", lambda *_args: (7, 0, 11))
    monkeypatch.setattr(atomic, "_windows_rename_file_handle", rename)
    try:
        try:
            atomic._windows_rename_releasing_barrier(
                api=api,
                kernel32=kernel,
                source_handle=100,
                parent_path=Path("state"),
                parent_handle=handle,
                destination_name="checkpoint.json",
                replace_existing=True,
                directory_handles=handles,
            )
        except snapshot.NativePolicySnapshotError as error:
            assert rename_failure and error is expected
        else:
            assert not rename_failure
        assert renamed == [True]
        assert len(handles) == len(api.live) == 1
        api.require_config_reader_compatible()
        assert api.live[handles[0][1]].desired_access == constants._WINDOWS_GENERIC_READ
    finally:
        for held_kernel, held_handle in handles:
            api._windows_close_handle(held_kernel, held_handle)
    assert not api.live


def _assert_private_directory(path: Path) -> None:
    kernel, handle, _ = snapshot._windows_open_handle(path, directory=True, lock=True)
    try:
        owner = snapshot._windows_owner_sid()
        snapshot._windows_verify_private_owner(handle, owner_sid=owner)
        snapshot._windows_verify_private_dacl(handle, owner_sid=owner, directory=True)
    finally:
        snapshot._windows_close_handle(kernel, handle)


def _assert_rename_blocked(path: Path) -> None:
    with pytest.raises(OSError) as failure:
        path.rename(path.with_name(path.name + "-moved"))
    assert failure.value.winerror == 32


def _rename_roundtrip(path: Path) -> None:
    moved = path.with_name(path.name + "-moved")
    path.rename(moved)
    moved.rename(path)


@_WINDOWS
@pytest.mark.parametrize("shared", [False, True])
@pytest.mark.parametrize("repair", [False, True])
def test_real_authority_lease_and_acl_repair_allow_config_capture(tmp_path: Path, shared: bool, repair: bool) -> None:
    home = tmp_path / "guard-home"
    snapshot._windows_ensure_private_directory(home)
    config = home / "config.toml"
    config.write_bytes(_CONFIG)
    original = capture_guard_config(config)
    home_identity = (home.stat().st_dev, home.stat().st_ino)
    _rename_roundtrip(home)
    if repair:
        # A real additional read ACE makes the private-DACL check fail. The
        # production lease must repair it using WRITE_DAC, without child-write
        # access on either the repair handle or the retained read handle.
        subprocess.run(
            ["icacls", str(home), "/grant", "*S-1-1-0:(OI)(CI)(RX)"],
            check=True,
            capture_output=True,
            timeout=10,
        )
        with pytest.raises(snapshot.NativePolicySnapshotError, match="acl_not_private"):
            _assert_private_directory(home)

    with hold_command_control_authority_lock(home, timeout_seconds=0, shared=shared):
        assert capture_guard_config(config) == original
        _assert_private_directory(home)
        _assert_rename_blocked(home)
        assert capture_guard_config(config) == original
        assert (home.stat().st_dev, home.stat().st_ino) == home_identity

    _rename_roundtrip(home)
    assert capture_guard_config(config) == original
    _assert_private_directory(home)


@_WINDOWS
@pytest.mark.parametrize("shared", [False, True])
def test_real_atomic_restore_keeps_config_readable_during_authority_lease(tmp_path: Path, shared: bool) -> None:
    home = tmp_path / "guard-home"
    snapshot._windows_ensure_private_directory(home)
    config = home / "config.toml"
    config.write_bytes(_CONFIG)
    original = capture_guard_config(config)
    _rename_roundtrip(home)
    with hold_command_control_authority_lock(home, timeout_seconds=0, shared=shared):
        with snapshot._windows_private_state_binding(home) as binding:
            state_config = binding.path / "config.toml"
            state_config.write_bytes(_CONFIG)
            state_original = capture_guard_config(state_config)
            identity = atomic._windows_parent_identity(snapshot, binding.kernel32, binding.handle)
            for generation in (1, 2):
                payload = f'{{"generation":{generation}}}'.encode()
                snapshot._windows_write_private_file_atomic(
                    parent_path=binding.path,
                    parent_handle=binding.handle,
                    directory_handles=binding.handles,
                    temporary_name=f".checkpoint-{generation}.tmp",
                    destination_name="checkpoint.json",
                    payload=payload,
                    maximum_bytes=1024,
                    kind="cache",
                )
                assert snapshot._windows_read_snapshot_bytes(binding.path / "checkpoint.json") == payload
                assert not (binding.path / f".checkpoint-{generation}.tmp").exists()
                assert atomic._windows_parent_identity(snapshot, binding.kernel32, binding.handle) == identity
                assert capture_guard_config(config) == original
                assert capture_guard_config(state_config) == state_original
                _assert_private_directory(binding.path)
                _assert_rename_blocked(binding.path)
                _assert_rename_blocked(home)
        assert capture_guard_config(config) == original
    _rename_roundtrip(home)
    assert capture_guard_config(config) == original
