"""Real filesystem controls for private-mode repair and native input observation."""

from __future__ import annotations

import os
import stat
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import store_base
from codex_plugin_scanner.guard.native_policy_authority_read import read_native_policy_authority_inputs
from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.store import EncryptedFileSecretStore, GuardStore, SystemKeyringSecretStore

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX private modes and inode ctime are required")


@pytest.fixture
def protected_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[GuardStore]:
    monkeypatch.setattr(SystemKeyringSecretStore, "_backend_is_available", classmethod(lambda _cls: False))
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    assert isinstance(store._policy_integrity_secret_store, EncryptedFileSecretStore)
    assert store.setup_policy_integrity(now="2026-09-19T00:00:00Z", include_items=False)["mode"] == "protected"
    yield store


def owner_and_mode(path: Path) -> tuple[int, int, int]:
    metadata = path.stat()
    return metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)


def test_authenticated_noop_read_preserves_watched_metadata(
    protected_store: GuardStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = protected_store
    publisher = NativePolicySnapshotPublisher(store=store)
    try:
        original_inputs = read_native_policy_authority_inputs(store, now=time.time())
        before = publisher._current_input_fingerprint()
        owners = {path: owner_and_mode(path) for path in (store.guard_home, store.path)}
        assert owners[store.guard_home][2] == 0o700
        assert owners[store.path][2] == 0o600
        chmod = os.chmod
        redundant: list[bool] = []
        metadata_changes: list[bool] = []

        def observe_chmod(path: Path, mode: int) -> None:
            previous = path.stat()
            chmod(path, mode)
            if path in owners:
                redundant.append(stat.S_IMODE(previous.st_mode) == mode)
                metadata_changes.append(path.stat().st_ctime_ns != previous.st_ctime_ns)

        monkeypatch.setattr(store_base.os, "chmod", observe_chmod)
        current_inputs = read_native_policy_authority_inputs(store, now=time.time())
        after = publisher._current_input_fingerprint()
        observation = {
            "authenticated_input_unchanged": current_inputs.input_digest == original_inputs.input_digest,
            "owners_and_private_modes_preserved": all(owner_and_mode(path) == value for path, value in owners.items()),
            "watcher_metadata_unchanged": after == before,
            "redundant_chmod_absent": not any(redundant),
            "permission_writer_left_ctime_unchanged": not any(metadata_changes),
        }
        assert observation == dict.fromkeys(observation, True)
    finally:
        publisher.close()


@pytest.mark.parametrize(("directory", "mode"), [(False, 0o600), (True, 0o700)])
def test_already_private_mode_is_a_real_filesystem_noop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, directory: bool, mode: int
) -> None:
    path = tmp_path / "private-target"
    if directory:
        path.mkdir()
    else:
        path.write_bytes(b"synthetic-private-mode-control")
    path.chmod(mode)
    before = path.stat()
    chmod = os.chmod
    calls: list[int] = []

    def observe_chmod(target: Path, requested_mode: int) -> None:
        calls.append(requested_mode)
        chmod(target, requested_mode)

    monkeypatch.setattr(store_base.os, "chmod", observe_chmod)
    store_base._set_private_mode(path, mode)
    after = path.stat()
    observation = {
        "writer_did_not_call_chmod": not calls,
        "ctime_unchanged": after.st_ctime_ns == before.st_ctime_ns,
        "identity_unchanged": (after.st_dev, after.st_ino) == (before.st_dev, before.st_ino),
        "owner_unchanged": (after.st_uid, after.st_gid) == (before.st_uid, before.st_gid),
        "mode_preserved": stat.S_IMODE(after.st_mode) == mode,
    }
    assert observation == dict.fromkeys(observation, True)


@pytest.mark.parametrize(("directory", "private_mode"), [(False, 0o600), (True, 0o700)])
def test_insecure_mode_is_repaired_without_changing_owner(tmp_path: Path, directory: bool, private_mode: int) -> None:
    path = tmp_path / "repair-target"
    if directory:
        path.mkdir()
    else:
        path.write_bytes(b"synthetic-private-mode-control")
    path.chmod(0o777)
    before = path.stat()
    store_base._set_private_mode(path, private_mode)
    after = path.stat()
    assert stat.S_IMODE(after.st_mode) == private_mode
    assert (after.st_uid, after.st_gid) == (before.st_uid, before.st_gid)
    assert (after.st_dev, after.st_ino) == (before.st_dev, before.st_ino)


def test_path_replacement_at_chmod_keeps_existing_repair_behavior(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "replace-target"
    retired = tmp_path / "retired-target"
    path.write_bytes(b"original")
    path.chmod(0o666)
    chmod = os.chmod
    replacements: list[bool] = []

    def replace_then_chmod(target: Path, mode: int) -> None:
        assert target == path and mode == 0o600
        target.rename(retired)
        target.write_bytes(b"replacement")
        chmod(target, 0o666)
        replacements.append(target.stat().st_ino != retired.stat().st_ino)
        chmod(target, mode)

    monkeypatch.setattr(store_base.os, "chmod", replace_then_chmod)
    store_base._set_private_mode(path, 0o600)
    assert replacements == [True]
    assert path.read_bytes() == b"replacement"
    assert retired.read_bytes() == b"original"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(retired.stat().st_mode) == 0o666
    assert (path.stat().st_uid, path.stat().st_gid) == (retired.stat().st_uid, retired.stat().st_gid)


def test_disappeared_path_keeps_existing_nonthrowing_repair(tmp_path: Path) -> None:
    path = tmp_path / "missing-target"
    store_base._set_private_mode(path, 0o600)
    assert not path.exists()
