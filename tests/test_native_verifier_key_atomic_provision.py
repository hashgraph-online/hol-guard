"""Concurrent first-time verifier key provisioning never exposes a partial key."""

from __future__ import annotations

import os
import sys
import threading
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_policy_snapshot_codec import derive_native_policy_verifier_key
from codex_plugin_scanner.guard.native_policy_snapshot_windows_key import provision_native_policy_verifier_key

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX provisioning path")


def test_concurrent_first_provisioners_never_observe_a_partial_key(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    master = b"m" * 32
    workers = 16
    barrier = threading.Barrier(workers)
    paths: list[Path] = []
    errors: list[BaseException] = []

    def provision() -> None:
        barrier.wait()
        try:
            paths.append(provision_native_policy_verifier_key(guard_home, master))
        except BaseException as error:  # pragma: no cover - failure path
            errors.append(error)

    threads = [threading.Thread(target=provision) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(set(paths)) == 1
    key_path = paths[0]
    assert key_path.read_bytes() == derive_native_policy_verifier_key(master)
    assert (key_path.stat().st_mode & 0o777) == 0o600
    assert [entry.name for entry in key_path.parent.iterdir() if entry.name.endswith(".tmp")] == []


def test_existing_key_is_never_replaced(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    key_path = provision_native_policy_verifier_key(guard_home, b"a" * 32)
    original = key_path.read_bytes()
    with pytest.raises(Exception, match="native_policy_verifier_key_mismatch"):
        provision_native_policy_verifier_key(guard_home, b"b" * 32)
    assert key_path.read_bytes() == original
    assert os.stat(key_path).st_nlink == 1


def test_filesystem_without_hard_links_falls_back_to_exclusive_create(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse_link(source: object, target: object) -> None:
        raise PermissionError("hard links unsupported")

    monkeypatch.setattr(os, "link", refuse_link)
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    master = b"n" * 32
    key_path = provision_native_policy_verifier_key(guard_home, master)
    assert key_path.read_bytes() == derive_native_policy_verifier_key(master)
    assert [entry.name for entry in key_path.parent.iterdir() if entry.name.endswith(".tmp")] == []
    assert provision_native_policy_verifier_key(guard_home, master) == key_path


def test_provisioner_waits_for_an_in_flight_writer_without_hard_links(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    master = b"p" * 32
    expected = derive_native_policy_verifier_key(master)
    key_path = provision_native_policy_verifier_key(guard_home, master)
    key_path.write_bytes(b"")
    key_path.chmod(0o600)

    def finish_write(_seconds: float) -> None:
        key_path.write_bytes(expected)
        key_path.chmod(0o600)

    monkeypatch.setattr("codex_plugin_scanner.guard.native_policy_snapshot_windows_key.time.sleep", finish_write)
    assert provision_native_policy_verifier_key(guard_home, master) == key_path


def test_a_permanently_truncated_key_still_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    key_path = provision_native_policy_verifier_key(guard_home, b"q" * 32)
    key_path.write_bytes(b"short")
    key_path.chmod(0o600)
    monkeypatch.setattr("codex_plugin_scanner.guard.native_policy_snapshot_windows_key.time.sleep", lambda _s: None)
    with pytest.raises(Exception, match="native_policy_verifier_key_invalid"):
        provision_native_policy_verifier_key(guard_home, b"q" * 32)
