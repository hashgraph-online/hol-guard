from __future__ import annotations

import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import private_file_io as reader


class _DescriptorObserver:
    def __init__(self, *, change_before=None, change_after=None):
        self.change_before = change_before or {}
        self.change_after = change_after or {}
        self.fstat_calls = 0
        self.read_calls = 0
        self.closed = []

    def __getattr__(self, name):
        return getattr(os, name)

    def fstat(self, descriptor):
        self.fstat_calls += 1
        metadata = os.fstat(descriptor)
        values = {
            name: getattr(metadata, name)
            for name in ("st_dev", "st_ino", "st_mode", "st_uid", "st_size", "st_mtime_ns", "st_ctime_ns")
        }
        changes = self.change_before if self.fstat_calls == 1 else self.change_after
        for name, value in changes.items():
            values[name] = value(values[name]) if callable(value) else value
        return SimpleNamespace(**values)

    def read(self, descriptor, maximum):
        self.read_calls += 1
        return os.read(descriptor, maximum)

    def close(self, descriptor):
        os.close(descriptor)
        self.closed.append(descriptor)


def _authority(tmp_path: Path) -> Path:
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    path = parent / "authority"
    path.write_bytes(b"synthetic\n")
    if os.name != "nt":
        path.chmod(0o600)
    return path


@pytest.mark.parametrize(
    "change",
    [{"st_ino": lambda value: value + 1}, {"st_mode": stat.S_IFDIR | 0o700}, {"st_size": 4097}],
    ids=["different_handle_identity", "directory_handle", "oversized_handle"],
)
def test_opened_descriptor_guards_reject_before_read_and_close(tmp_path, monkeypatch, change):
    target = _authority(tmp_path)
    observer = _DescriptorObserver(change_before=change)
    monkeypatch.setattr(reader, "os", observer)
    assert reader.read_private_regular_bytes(target, max_bytes=4096, require_private_parent=True) is None
    assert observer.fstat_calls == 1
    assert observer.read_calls == 0
    assert len(observer.closed) == 1
    with pytest.raises(OSError):
        os.fstat(observer.closed[0])


@pytest.mark.skipif(os.name == "nt", reason="Original explicit owner check is POSIX-only")
def test_opened_descriptor_owner_must_still_match(tmp_path, monkeypatch):
    target = _authority(tmp_path)
    observer = _DescriptorObserver(change_before={"st_uid": lambda value: value + 1})
    monkeypatch.setattr(reader, "os", observer)
    assert reader.read_private_regular_bytes(target, max_bytes=4096, require_private_parent=True) is None
    assert observer.read_calls == 0
    assert len(observer.closed) == 1


@pytest.mark.parametrize(
    "field",
    ["st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns"],
)
def test_changed_descriptor_metadata_is_never_returned(tmp_path, monkeypatch, field):
    target = _authority(tmp_path)
    observer = _DescriptorObserver(change_after={field: lambda value: value + 1})
    monkeypatch.setattr(reader, "os", observer)
    assert reader.read_private_regular_bytes(target, max_bytes=4096, require_private_parent=True) is None
    assert observer.fstat_calls == 2
    assert observer.read_calls > 0
    assert len(observer.closed) == 1


def test_descriptor_read_exception_keeps_identity_and_closes(tmp_path, monkeypatch):
    target = _authority(tmp_path)
    observer = _DescriptorObserver()
    failure = OSError("synthetic read failure")

    def fail_read(_descriptor, _maximum):
        raise failure

    monkeypatch.setattr(observer, "read", fail_read)
    monkeypatch.setattr(reader, "os", observer)
    with pytest.raises(OSError) as caught:
        reader.read_private_regular_bytes(target, max_bytes=4096, require_private_parent=True)
    assert caught.value is failure
    assert len(observer.closed) == 1


def test_codex_token_recheck_still_rejects_authenticated_state_mismatch(tmp_path):
    import hashlib

    from codex_plugin_scanner.guard.adapters import codex_daemon_hook_auth
    from codex_plugin_scanner.guard.daemon import manager

    home = tmp_path / "guard"
    manager._ensure_private_directory(home)
    manager._write_private_atomic_text(home / "daemon-auth-token", "synthetic-new-token")
    state = {"auth_token_id": hashlib.sha256(b"synthetic-old-token").hexdigest()}
    with pytest.raises(ValueError, match="does not match authenticated state"):
        codex_daemon_hook_auth._daemon_auth_token(home / "daemon-state.json", state)
