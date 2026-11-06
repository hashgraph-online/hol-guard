from __future__ import annotations

import errno
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import durable_io


def test_fsync_directory_ignores_unsupported_open(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def unsupported_open(*_args: object, **_kwargs: object) -> int:
        raise OSError(errno.EINVAL, "unsupported")

    monkeypatch.setattr(durable_io.os, "name", "posix")
    monkeypatch.setattr(durable_io.os, "open", unsupported_open)

    durable_io.fsync_directory(tmp_path)


def test_fsync_directory_closes_descriptor_when_sync_is_unsupported(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    closed: list[int] = []
    monkeypatch.setattr(durable_io.os, "name", "posix")
    monkeypatch.setattr(durable_io.os, "open", lambda *_args, **_kwargs: 41)
    monkeypatch.setattr(durable_io.os, "close", closed.append)

    def unsupported_sync(_descriptor: int) -> None:
        raise OSError(errno.ENOTSUP, "unsupported")

    monkeypatch.setattr(durable_io.os, "fsync", unsupported_sync)

    durable_io.fsync_directory(tmp_path)

    assert closed == [41]


def test_fsync_directory_preserves_real_failures(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    closed: list[int] = []
    monkeypatch.setattr(durable_io.os, "name", "posix")
    monkeypatch.setattr(durable_io.os, "open", lambda *_args, **_kwargs: 42)
    monkeypatch.setattr(durable_io.os, "close", closed.append)

    def failed_sync(_descriptor: int) -> None:
        raise OSError(errno.EIO, "failed")

    monkeypatch.setattr(durable_io.os, "fsync", failed_sync)

    with pytest.raises(OSError) as error:
        durable_io.fsync_directory(tmp_path)

    assert error.value.errno == errno.EIO
    assert closed == [42]
