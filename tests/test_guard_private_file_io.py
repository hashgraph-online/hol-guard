from __future__ import annotations

import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.private_file_io import (
    read_private_regular_bytes,
    read_private_regular_text,
)


def _private_file(tmp_path: Path, payload: bytes = b"secret\n") -> Path:
    private_dir = tmp_path / "private"
    private_dir.mkdir(mode=0o700)
    path = private_dir / "authority"
    path.write_bytes(payload)
    if os.name != "nt":
        private_dir.chmod(0o700)
        path.chmod(0o600)
    return path


def test_private_regular_file_read_rejects_invalid_utf8(tmp_path: Path) -> None:
    path = _private_file(tmp_path, b"\xff\xfe")

    assert read_private_regular_text(path, max_bytes=2, require_private_parent=True) is None
    assert read_private_regular_bytes(path, max_bytes=2, require_private_parent=True) == b"\xff\xfe"


def test_private_regular_file_read_validates_positive_bound(tmp_path: Path) -> None:
    path = _private_file(tmp_path)

    with pytest.raises(ValueError, match="positive integer"):
        read_private_regular_bytes(path, max_bytes=0)
    with pytest.raises(ValueError, match="positive integer"):
        read_private_regular_bytes(path, max_bytes=True)


def test_private_regular_file_read_tolerates_sibling_parent_activity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _private_file(tmp_path)
    original_read = os.read
    touched = False

    def read_and_create_sibling(descriptor: int, count: int) -> bytes:
        nonlocal touched
        if not touched:
            touched = True
            sibling = path.parent / "sibling"
            sibling.write_bytes(b"noise")
            if os.name != "nt":
                sibling.chmod(0o600)
        return original_read(descriptor, count)

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.private_file_io.os.read",
        read_and_create_sibling,
    )

    assert read_private_regular_text(path, max_bytes=64, require_private_parent=True) == "secret"


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission semantics")
def test_private_regular_file_read_rejects_parent_mode_change_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _private_file(tmp_path)
    original_read = os.read

    def read_and_relax_parent(descriptor: int, count: int) -> bytes:
        path.parent.chmod(0o755)
        return original_read(descriptor, count)

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.private_file_io.os.read",
        read_and_relax_parent,
    )

    assert read_private_regular_text(path, max_bytes=64, require_private_parent=True) is None
