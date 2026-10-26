from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import contained_execution_common as common_module


def test_file_sha256_hashes_exact_leading_space_path(tmp_path: Path) -> None:
    path = tmp_path / " leading-space"
    content = b"healthy executable bytes\n"
    _ = path.write_bytes(content)

    assert common_module.file_sha256(str(path)) == hashlib.sha256(content).hexdigest()


def test_file_sha256_rejects_read_growth_past_bound(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "executable"
    _ = path.write_bytes(b"1234")
    monkeypatch.setattr(common_module, "_MAX_EXECUTABLE_BYTES", 4)
    real_read = common_module.os.read
    grown = False

    def grow_after_read(descriptor: int, size: int) -> bytes:
        nonlocal grown
        chunk = real_read(descriptor, size)
        if chunk and not grown:
            grown = True
            return chunk + b"5"
        return chunk

    monkeypatch.setattr(common_module.os, "read", grow_after_read)

    with pytest.raises(ValueError, match="bounded regular file"):
        _ = common_module.file_sha256(str(path))


@pytest.mark.skipif(
    not hasattr(os, "mkfifo") or not hasattr(os, "O_NONBLOCK"),
    reason="requires POSIX FIFO and nonblocking open support",
)
def test_file_sha256_rejects_fifo_with_nonblocking_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "executable"
    os.mkfifo(path)
    opened_flags: list[int] = []
    real_open = common_module.os.open

    def observe_open(path_name: str, flags: int, *args: object, **kwargs: object) -> int:
        opened_flags.append(flags)
        assert flags & os.O_NONBLOCK
        return real_open(path_name, flags, *args, **kwargs)

    monkeypatch.setattr(common_module.os, "open", observe_open)

    with pytest.raises(ValueError, match="bounded regular file"):
        _ = common_module.file_sha256(str(path))
    assert opened_flags


def test_file_sha256_rejects_short_read_for_stable_size(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "executable"
    _ = path.write_bytes(b"stable file bytes\n")
    real_read = common_module.os.read
    shortened = False

    def return_short_read(descriptor: int, size: int) -> bytes:
        nonlocal shortened
        chunk = real_read(descriptor, size)
        if chunk and not shortened:
            shortened = True
            return chunk[:1]
        return b""

    monkeypatch.setattr(common_module.os, "read", return_short_read)

    with pytest.raises(ValueError, match="identity changed while hashing"):
        _ = common_module.file_sha256(str(path))


@pytest.mark.skipif(not hasattr(os, "fchmod"), reason="requires descriptor metadata mutation")
def test_file_sha256_rejects_descriptor_metadata_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "executable"
    _ = path.write_bytes(b"descriptor mutation\n")
    path.chmod(0o700)
    real_read = common_module.os.read
    mutated = False

    def mutate_after_read(descriptor: int, size: int) -> bytes:
        nonlocal mutated
        chunk = real_read(descriptor, size)
        if chunk and not mutated:
            mutated = True
            os.fchmod(descriptor, 0o600)
        return chunk

    monkeypatch.setattr(common_module.os, "read", mutate_after_read)

    with pytest.raises(ValueError, match="identity changed"):
        _ = common_module.file_sha256(str(path))


def test_file_sha256_rejects_regular_path_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "executable"
    replacement = tmp_path / "replacement"
    _ = path.write_bytes(b"original executable\n")
    _ = replacement.write_bytes(b"replacement executable\n")
    real_read = common_module.os.read
    replaced = False

    def replace_after_read(descriptor: int, size: int) -> bytes:
        nonlocal replaced
        chunk = real_read(descriptor, size)
        if chunk and not replaced:
            replaced = True
            path.unlink()
            replacement.replace(path)
        return chunk

    monkeypatch.setattr(common_module.os, "read", replace_after_read)

    with pytest.raises(ValueError, match="identity changed"):
        _ = common_module.file_sha256(str(path))


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="requires symlink support")
def test_file_sha256_rejects_path_replaced_by_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "executable"
    replacement = tmp_path / "replacement"
    _ = path.write_bytes(b"original executable\n")
    _ = replacement.write_bytes(b"replacement executable\n")
    real_read = common_module.os.read
    replaced = False

    def replace_with_symlink(descriptor: int, size: int) -> bytes:
        nonlocal replaced
        chunk = real_read(descriptor, size)
        if chunk and not replaced:
            replaced = True
            path.unlink()
            path.symlink_to(replacement)
        return chunk

    monkeypatch.setattr(common_module.os, "read", replace_with_symlink)

    with pytest.raises(ValueError, match="identity changed"):
        _ = common_module.file_sha256(str(path))


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="requires symlink support")
def test_file_sha256_rejects_initial_symlink(tmp_path: Path) -> None:
    path = tmp_path / "executable"
    target = tmp_path / "target"
    _ = target.write_bytes(b"target executable\n")
    path.symlink_to(target)

    with pytest.raises(ValueError, match="must not be a symlink"):
        _ = common_module.file_sha256(str(path))


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="requires symlink support")
def test_file_sha256_rejects_initial_symlink_without_o_nofollow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "executable"
    target = tmp_path / "target"
    _ = target.write_bytes(b"target executable\n")
    path.symlink_to(target)
    monkeypatch.delattr(common_module.os, "O_NOFOLLOW", raising=False)

    with pytest.raises(ValueError, match="must not be a symlink"):
        _ = common_module.file_sha256(str(path))
