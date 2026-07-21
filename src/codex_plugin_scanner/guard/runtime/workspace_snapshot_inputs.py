"""Complete bounded workspace snapshots for result-only contained commands."""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from collections.abc import Iterator
from itertools import pairwise
from pathlib import Path
from typing import Final

from .containment_contract import ContainmentInput
from .secret_sensitivity import classify_secret_path

_MAX_FILES: Final = 20_000
_MAX_BYTES: Final = 256 * 1024 * 1024
_MAX_ENTRIES: Final = 50_000
_DISCOVERY_TIMEOUT_SECONDS: Final = 5.0
_SKIPPED_STATE_NAMES: Final = frozenset({".git", ".guard"})
_PROTECTED_NAMES: Final = frozenset(
    {
        ".aws",
        ".azure",
        ".docker",
        ".gnupg",
        ".kube",
        ".netrc",
        ".npmrc",
        ".pypirc",
        ".ssh",
        ".vault-token",
        "auth.json",
        "credentials",
        "credentials.json",
        "guard-home",
        "secrets.json",
    }
)
_PROTECTED_SUFFIXES: Final = (".jks", ".key", ".keystore", ".p12", ".pem", ".pfx")
_PROTECTED_WORDS: Final = frozenset(
    {"credential", "credentials", "passwd", "password", "passwords", "secret", "secrets", "token", "tokens"}
)
_PROTECTED_WORD_PAIRS: Final = frozenset({("api", "key"), ("private", "key"), ("service", "account")})
_SSH_PRIVATE_KEY_NAMES: Final = frozenset({"id_dsa", "id_ecdsa", "id_ed25519", "id_rsa"})


def complete_workspace_snapshot(workspace: Path) -> tuple[str, tuple[ContainmentInput, ...]]:
    """Capture every eligible workspace file or reject the command for review."""

    canonical_workspace = _canonical_directory(workspace)
    captured: list[tuple[str, str, ContainmentInput]] = []
    exclusions: list[tuple[str, str]] = []
    total_bytes = 0
    started_at = time.monotonic()
    visited_entries = [0]
    directories = [(canonical_workspace, _directory_identity(canonical_workspace))]
    while directories:
        directory, expected_identity = directories.pop()
        for entry in _bounded_entries(directory, expected_identity, started_at, visited_entries):
            path = directory / entry.name
            relative = path.relative_to(canonical_workspace)
            lowered_parts = tuple(part.lower() for part in relative.parts)
            if any(part in _SKIPPED_STATE_NAMES for part in lowered_parts):
                exclusions.append((relative.as_posix(), "protected-state"))
                continue
            if _is_protected(relative):
                raise ValueError("protected workspace content requires Guard review")
            if entry.is_dir(follow_symlinks=False) and entry.name == ".bin" and "node_modules" in lowered_parts:
                exclusions.append((relative.as_posix(), "package-bin-links"))
                continue
            if entry.is_symlink():
                raise ValueError("workspace snapshot cannot contain symlinks")
            if entry.is_dir(follow_symlinks=False):
                metadata = entry.stat(follow_symlinks=False)
                directories.append((path, (metadata.st_dev, metadata.st_ino)))
                continue
            if not entry.is_file(follow_symlinks=False):
                raise ValueError("workspace snapshot inputs must be regular files")
            metadata = entry.stat(follow_symlinks=False)
            if metadata.st_nlink != 1:
                raise ValueError("workspace snapshot cannot contain hard-linked files")
            total_bytes += metadata.st_size
            if len(captured) >= _MAX_FILES or total_bytes > _MAX_BYTES:
                raise ValueError("workspace snapshot exceeds containment identity budget")
            digest = _snapshot_file_digest(path, metadata)
            _check_discovery_budget(started_at, visited_entries[0])
            snapshot_path = relative.as_posix()
            captured.append(
                (
                    snapshot_path,
                    digest,
                    ContainmentInput(str(path), snapshot_path, digest),
                )
            )
    captured.sort(key=lambda item: item[0])
    records = [(path, digest) for path, digest, _item in captured]
    exclusions.sort()
    return _binding_digest({"exclusions": exclusions, "files": records}), tuple(
        item for _path, _digest, item in captured
    )


def reject_external_node_modules(workspace: Path) -> None:
    """Reject Node resolution roots outside the captured workspace."""

    for ancestor in workspace.parents:
        dependency_root = ancestor / "node_modules"
        try:
            _ = dependency_root.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise ValueError("external Node dependency identity is unavailable") from exc
        raise ValueError("external Node dependencies require Guard review")


def _bounded_entries(
    directory: Path,
    expected_identity: tuple[int, int],
    started_at: float,
    visited_entries: list[int],
) -> Iterator[os.DirEntry[str]]:
    if os.name == "nt":
        yield from _bounded_windows_entries(directory, expected_identity, started_at, visited_entries)
        return
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(directory, flags)
    except OSError as exc:
        raise ValueError("workspace snapshot discovery failed") from exc
    try:
        metadata = os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino) != expected_identity:
            raise ValueError("workspace directory identity changed during discovery")
        with os.scandir(descriptor) as entries:
            for entry in entries:
                visited_entries[0] += 1
                _check_discovery_budget(started_at, visited_entries[0])
                yield entry
    except OSError as exc:
        raise ValueError("workspace snapshot discovery failed") from exc
    finally:
        os.close(descriptor)


def _bounded_windows_entries(
    directory: Path,
    expected_identity: tuple[int, int],
    started_at: float,
    visited_entries: list[int],
) -> Iterator[os.DirEntry[str]]:
    try:
        if _directory_identity(directory) != expected_identity:
            raise ValueError("workspace directory identity changed during discovery")
        with os.scandir(directory) as entries:
            for entry in entries:
                visited_entries[0] += 1
                _check_discovery_budget(started_at, visited_entries[0])
                yield entry
        if _directory_identity(directory) != expected_identity:
            raise ValueError("workspace directory identity changed during discovery")
    except OSError as exc:
        raise ValueError("workspace snapshot discovery failed") from exc


def _snapshot_file_digest(path: Path, expected: os.stat_result) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        expected_identity = (expected.st_dev, expected.st_ino, expected.st_size, expected.st_mtime_ns)
        observed_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        if observed_identity != expected_identity or before.st_nlink != 1:
            raise ValueError("workspace file identity changed during discovery")
        digest = hashlib.sha256()
        consumed = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            consumed += len(chunk)
            if consumed > _MAX_BYTES:
                raise ValueError("workspace snapshot exceeds containment identity budget")
            digest.update(chunk)
        after = os.fstat(descriptor)
        final_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if final_identity != observed_identity:
            raise ValueError("workspace file identity changed during discovery")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _is_protected(relative: Path) -> bool:
    return classify_secret_path(relative.as_posix()) is not None or any(
        _is_protected_part(part) for part in relative.parts
    )


def _is_protected_part(part: str) -> bool:
    lowered = part.lower()
    return (
        lowered in _PROTECTED_NAMES
        or lowered in _SSH_PRIVATE_KEY_NAMES
        or lowered.startswith(".env")
        or lowered.endswith(_PROTECTED_SUFFIXES)
        or _has_protected_words(part)
    )


def _has_protected_words(part: str) -> bool:
    camel_split = re.sub(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])", "-", part)
    words = tuple(value for value in re.split(r"[^a-z0-9]+", camel_split.lower()) if value)
    return bool(_PROTECTED_WORDS.intersection(words)) or bool(_PROTECTED_WORD_PAIRS.intersection(pairwise(words)))


def _check_discovery_budget(started_at: float, visited_entries: int) -> None:
    if visited_entries > _MAX_ENTRIES:
        raise ValueError("workspace discovery entry budget exceeded")
    if time.monotonic() - started_at > _DISCOVERY_TIMEOUT_SECONDS:
        raise ValueError("workspace discovery time budget exceeded")


def _canonical_directory(path: Path) -> Path:
    if path.is_symlink() or not path.is_dir():
        raise ValueError("workspace must be an existing canonical directory")
    canonical = path.resolve(strict=True)
    if canonical != Path(os.path.normpath(str(path))):
        raise ValueError("workspace cannot contain aliases")
    return canonical


def _directory_identity(path: Path) -> tuple[int, int]:
    metadata = path.stat(follow_symlinks=False)
    return metadata.st_dev, metadata.st_ino


def _binding_digest(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(len(encoded).to_bytes(8, "big") + encoded).hexdigest()


__all__ = ("complete_workspace_snapshot", "reject_external_node_modules")
