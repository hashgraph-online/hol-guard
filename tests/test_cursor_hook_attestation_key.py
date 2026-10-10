"""Attestation keys must stay private enough for the resident to verify them."""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.cursor_native_approval import (
    compute_cursor_after_observer_proof,
    cursor_after_observer_proof_message,
    cursor_hook_attestation_secret_path,
    ensure_cursor_hook_attestation_secret,
    normalize_cursor_shell_command,
)

posix_only = pytest.mark.skipif(
    os.name != "posix",
    reason="the resident enforces owner-private attestation keys on unix",
)


@posix_only
def test_loose_attestation_key_is_tightened_and_reused(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard"
    secret_path = cursor_hook_attestation_secret_path(guard_home)
    secret_path.parent.mkdir(parents=True)
    secret_path.write_bytes(b"existing-key-bytes")
    secret_path.chmod(0o644)

    secret = ensure_cursor_hook_attestation_secret(guard_home)

    assert secret == b"existing-key-bytes"
    assert stat_mode(secret_path) == 0o600


@posix_only
def test_symlinked_attestation_key_is_replaced_without_writing_the_target(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard"
    secret_path = cursor_hook_attestation_secret_path(guard_home)
    secret_path.parent.mkdir(parents=True)
    target = tmp_path / "outside.key"
    target.write_bytes(b"outside-key")
    secret_path.symlink_to(target)

    secret = ensure_cursor_hook_attestation_secret(guard_home)

    assert secret != b"outside-key"
    assert len(secret) == 32
    assert secret_path.is_symlink() is False
    assert stat_mode(secret_path) == 0o600
    assert target.read_bytes() == b"outside-key"


@posix_only
def test_empty_attestation_key_is_replaced(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard"
    secret_path = cursor_hook_attestation_secret_path(guard_home)
    secret_path.parent.mkdir(parents=True)
    secret_path.write_bytes(b"")
    secret_path.chmod(0o600)

    secret = ensure_cursor_hook_attestation_secret(guard_home)

    assert secret
    assert len(secret) == 32
    assert secret_path.read_bytes() == secret
    assert stat_mode(secret_path) == 0o600


@posix_only
def test_attestation_write_does_not_follow_a_symlink(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.cursor_native_approval import _write_attestation_secret

    secret_path = tmp_path / "cursor-hook-attestation.key"
    target = tmp_path / "outside.key"
    target.write_bytes(b"outside-key")
    secret_path.symlink_to(target)

    with pytest.raises(OSError):
        _write_attestation_secret(secret_path, b"replacement-key")

    assert target.read_bytes() == b"outside-key"


def test_observer_proof_signs_the_twice_normalised_command() -> None:
    raw = "lean-ctx -c 'lean-ctx -c git status'"
    once = normalize_cursor_shell_command(raw)
    twice = normalize_cursor_shell_command(once)
    assert once != twice
    secret = b"k" * 32
    proof = compute_cursor_after_observer_proof(
        secret=secret,
        conversation_id="conversation",
        command=raw,
        approval_binding="binding",
        observer_event="afterShellExecution",
    )
    message = cursor_after_observer_proof_message(
        conversation_id="conversation",
        command=twice,
        approval_binding="binding",
        observer_event="afterShellExecution",
    )

    assert proof == hmac.new(secret, message, hashlib.sha256).hexdigest()


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


@posix_only
def test_new_attestation_key_is_owner_private(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard"

    secret = ensure_cursor_hook_attestation_secret(guard_home)

    secret_path = cursor_hook_attestation_secret_path(guard_home)
    assert secret_path.read_bytes() == secret
    assert stat_mode(secret_path) == 0o600
    assert os.stat(secret_path).st_uid == os.getuid()
