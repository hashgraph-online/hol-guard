"""Cursor native shell approval attestation for afterShell observer hooks."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path

_CURSOR_HOOK_ATTESTATION_RELATIVE = Path("secrets") / "cursor-hook-attestation.key"
_CURSOR_SHELL_BINDINGS_DIR = Path("cursor-shell-bindings")
_MANAGED_HOOK_ENV = "HOL_GUARD_MANAGED_CURSOR_HOOK"
_AFTER_SHELL_PROOF_ENV = "HOL_GUARD_CURSOR_AFTER_SHELL_PROOF"
_APPROVAL_BINDING_ENV = "HOL_GUARD_CURSOR_APPROVAL_BINDING"
_AFTER_SHELL_PROOF_EVENT = "afterShellExecution"


def _cursor_shell_binding_segment(conversation_id: str) -> str:
    cleaned = conversation_id.strip()
    if not cleaned:
        return "missing-conversation"
    if "/" in cleaned or "\\" in cleaned or cleaned in {".", ".."}:
        return hashlib.sha256(cleaned.encode("utf-8")).hexdigest()[:32]
    return cleaned


def cursor_after_shell_proof_message(
    *,
    conversation_id: str,
    command: str,
    approval_binding: str,
) -> bytes:
    return (
        chr(0)
        .join(
            (
                conversation_id.strip(),
                command.strip(),
                approval_binding.strip(),
                _AFTER_SHELL_PROOF_EVENT,
            )
        )
        .encode("utf-8")
    )


def cursor_hook_attestation_secret_path(guard_home: Path) -> Path:
    return guard_home / _CURSOR_HOOK_ATTESTATION_RELATIVE


def cursor_shell_binding_path(guard_home: Path, conversation_id: str, command: str) -> Path:
    fingerprint = hashlib.sha256(command.strip().encode("utf-8")).hexdigest()[:24]
    return guard_home / _CURSOR_SHELL_BINDINGS_DIR / _cursor_shell_binding_segment(conversation_id) / fingerprint


def write_cursor_shell_binding_file(
    guard_home: Path,
    *,
    conversation_id: str,
    command: str,
    approval_binding: str,
) -> None:
    binding_path = cursor_shell_binding_path(guard_home, conversation_id, command)
    binding_path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    try:
        fd = os.open(binding_path, flags, 0o600)
    except OSError:
        binding_path.write_text(approval_binding, encoding="utf-8")
        with suppress(OSError):
            binding_path.chmod(0o600)
        return
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(approval_binding)
    except OSError:
        with suppress(OSError):
            binding_path.unlink(missing_ok=True)
        raise


def read_cursor_shell_binding_file(guard_home: Path, *, conversation_id: str, command: str) -> str | None:
    binding_path = cursor_shell_binding_path(guard_home, conversation_id, command)
    try:
        binding = binding_path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return binding or None


def remove_cursor_shell_binding_file(guard_home: Path, *, conversation_id: str, command: str) -> None:
    binding_path = cursor_shell_binding_path(guard_home, conversation_id, command)
    with suppress(OSError):
        binding_path.unlink()
    with suppress(OSError):
        binding_path.parent.rmdir()


def _write_attestation_secret(secret_path: Path, generated: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        fd = os.open(secret_path, flags, 0o600)
    except OSError:
        secret_path.write_bytes(generated)
        with suppress(OSError):
            secret_path.chmod(0o600)
        return
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(generated)
    except OSError:
        with suppress(OSError):
            secret_path.unlink(missing_ok=True)
        raise


def ensure_cursor_hook_attestation_secret(guard_home: Path) -> bytes:
    secret_path = cursor_hook_attestation_secret_path(guard_home)
    secret_path.parent.mkdir(parents=True, exist_ok=True)
    if secret_path.is_file():
        try:
            existing = secret_path.read_bytes()
        except OSError:
            existing = b""
        if existing:
            return existing
    generated = secrets.token_bytes(32)
    _write_attestation_secret(secret_path, generated)
    return generated


def _optional_string(value: object) -> str | None:
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    return None


def cursor_generation_id(payload: Mapping[str, object]) -> str | None:
    for key in ("generation_id", "generationId"):
        value = _optional_string(payload.get(key))
        if value is not None:
            return value
    return None


def resolve_cursor_approval_binding(
    payload: Mapping[str, object],
    *,
    env: Mapping[str, str] | None = None,
) -> str | None:
    binding = cursor_generation_id(payload)
    if binding is not None:
        return binding
    source = os.environ if env is None else env
    return _optional_string(source.get(_APPROVAL_BINDING_ENV))


def ensure_cursor_approval_binding(payload: Mapping[str, object]) -> str:
    binding = cursor_generation_id(payload)
    if binding is not None:
        return binding
    return f"hol-guard:{secrets.token_urlsafe(24)}"


def compute_cursor_after_shell_proof(
    *,
    secret: bytes,
    conversation_id: str,
    command: str,
    approval_binding: str,
) -> str:
    message = cursor_after_shell_proof_message(
        conversation_id=conversation_id,
        command=command,
        approval_binding=approval_binding,
    )
    digest = hmac.new(secret, message, hashlib.sha256).hexdigest()
    return digest


def verify_cursor_after_shell_proof(
    *,
    secret: bytes,
    conversation_id: str,
    command: str,
    approval_binding: str,
    proof: str,
) -> bool:
    if not proof.strip():
        return False
    expected = compute_cursor_after_shell_proof(
        secret=secret,
        conversation_id=conversation_id,
        command=command,
        approval_binding=approval_binding,
    )
    return hmac.compare_digest(expected, proof.strip())


def managed_cursor_hook_invocation(env: Mapping[str, str] | None = None) -> bool:
    source = os.environ if env is None else env
    return source.get(_MANAGED_HOOK_ENV) == "1"


def after_shell_proof_from_env(env: Mapping[str, str] | None = None) -> str | None:
    source = os.environ if env is None else env
    return _optional_string(source.get(_AFTER_SHELL_PROOF_ENV))


def cursor_after_shell_trusted(
    *,
    guard_home: Path,
    pending: Mapping[str, object],
    payload: Mapping[str, object],
    conversation_id: str,
    command: str,
    env: Mapping[str, str] | None = None,
) -> bool:
    from ..runtime.harness_attribution import cursor_runtime_detected

    if not managed_cursor_hook_invocation(env):
        return False
    if not cursor_runtime_detected(env):
        return False
    pending_binding = _optional_string(pending.get("approval_binding")) or _optional_string(
        pending.get("generation_id")
    )
    payload_binding = resolve_cursor_approval_binding(payload, env=env)
    if pending_binding is None or payload_binding is None:
        return False
    if pending_binding != payload_binding:
        return False
    proof = after_shell_proof_from_env(env)
    if proof is None:
        return False
    expected_proof = pending.get("after_shell_proof")
    if not isinstance(expected_proof, str) or not expected_proof.strip():
        return False
    if not hmac.compare_digest(expected_proof.strip(), proof.strip()):
        return False
    try:
        secret = ensure_cursor_hook_attestation_secret(guard_home)
    except OSError:
        return False
    return verify_cursor_after_shell_proof(
        secret=secret,
        conversation_id=conversation_id,
        command=command,
        approval_binding=payload_binding,
        proof=proof,
    )


__all__ = [
    "after_shell_proof_from_env",
    "compute_cursor_after_shell_proof",
    "cursor_after_shell_proof_message",
    "cursor_after_shell_trusted",
    "cursor_generation_id",
    "cursor_hook_attestation_secret_path",
    "cursor_shell_binding_path",
    "ensure_cursor_approval_binding",
    "ensure_cursor_hook_attestation_secret",
    "managed_cursor_hook_invocation",
    "read_cursor_shell_binding_file",
    "remove_cursor_shell_binding_file",
    "resolve_cursor_approval_binding",
    "verify_cursor_after_shell_proof",
    "write_cursor_shell_binding_file",
]
