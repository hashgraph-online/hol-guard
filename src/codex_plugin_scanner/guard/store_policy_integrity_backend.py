"""Platform policy-integrity secret-store selection.

Keep local policy integrity usable on desktop Linux when the Python keyring
backend changes between daemon and terminal sessions. Keep the signing key and
its control metadata together; never overwrite a verified local identity with
an unrelated keyring copy.
"""

from __future__ import annotations

import base64
import hmac
import os
import sys
from contextlib import suppress
from pathlib import Path
from typing import Literal

from .store_base import (
    _POLICY_INTEGRITY_CONTROL_REF,
    _POLICY_INTEGRITY_KEY_REF,
    _POLICY_INTEGRITY_PRIMARY_SECRET_TIMEOUT_SECONDS,
    _POLICY_INTEGRITY_SERVICE_NAME,
    EncryptedFileSecretStore,
    FallbackSecretStore,
    SecretStore,
    SystemKeyringSecretStore,
    _store_logger,
)
from .store_base import (
    _build_policy_integrity_secret_store as _base_policy_integrity_secret_store,
)


def _matches_native_authority(guard_home: Path, encoded_key: str | None) -> bool:
    """Select an existing key only with authenticated, mutually consistent state."""

    from .native_command_control_authority import AUTHORITY_FILE_NAME, AUTHORITY_MAX_BYTES, decode_authority
    from .native_command_control_authority_io import read_private_state
    from .native_command_control_authority_store import read_native_control_floor_for_home
    from .native_policy_snapshot_codec import derive_native_policy_verifier_key
    from .native_policy_snapshot_constants import NATIVE_POLICY_VERIFIER_KEY_NAME, NativePolicySnapshotError

    if encoded_key is None:
        return False
    try:
        key = base64.urlsafe_b64decode(encoded_key.encode("ascii"))
        if len(key) != 32:
            return False
        verifier = derive_native_policy_verifier_key(key)
        marker = read_private_state(guard_home, AUTHORITY_FILE_NAME, AUTHORITY_MAX_BYTES)
        if marker is None:
            return False
        decode_authority(marker, verifier)
        # Never select an old marker's key when the retained anti-rollback
        # floor or resident verifier belongs to a different native identity.
        read_native_control_floor_for_home(guard_home, verifier)
        persisted = read_private_state(guard_home, NATIVE_POLICY_VERIFIER_KEY_NAME, 32)
        return persisted is None or hmac.compare_digest(persisted, verifier)
    except (NativePolicySnapshotError, OSError, ValueError, UnicodeError):
        return False


class MirroredPolicyIntegritySecretStore(FallbackSecretStore):
    """Prefer the system keyring and keep its key usable in a headless session."""

    def __init__(self, primary: SecretStore, fallback: SecretStore, *, guard_home: Path | None = None) -> None:
        super().__init__(primary, fallback)
        self._guard_home = guard_home

    def _read_primary(self, secret_id: str) -> str | None:
        if isinstance(self.primary, SystemKeyringSecretStore):
            return self.primary.get_secret_with_timeout(
                secret_id, timeout_seconds=_POLICY_INTEGRITY_PRIMARY_SECRET_TIMEOUT_SECONDS
            )
        return self.primary.get_secret(secret_id)

    def _read_or_none(self, secret_store: SecretStore, secret_id: str) -> str | None:
        try:
            return self._read_primary(secret_id) if secret_store is self.primary else secret_store.get_secret(secret_id)
        except Exception:
            return None

    def _policy_refs(self, secret_id: str) -> tuple[str, str] | None:
        if self._guard_home is None:
            return None
        for prefix in (_POLICY_INTEGRITY_KEY_REF, _POLICY_INTEGRITY_CONTROL_REF):
            if secret_id.startswith(f"{prefix}:"):
                suffix = secret_id[len(prefix) :]
                return f"{_POLICY_INTEGRITY_KEY_REF}{suffix}", f"{_POLICY_INTEGRITY_CONTROL_REF}{suffix}"
        return None

    def _policy_source(
        self, primary_key: str | None, fallback_key: str | None
    ) -> Literal["primary", "fallback", "unverified"]:
        from .native_command_control_authority import AUTHORITY_FILE_NAME
        from .native_policy_snapshot_constants import (
            _RUST_GENERATION_FLOOR_NAME,
            _RUST_SNAPSHOT_STATE_NAME,
            NATIVE_POLICY_VERIFIER_KEY_NAME,
            NATIVE_RUNTIME_STATE_DIRECTORY,
        )

        if primary_key is None and fallback_key is not None:
            return "fallback"
        if primary_key == fallback_key or self._guard_home is None:
            return "primary"
        state = self._guard_home / NATIVE_RUNTIME_STATE_DIRECTORY
        # A dangling symlink is suspicious retained state, not a fresh home.
        armed = any(
            os.path.lexists(state / name)
            for name in (
                AUTHORITY_FILE_NAME,
                NATIVE_POLICY_VERIFIER_KEY_NAME,
                _RUST_SNAPSHOT_STATE_NAME,
                _RUST_GENERATION_FLOOR_NAME,
            )
        )
        if not armed or _matches_native_authority(self._guard_home, primary_key):
            return "primary"
        if _matches_native_authority(self._guard_home, fallback_key):
            return "fallback"
        return "unverified"

    def _get_policy_value(self, secret_id: str, refs: tuple[str, str]) -> str | None:
        """Read the key and control metadata from the same authenticated origin."""

        key_ref, control_ref = refs
        primary_key = self._read_or_none(self.primary, key_ref)
        fallback_key = self._read_or_none(self.fallback, key_ref)
        source = self._policy_source(primary_key, fallback_key)
        if secret_id == key_ref and primary_key == fallback_key:
            return primary_key
        if source == "fallback":
            return fallback_key if secret_id == key_ref else self._read_or_none(self.fallback, control_ref)
        primary_control = self._read_or_none(self.primary, control_ref)
        if source == "unverified":
            # Preserve both identities for explicit recovery. Downstream native
            # verification still rejects an unauthenticated selected key.
            return primary_key if secret_id == key_ref else primary_control
        fallback_control = self._read_or_none(self.fallback, control_ref)
        if primary_control is None and primary_key == fallback_key:
            primary_control = fallback_control
        try:
            if primary_control is not None:
                if primary_control != fallback_control:
                    self.fallback.set_secret(control_ref, primary_control)
            elif fallback_control is not None and primary_key != fallback_key:
                # Do not leave an old generation paired with a new key when
                # its matching primary control metadata is unavailable.
                return primary_key if secret_id == key_ref else None
            if primary_key is not None and primary_key != fallback_key:
                # Mirror matching metadata first. If that fails, never replace
                # the fallback key and leave it paired with another identity.
                self.fallback.set_secret(key_ref, primary_key)
        except Exception:
            # Mirroring is best effort; the next read re-attempts it after the
            # verified source check, so a failed copy is never silent damage.
            _store_logger.debug("Policy-integrity fallback mirror update failed.", exc_info=True)
        return primary_key if secret_id == key_ref else primary_control

    def get_secret(self, secret_id: str) -> str | None:
        refs = self._policy_refs(secret_id)
        if refs is not None:
            return self._get_policy_value(secret_id, refs)
        primary_value = self._read_or_none(self.primary, secret_id)
        if primary_value is not None:
            with suppress(Exception):
                if self.fallback.get_secret(secret_id) != primary_value:
                    self.fallback.set_secret(secret_id, primary_value)
            return primary_value
        return self._read_or_none(self.fallback, secret_id)

    def set_secret(self, secret_id: str, value: str) -> None:
        refs = self._policy_refs(secret_id)
        if refs is not None and secret_id == refs[1]:
            source = self._policy_source(
                self._read_or_none(self.primary, refs[0]), self._read_or_none(self.fallback, refs[0])
            )
            if source == "fallback":
                self.fallback.set_secret(secret_id, value)
                return
            if source == "unverified":
                raise RuntimeError("policy identity could not be verified for a control-state update")
        self.primary.set_secret(secret_id, value)
        with suppress(Exception):
            self.fallback.set_secret(secret_id, value)

    def delete_secret(self, secret_id: str) -> None:
        self.primary.delete_secret(secret_id)
        try:
            remaining = self._read_primary(secret_id)
        except Exception as error:
            raise RuntimeError("policy integrity keyring deletion could not be verified") from error
        if remaining is not None:
            raise RuntimeError("policy integrity keyring deletion did not persist")
        self.fallback.delete_secret(secret_id)
        if self.fallback.get_secret(secret_id) is not None:
            raise RuntimeError("policy integrity vault deletion did not persist")


def build_policy_integrity_secret_store(
    guard_home: Path,
    *,
    allow_system_keyring: bool = False,
) -> SecretStore | None:
    """Return a prompt-safe policy-integrity store for the current platform."""

    if sys.platform == "darwin":
        return _base_policy_integrity_secret_store(
            guard_home,
            allow_system_keyring=allow_system_keyring,
        )

    if sys.platform != "linux":
        return _base_policy_integrity_secret_store(
            guard_home,
            allow_system_keyring=allow_system_keyring,
        )

    fallback = EncryptedFileSecretStore(guard_home)
    if SystemKeyringSecretStore._backend_is_available():
        return MirroredPolicyIntegritySecretStore(
            SystemKeyringSecretStore(service_name=_POLICY_INTEGRITY_SERVICE_NAME),
            fallback,
            guard_home=guard_home,
        )
    return fallback


__all__ = ["build_policy_integrity_secret_store"]
