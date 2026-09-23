"""Platform policy-integrity secret-store selection.

Keep local policy integrity usable on desktop Linux when the Python keyring
backend changes between daemon and terminal sessions. Mirror a readable legacy
keyring secret into the owner-only local vault before either process uses it.
"""

from __future__ import annotations

import sys
from contextlib import suppress
from pathlib import Path

from .store_base import (
    _POLICY_INTEGRITY_PRIMARY_SECRET_TIMEOUT_SECONDS,
    _POLICY_INTEGRITY_SERVICE_NAME,
    EncryptedFileSecretStore,
    FallbackSecretStore,
    SecretStore,
    SystemKeyringSecretStore,
)
from .store_base import (
    _build_policy_integrity_secret_store as _base_policy_integrity_secret_store,
)


class MirroredPolicyIntegritySecretStore(FallbackSecretStore):
    """Prefer the system keyring and keep its key usable in a headless session."""

    def _read_primary(self, secret_id: str) -> str | None:
        if isinstance(self.primary, SystemKeyringSecretStore):
            return self.primary.get_secret_with_timeout(
                secret_id, timeout_seconds=_POLICY_INTEGRITY_PRIMARY_SECRET_TIMEOUT_SECONDS
            )
        return self.primary.get_secret(secret_id)

    def get_secret(self, secret_id: str) -> str | None:
        try:
            primary_value = self._read_primary(secret_id)
        except Exception:
            primary_value = None
        if primary_value is not None:
            with suppress(Exception):
                if self.fallback.get_secret(secret_id) != primary_value:
                    self.fallback.set_secret(secret_id, primary_value)
            return primary_value
        try:
            return self.fallback.get_secret(secret_id)
        except Exception:
            return None

    def set_secret(self, secret_id: str, value: str) -> None:
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
        )
    return fallback


__all__ = ["build_policy_integrity_secret_store"]
