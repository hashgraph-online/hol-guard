"""Platform policy-integrity secret-store selection.

Keep local policy integrity usable on desktop Linux even when the Python keyring
backend is missing or unavailable. When a system keyring is available it remains
the authoritative rollback-control backend; only hosts without a usable keyring
fall back to Guard's owner-only encrypted local vault.
"""

from __future__ import annotations

import sys
from pathlib import Path

from .store_base import (
    _POLICY_INTEGRITY_SERVICE_NAME,
    EncryptedFileSecretStore,
    MigratingFallbackSecretStore,
    SecretStore,
    SystemKeyringSecretStore,
)
from .store_base import (
    _build_policy_integrity_secret_store as _base_policy_integrity_secret_store,
)


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

    if SystemKeyringSecretStore._backend_is_available():
        return MigratingFallbackSecretStore(
            SystemKeyringSecretStore(service_name=_POLICY_INTEGRITY_SERVICE_NAME),
            EncryptedFileSecretStore(guard_home),
        )
    return EncryptedFileSecretStore(guard_home)


__all__ = ["build_policy_integrity_secret_store"]
