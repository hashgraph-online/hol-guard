"""Windows policy-integrity key storage.

Credential Manager is unreachable from logon sessions that carry no
credentials, such as OpenSSH key authentication and S4U scheduled tasks. The
encrypted vault under the Guard home is the only store every session can read,
so it is the source of truth on Windows. Credential Manager is read only to
import a key that an earlier release stored there. Each import moves the key,
so the two stores never hold competing current keys.
"""

from __future__ import annotations

from .store_base import FallbackSecretStore, SystemKeyringSecretStore, _store_logger


class CredentialManagerUnreachableError(RuntimeError):
    """This logon session cannot open Credential Manager."""


class WindowsPolicyIntegritySecretStore(FallbackSecretStore):
    """Keep the policy-integrity key in the local vault on Windows."""

    primary: SystemKeyringSecretStore

    def _read_legacy(self, secret_id: str) -> str | None:
        keyring_module = self.primary._load_keyring_module_or_none()
        if keyring_module is None:
            return None
        try:
            value = keyring_module.get_password(self.primary.service_name, secret_id)
        except Exception as error:
            if self.primary._is_windows_keyring_session_unavailable(error):
                raise CredentialManagerUnreachableError(
                    "Credential Manager is not available in this Windows logon session."
                ) from error
            raise
        return value if isinstance(value, str) and value else None

    def _delete_legacy(self, secret_id: str) -> None:
        keyring_module = self.primary._load_keyring_module_or_none()
        if keyring_module is None:
            return
        try:
            keyring_module.delete_password(self.primary.service_name, secret_id)
        except Exception:
            _store_logger.debug("Policy-integrity Credential Manager delete failed.", exc_info=True)
        if self._read_legacy(secret_id) is not None:
            raise RuntimeError("policy integrity Credential Manager deletion did not persist")

    def get_secret(self, secret_id: str) -> str | None:
        value = self.fallback.get_secret(secret_id)
        if value is not None:
            return value
        try:
            legacy = self._read_legacy(secret_id)
        except CredentialManagerUnreachableError:
            # Key creation refuses a home that already has native identity
            # state, so a key an earlier session left in Credential Manager is
            # imported later rather than replaced.
            return None
        if legacy is None:
            return None
        self.fallback.set_secret(secret_id, legacy)
        try:
            self._delete_legacy(secret_id)
        except Exception:
            _store_logger.debug("Imported policy-integrity value is still in Credential Manager.", exc_info=True)
        return legacy

    def get_secret_no_ui(self, secret_id: str) -> str | None:
        return self.get_secret(secret_id)

    def set_secret(self, secret_id: str, value: str) -> None:
        self.fallback.set_secret(secret_id, value)

    def promote_secret(self, secret_id: str, value: str) -> None:
        return None

    def delete_secret(self, secret_id: str) -> None:
        # Remove any legacy copy first. If this session cannot reach Credential
        # Manager, refuse rather than let a later session import the old key.
        try:
            self._delete_legacy(secret_id)
        except CredentialManagerUnreachableError as error:
            raise CredentialManagerUnreachableError(
                "Credential Manager is not available in this Windows logon session, so an older copy of the "
                "policy-integrity key cannot be removed. Run the reset from an interactive Windows session."
            ) from error
        self.fallback.delete_secret(secret_id)
        if self.fallback.get_secret(secret_id) is not None:
            raise RuntimeError("policy integrity vault deletion did not persist")


__all__ = ["CredentialManagerUnreachableError", "WindowsPolicyIntegritySecretStore"]
