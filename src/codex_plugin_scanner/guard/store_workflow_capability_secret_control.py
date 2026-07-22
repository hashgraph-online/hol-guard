"""Credential-store boundary for external workflow-capability control."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from .store_base import SecretStore, SystemKeyringSecretStore


class StoreWorkflowCapabilitySecretControlMixin:
    @property
    def _policy_integrity_secret_store(self) -> SystemKeyringSecretStore | None:
        raise NotImplementedError

    @staticmethod
    def _should_skip_policy_integrity_keychain_access(secret_store: SecretStore) -> bool:
        _ = secret_store
        raise NotImplementedError

    def _build_scoped_secret_ref(self, prefix: str) -> str:
        _ = prefix
        raise NotImplementedError

    def _get_policy_integrity_secret_from_store(self, secret_id: str) -> str | None:
        _ = secret_id
        raise NotImplementedError

    def _load_workflow_capability_control(self) -> str | None:
        secret_store = self._policy_integrity_secret_store
        if secret_store is None or self._should_skip_policy_integrity_keychain_access(secret_store):
            return None
        reference = self._build_scoped_secret_ref("guard-workflow-capability-control")
        return self._get_policy_integrity_secret_from_store(reference)

    def _store_workflow_capability_control(self, encoded: str) -> bool:
        secret_store = self._policy_integrity_secret_store
        if secret_store is None or self._should_skip_policy_integrity_keychain_access(secret_store):
            return False
        reference = self._build_scoped_secret_ref("guard-workflow-capability-control")
        try:
            secret_store.set_secret(reference, encoded)
        except Exception:
            return False
        return self._get_policy_integrity_secret_from_store(reference) == encoded
