"""Generated production-key authority in a disposable qualification store.

The concrete bootstrap/read/lock APIs are shared by pinned baseline 2e672d2
and the candidate. This is fixture provisioning, not interactive enrollment.
"""

from __future__ import annotations

from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_base import EncryptedFileSecretStore


def verify_empty_command_authority(store: GuardStore) -> dict[str, str]:
    view = store.read_extension_control_authority(catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest)
    return _verified_empty_view(view)


def _verified_empty_view(view: ExtensionControlAuthorityView) -> dict[str, str]:
    if view.health is not AuthorityHealth.PROTECTED or view.revision != 0 or view.layers:
        raise RuntimeError("qualification command authority is not verified empty protected state")
    return {
        "provisioning": "isolated_ci_generated_key_empty_authority",
        "enrollment_flow": "not_exercised",
        "verified_health": view.health.value,
    }


def prepare_empty_command_authority(store: GuardStore) -> dict[str, str]:
    store._extension_control_authority_secret_store = EncryptedFileSecretStore(store.guard_home)
    catalog = BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    with store._extension_control_authority_lock():
        # The pinned baseline lock is not reentrant. Both releases expose the
        # concrete locked reader, so keep the entire bootstrap interval under
        # one real lease without calling the public lock-taking reader again.
        current = store._read_extension_control_authority_locked(catalog)
        if current.health is not AuthorityHealth.UNENROLLED:
            raise RuntimeError("qualification command authority must be freshly unenrolled")
        store._bootstrap_extension_control_authority(catalog, key=None)
        return _verified_empty_view(store._read_extension_control_authority_locked(catalog))
