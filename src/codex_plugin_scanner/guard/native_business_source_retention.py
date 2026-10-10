"""Independent local source marker retention, without provider credential custody.

Use the existing policy-integrity backend. Mirrored copies must agree; neither
an unavailable copy nor an older fallback is interpreted as a fresh install.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .native_business_source_anchor_bridge import MAX_ANCHOR_BYTES
from .native_policy_snapshot_constants import NativePolicySnapshotError
from .store_base import FallbackSecretStore, SystemKeyringSecretStore
from .store_policy_integrity_windows import WindowsPolicyIntegritySecretStore

if TYPE_CHECKING:
    from .store import GuardStore
    from .store_base import SecretStore


def _invalid() -> NativePolicySnapshotError:
    return NativePolicySnapshotError("native_business_source_retention_unavailable")


def _copies(store: GuardStore) -> tuple[SecretStore, ...]:
    backend = store._policy_integrity_secret_store
    if backend is None:
        raise _invalid()
    # The Windows vault is the single source of truth; Credential Manager only
    # holds legacy keys and is unreachable from SSH and service sessions.
    if isinstance(backend, FallbackSecretStore) and not isinstance(backend, WindowsPolicyIntegritySecretStore):
        return backend.primary, backend.fallback
    return (backend,)


def _ref(store: GuardStore) -> str:
    # Dedicated namespace: do not trigger legacy key/control pairing rules.
    return store._build_scoped_secret_ref("hol-guard-business-source-anchor-v1")


def _read(copy: SecretStore, reference: str) -> str | None:
    try:
        result = (
            copy.get_secret_with_timeout(reference, timeout_seconds=1.0)
            if isinstance(copy, SystemKeyringSecretStore)
            else copy.get_secret(reference)
        )
        if result is not None and (type(result) is not str or len(result.encode("utf-8")) > MAX_ANCHOR_BYTES):
            raise _invalid()
        return result
    except Exception:
        raise _invalid() from None


def read_retained_business_source_anchor(store: GuardStore) -> bytes | None:
    values = read_retained_business_source_anchor_copies(store)
    if any(value != values[0] for value in values):
        raise NativePolicySnapshotError("native_business_source_retention_conflict")
    return values[0]


def read_retained_business_source_anchor_copies(store: GuardStore) -> tuple[bytes | None, ...]:
    """Recovery must authenticate every copy; unavailable copies still refuse."""
    return tuple(
        None if value is None else value.encode("utf-8")
        for value in (_read(copy, _ref(store)) for copy in _copies(store))
    )


def write_retained_business_source_anchor(store: GuardStore, wire: bytes) -> None:
    if type(wire) is not bytes or not wire or len(wire) > MAX_ANCHOR_BYTES:
        raise _invalid()
    try:
        value = wire.decode("utf-8")
        for copy in _copies(store):
            copy.set_secret(_ref(store), value)
    except Exception:
        raise _invalid() from None
    if read_retained_business_source_anchor(store) != wire:
        raise NativePolicySnapshotError("native_business_source_retention_write_mismatch")
