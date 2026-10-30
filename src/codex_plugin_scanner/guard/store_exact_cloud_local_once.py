"""Request-bound persistence access for purpose-separated exact Cloud grants."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol

from .native_store_policy import encode_key


class _NativeStoreOwner(Protocol):
    def _native_store_call(self, method: str, args: Mapping[str, object]) -> Any: ...

    def _policy_integrity_secret_material(self, *, create: bool) -> tuple[bytes | None, str | None]: ...


class StoreExactCloudLocalOnceMixin:
    def peek_exact_cloud_local_once_approval(
        self: _NativeStoreOwner,
        *,
        request_id: str,
        now: str,
    ) -> dict[str, object] | None:
        # The resident finds the row through the resolved request it answers,
        # verifies it under the exact Cloud purpose and reads the authority
        # revision in one snapshot. The key stays with the keyring here.
        key, key_id = self._policy_integrity_secret_material(create=False)
        if key is None or key_id is None:
            return None
        decision = self._native_store_call(
            "peek_exact_cloud_local_once_approval",
            {
                "request_id": request_id,
                "now": now,
                "integrity_key_b64": encode_key(key),
                "integrity_key_id": key_id,
            },
        )
        return dict(decision) if isinstance(decision, Mapping) else None


__all__ = ["StoreExactCloudLocalOnceMixin"]
