"""Request-bound persistence access for purpose-separated exact Cloud grants."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol

from .native_guard_store import NativeGuardStoreUnavailable
from .native_store_policy import encode_key

_NO_ANSWER = "native_guard_store_unavailable"


class _NativeStoreOwner(Protocol):
    def _native_store_call(self, method: str, args: Mapping[str, object]) -> Any: ...

    def _policy_integrity_secret_material(self, *, create: bool) -> tuple[bytes | None, str | None]: ...

    def _provision_resident_verifier(self, key: bytes | None = None) -> None: ...


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
        self._provision_resident_verifier(key)
        args = {
            "request_id": request_id,
            "now": now,
            "integrity_key_b64": encode_key(key),
            "integrity_key_id": key_id,
        }
        decision = _read(self, "peek_exact_cloud_local_once_approval", args)
        return dict(decision) if isinstance(decision, Mapping) else None

    def settle_claimed_native_allow(
        self: _NativeStoreOwner,
        *,
        harness: str,
        artifact_id: str,
        workspace: str | None,
        identity: str,
        claimed_saved_allow_hash: str,
        claimed_approval_request_id: str | None,
        claim_saved_approval: bool,
        now: str,
    ) -> bool:
        # The resident checks the claimed identity, peeks the exact local-once
        # allow, spends it or falls back to the request's exact Cloud allow in
        # one call. The key stays with the keyring here.
        key, key_id = self._policy_integrity_secret_material(create=False)
        if key is None or key_id is None:
            return False
        # The resident serves only once its verifier exists; a restart that
        # lost it is restored from the keyring key, as the lookup does.
        self._provision_resident_verifier(key)
        args = {
            "harness": harness,
            "artifact_id": artifact_id,
            "workspace": workspace,
            "identity": identity,
            "claimed_saved_allow_hash": claimed_saved_allow_hash,
            "claimed_approval_request_id": claimed_approval_request_id,
            "claim_saved_approval": claim_saved_approval,
            "now": now,
            "integrity_key_b64": encode_key(key),
            "integrity_key_id": key_id,
        }
        # Never retried: a claim spends the approval, and even a live
        # completion's lookup records a refused row's integrity audit, so a
        # call whose reply was lost may already have landed.
        return self._native_store_call("settle_claimed_native_allow", args) is True


def _read(owner: _NativeStoreOwner, method: str, args: Mapping[str, object]) -> Any:
    try:
        return owner._native_store_call(method, args)
    except NativeGuardStoreUnavailable as error:
        if error.reason != _NO_ANSWER:
            raise
    # A read changes nothing, so a resident that dropped one round trip
    # (a restart, a busy socket) gets one more.
    return owner._native_store_call(method, args)


__all__ = ["StoreExactCloudLocalOnceMixin"]
