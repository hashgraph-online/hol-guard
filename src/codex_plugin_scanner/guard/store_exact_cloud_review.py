"""Persistence boundary for replay-safe exact Cloud Review decisions."""

from __future__ import annotations

import os
from collections.abc import Mapping
from contextlib import AbstractContextManager
from typing import Any, Protocol

from .dpop_key_binding import verified_dpop_jwk_thumbprint
from .native_store_policy import integrity_key_fields

_OAUTH_KEY = "oauth_local_credentials"


class _ConnectionOwner(Protocol):
    def hold_oauth_credential_lock(self) -> AbstractContextManager[None]: ...

    def _policy_integrity_secret_material(self, *, create: bool) -> tuple[bytes | None, str | None]: ...

    def _native_store_call(self, method: str, args: Mapping[str, object]) -> Any: ...

    def _load_oauth_secret_payload(
        self,
        payload: dict[str, object],
        *,
        promote: bool = True,
        allow_primary: bool = True,
    ) -> dict[str, object] | None: ...


def _process_cwd() -> str | None:
    """This process's directory, as the approval queue reads pass it."""

    try:
        return os.getcwd()
    except OSError:
        return None


def _exact_dpop_thumbprint(owner: _ConnectionOwner) -> str | None:
    """The DPoP thumbprint this install's stored OAuth secret actually proves.

    The secret store and the key check stay here, where the keychain lives.
    The resident takes the verified thumbprint and rebuilds the binding from
    the credential row it reads inside the write transaction, so a
    credential that rotates in between cannot match what the cloud signed.
    """

    oauth_state = owner._native_store_call("get_sync_payload", {"state_key": _OAUTH_KEY})
    if not isinstance(oauth_state, dict):
        return None
    oauth_secret = owner._load_oauth_secret_payload(oauth_state, promote=False, allow_primary=False)
    if not isinstance(oauth_secret, dict):
        return None
    try:
        thumbprint = verified_dpop_jwk_thumbprint(
            private_key_pem=oauth_secret.get("dpop_private_key_pem"),
            public_jwk=oauth_secret.get("dpop_public_jwk"),
        )
    except ValueError:
        return None
    if oauth_secret.get("dpop_public_jwk_thumbprint") != thumbprint:
        return None
    return thumbprint


class StoreExactCloudReviewMixin:
    def exact_cloud_review_state(self: _ConnectionOwner) -> dict[str, object]:
        """The stored consent capability and revocation, each as parsed JSON or None."""

        payload = self._native_store_call("exact_cloud_review_state", {})
        if not isinstance(payload, dict):
            raise RuntimeError("Guard exact Cloud Review state was not read.")
        return {"capability": payload.get("capability"), "revocation": payload.get("revocation")}

    def replace_exact_cloud_review_state(
        self: _ConnectionOwner,
        *,
        capability: dict[str, object] | None,
        revocation: dict[str, object] | None,
        now: str,
        event_name: str,
        event_payload: dict[str, object],
        expected_capability: object = None,
        require_expected_capability: bool = False,
    ) -> bool:
        """Atomically persist consent state; an expected capability provides CAS."""

        replaced = self._native_store_call(
            "replace_exact_cloud_review_state",
            {
                "capability": capability,
                "revocation": revocation,
                "now": now,
                "event_name": event_name,
                "event_payload": event_payload,
                "expected_capability": expected_capability,
                "require_expected_capability": require_expected_capability,
            },
        )
        return replaced is True

    def has_exact_cloud_review_receipt(self: _ConnectionOwner, receipt_id: str) -> bool:
        return self._native_store_call("has_exact_cloud_review_receipt", {"receipt_id": receipt_id}) is True

    def resolve_one_request_with_signed_remote_exact_result(
        self: _ConnectionOwner,
        request_id: str,
        *,
        receipt_id: str,
        resolution_action: str,
        resolution_scope: str,
        reason: str,
        expected_capability: dict[str, object] | None,
        expected_oauth_binding: dict[str, object],
        expected_request: dict[str, object],
        expected_raw_request: dict[str, object],
        receipt_expires_at: str,
        skip_exact_capability: bool = False,
    ) -> dict[str, object]:
        """Claim and apply an exact receipt after rechecking all mutable state."""

        key_fields: dict[str, object] = {"integrity_key_b64": None, "integrity_key_id": None}
        if resolution_action == "allow":
            integrity_key, integrity_key_id = self._policy_integrity_secret_material(create=True)
            key_fields = integrity_key_fields(
                getattr(self, "_policy_integrity_secret_store", None), integrity_key, integrity_key_id
            )
        with self.hold_oauth_credential_lock():
            # The resident holds one transaction across the consent recheck, the
            # receipt claim, the resolution and the local authority it writes, so
            # a verdict the cloud signed earlier cannot land on an install that
            # has moved since.
            payload = self._native_store_call(
                "apply_signed_remote_exact_result",
                {
                    "request_id": request_id,
                    "receipt_id": receipt_id,
                    "resolution_action": resolution_action,
                    "resolution_scope": resolution_scope,
                    "reason": reason,
                    "receipt_expires_at": receipt_expires_at,
                    "skip_exact_capability": skip_exact_capability,
                    "expected_capability": expected_capability,
                    "expected_oauth_binding": expected_oauth_binding,
                    "expected_request": expected_request,
                    "expected_raw_request": expected_raw_request,
                    "dpop_thumbprint": _exact_dpop_thumbprint(self),
                    # The expected snapshot was read with this process's
                    # directory, which is what resolves a relative config path
                    # into a workspace scope. The recheck reads the request
                    # again, so it resolves from the same place or an unchanged
                    # request reads as stale.
                    "cwd": _process_cwd(),
                    **key_fields,
                },
            )
        if not isinstance(payload, dict):
            raise RuntimeError("Guard exact Cloud Review result was not applied.")
        return payload
