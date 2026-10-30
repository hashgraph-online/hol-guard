"""Request-bound persistence access for purpose-separated exact Cloud grants."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any, Protocol

from .native_store_policy import encode_key
from .project_identity import _process_directory


class _NativeStoreOwner(Protocol):
    def _native_store_call(self, method: str, args: Mapping[str, object]) -> Any: ...

    def _policy_integrity_secret_material(self, *, create: bool) -> tuple[bytes | None, str | None]: ...

    def _provision_resident_verifier(self, key: bytes | None = None) -> None: ...

    policy_lookup_evidence: Callable[..., Any]

    policy_decision_lookup_request: Callable[..., dict[str, object]]


class StoreExactCloudLocalOnceMixin:
    def codex_live_allow_authority(
        self: _NativeStoreOwner, request: Mapping[str, object], *, now: str
    ) -> dict[str, object] | None:
        # The resident reads the request's exact Cloud allow and otherwise the
        # non-consuming lookup composed with the workspace's portable project
        # memory, in one call. The keyring and the integrity-state refresh
        # stay here.
        request_id = request["request_id"]
        args: dict[str, object] = {"request_id": request_id, "now": now, "cwd": _process_directory()}
        key, key_id = self._policy_integrity_secret_material(create=False)
        if key is not None and key_id is not None:
            self._provision_resident_verifier(key)
            args["integrity_key_b64"] = encode_key(key)
            args["integrity_key_id"] = key_id
        evidence = self.policy_lookup_evidence(now=now)
        if evidence.degraded_trust_status is None:
            args["lookup"] = self.policy_decision_lookup_request(
                evidence,
                harness=str(request["harness"]),
                artifact_id=_text(request.get("artifact_id")),
                artifact_hash=_text(request.get("artifact_hash")),
                workspace=_text(request.get("workspace")),
                publisher=_text(request.get("publisher")),
                runtime_exact_match_context=None,
                consume_one_shot=False,
            )
        # Never retried: the lookup records a refused row's integrity audit.
        decision = self._native_store_call("codex_live_allow_authority", args)
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


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


__all__ = ["StoreExactCloudLocalOnceMixin"]
