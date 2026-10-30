"""Request-bound persistence access for purpose-separated exact Cloud grants."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Mapping
from typing import Any, Protocol

from .native_store_policy import encode_key
from .project_identity import _process_directory

_LOOKUP_KEY_FIELDS = ("integrity_key_b64", "local_once_integrity_key_b64")


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
        args, evidence_error = _live_authority_args(self, request, now=now)
        # Never retried: the lookup records a refused row's integrity audit.
        decision = self._native_store_call("codex_live_allow_authority", args)
        if isinstance(decision, Mapping):
            return dict(decision)
        if evidence_error is not None:
            raise evidence_error
        return None

    def complete_codex_live_decision(
        self: _NativeStoreOwner,
        request: Mapping[str, object],
        *,
        now: str,
        fresh_allow_authorized: bool,
    ) -> dict[str, object]:
        # The resident checks the decision, reads an allow's exact authority,
        # spends it and records the waiting hook's continuation in one call.
        evidence_error: Exception | None = None
        if fresh_allow_authorized and request.get("resolution_action") == "allow":
            args, evidence_error = _live_authority_args(self, request, now=now)
        else:
            args = {"request_id": request["request_id"], "now": now, "cwd": _process_directory()}
        args["fresh_allow_authorized"] = fresh_allow_authorized
        # Never retried: the lookup records a refused row's integrity audit.
        result = self._native_store_call("complete_codex_live_decision", args)
        if not isinstance(result, Mapping):
            return {"completed": False, "error": "continuation_not_recorded"}
        if evidence_error is not None and result.get("error") == "exact_approval_authority_missing":
            raise evidence_error
        return dict(result)

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


def _live_authority_args(
    owner: _NativeStoreOwner, request: Mapping[str, object], *, now: str
) -> tuple[dict[str, object], Exception | None]:
    """The authority arguments of a Codex live allow, and any evidence error.

    The lookup is only the fallback: evidence that cannot be gathered must not
    hide the exact Cloud allow the resident reads first.
    """
    args: dict[str, object] = {"request_id": request["request_id"], "now": now, "cwd": _process_directory()}
    evidence_error: Exception | None = None
    lookup: dict[str, object] | None = None
    try:
        evidence = owner.policy_lookup_evidence(now=now)
    except (OSError, RuntimeError, ValueError, sqlite3.Error) as error:
        evidence_error = error
    else:
        if evidence.degraded_trust_status is None:
            lookup = owner.policy_decision_lookup_request(
                evidence,
                harness=str(request["harness"]),
                artifact_id=_text(request.get("artifact_id")),
                artifact_hash=_text(request.get("artifact_hash")),
                workspace=_text(request.get("workspace")),
                publisher=_text(request.get("publisher")),
                runtime_exact_match_context=None,
                consume_one_shot=False,
            )
    # Read after the evidence, which may mint the key the lookup names.
    key, key_id = owner._policy_integrity_secret_material(create=False)
    if key is not None and key_id is not None:
        owner._provision_resident_verifier(key)
        args["integrity_key_b64"] = encode_key(key)
        args["integrity_key_id"] = key_id
    if lookup is not None:
        # Key bytes travel only at the top level, which the request digest
        # never covers; the resident restores them into the lookup.
        for field in _LOOKUP_KEY_FIELDS:
            lookup.pop(field, None)
        args["lookup"] = lookup
    return args, evidence_error


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


__all__ = ["StoreExactCloudLocalOnceMixin"]
