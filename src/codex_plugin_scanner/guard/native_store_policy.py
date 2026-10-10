"""Resident bridge for the store-policy ops: reuse claim and miss diagnostic.

Rust owns the authority for both. ``GuardStore`` only procures the
OS-keyring-facing integrity evidence (state and HMAC keys), ships it with the
request, and decodes the answer. A missing, malformed or mismatched reply is
never a reason to recompute anything in Python: the claim reports ``False`` and
the diagnostic raises ``ValueError``.
"""

from __future__ import annotations

import base64
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from uuid import uuid4

from .native_context import _canonical_request_sha256
from .native_execution import _resident_request

CLAIM_APPROVAL_REUSE_FEATURE = "claim-approval-reuse-v1"
APPROVAL_REUSE_DIAGNOSTIC_FEATURE = "approval-reuse-diagnostic-v1"
_CLAIM_REQUEST_SCHEMA = "guard-claim-approval-reuse-request.v1"
_CLAIM_RESULT_SCHEMA = "guard-claim-approval-reuse-result.v1"
_DIAGNOSTIC_REQUEST_SCHEMA = "guard-approval-reuse-diagnostic-request.v1"
_DIAGNOSTIC_RESULT_SCHEMA = "guard-approval-reuse-diagnostic-result.v1"
_CLAIM_MAX_BYTES = 512 * 1024
_TIMEOUT_SECONDS = 10.0
DIAGNOSTIC_UNAVAILABLE = "native_approval_reuse_diagnostic_unavailable"

IntegrityEvidence = Mapping[str, object]
EvidenceProvider = Callable[[bool, bool], IntegrityEvidence]


def encode_key(key: bytes | None) -> str | None:
    return base64.urlsafe_b64encode(key).rstrip(b"=").decode("ascii") if key is not None else None


def _payload(response: dict[str, object] | None, request: dict[str, object]) -> dict[str, object] | None:
    """The ``ok`` payload of a reply bound to ``request``, else ``None``."""

    if response is None:
        return None
    try:
        digest = "sha256:" + _canonical_request_sha256(request)
    except (TypeError, ValueError):
        return None
    if (
        response.get("request_id") != request["request_id"]
        or response.get("request_sha256") != digest
        or response.get("status") != "ok"
        or response.get("code") != "ok"
    ):
        return None
    payload = response.get("payload")
    return payload if isinstance(payload, dict) else None


def native_claim_approval_reuse_decisions(
    *,
    store_path: Path | str,
    guard_home: Path,
    decisions: Sequence[Mapping[str, object]],
    now: str,
    evidence: IntegrityEvidence,
) -> bool:
    """Ask the resident to claim a batch of saved allows; ``False`` on no answer."""

    request: dict[str, object] = {
        "schema": _CLAIM_REQUEST_SCHEMA,
        "request_id": f"claim-approval-reuse-{uuid4().hex}",
        "store_path": str(store_path),
        "guard_home": str(guard_home),
        "decisions": [dict(decision) for decision in decisions],
        "now": now,
        **{key: value for key, value in evidence.items() if value is not None},
    }
    try:
        response = _resident_request(
            operation="claim_approval_reuse_decisions",
            request=request,
            guard_home=guard_home,
            timeout_seconds=_TIMEOUT_SECONDS,
            required_feature=CLAIM_APPROVAL_REUSE_FEATURE,
            response_schema=_CLAIM_RESULT_SCHEMA,
            max_request_bytes=_CLAIM_MAX_BYTES,
            record_success=False,
        )
    except (TypeError, ValueError):
        return False
    payload = _payload(response, request)
    return payload is not None and payload.get("claimed") is True


def native_approval_reuse_diagnostic(
    *,
    store_path: Path | str,
    guard_home: Path,
    harness: str,
    artifact_id: str,
    artifact_hash: str | None,
    workspace: str | None,
    publisher: str | None,
    now: str,
    evidence_provider: EvidenceProvider,
) -> tuple[str | None, str | None]:
    """Diagnose a saved-allow miss as ``(reason, stored_hash)``.

    The first call carries no evidence; when the resident finds rows whose
    integrity it must verify it answers with a ``need`` naming the evidence, the
    provider supplies it, and the identical request is repeated with it.
    """

    request: dict[str, object] = {
        "schema": _DIAGNOSTIC_REQUEST_SCHEMA,
        "request_id": f"approval-reuse-diagnostic-{uuid4().hex}",
        "store_path": str(store_path),
        "guard_home": str(guard_home),
        "harness": harness,
        "artifact_id": artifact_id,
        "artifact_hash": artifact_hash,
        "workspace": workspace,
        "publisher": publisher,
        "now": now,
    }
    for _attempt in range(2):
        try:
            response = _resident_request(
                operation="approval_reuse_diagnostic",
                request=request,
                guard_home=guard_home,
                timeout_seconds=_TIMEOUT_SECONDS,
                required_feature=APPROVAL_REUSE_DIAGNOSTIC_FEATURE,
                response_schema=_DIAGNOSTIC_RESULT_SCHEMA,
                record_success=False,
            )
        except (TypeError, ValueError):
            break
        payload = _payload(response, request)
        if payload is None:
            break
        if payload.get("need") == "integrity_evidence" and "evidence" not in request:
            evidence = evidence_provider(payload.get("policy") is True, payload.get("local_once") is True)
            request["evidence"] = {key: value for key, value in evidence.items() if value is not None}
            continue
        reason, stored_hash = payload.get("reason"), payload.get("stored_hash")
        if set(payload) == {"reason", "stored_hash"} and all(
            value is None or isinstance(value, str) for value in (reason, stored_hash)
        ):
            return reason, stored_hash  # type: ignore[return-value]
        break
    raise ValueError(DIAGNOSTIC_UNAVAILABLE)
