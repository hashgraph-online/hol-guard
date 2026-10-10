"""Resident bridge for the store-policy ops: reuse claim and miss diagnostic.

Rust owns the authority for both. ``GuardStore`` only procures the
OS-keyring-facing integrity evidence (state and HMAC keys), ships it with the
request, and decodes the answer. A missing, malformed or mismatched reply is
never a reason to recompute anything in Python: the claim reports ``False`` and
the diagnostic raises ``ValueError``.
"""

from __future__ import annotations

import base64
import hashlib
import sqlite3
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from uuid import uuid4

from .native_context import _canonical_request_sha256
from .native_execution import _resident_request
from .native_runtime import native_runtime_status
from .native_runtime_resilience import native_record_resident_failure, native_record_resident_success

CLAIM_APPROVAL_REUSE_FEATURE = "claim-approval-reuse-v1"
APPROVAL_REUSE_DIAGNOSTIC_FEATURE = "approval-reuse-diagnostic-v1"
_CLAIM_REQUEST_SCHEMA = "guard-claim-approval-reuse-request.v1"
_CLAIM_RESULT_SCHEMA = "guard-claim-approval-reuse-result.v1"
_DIAGNOSTIC_REQUEST_SCHEMA = "guard-approval-reuse-diagnostic-request.v1"
_DIAGNOSTIC_RESULT_SCHEMA = "guard-approval-reuse-diagnostic-result.v1"
_CLAIM_MAX_BYTES = 512 * 1024
_TIMEOUT_SECONDS = 10.0
DIAGNOSTIC_UNAVAILABLE = "native_approval_reuse_diagnostic_unavailable"
# Store-resident sources a signed policy bundle's validity depends on. The
# resident re-reads every one of them under the claim's write lock and refuses
# the claim when any differs from what the evidence was gathered against.
BUNDLE_STATE_KEYS = (
    "policy_bundle",
    "policy_bundle_keyring",
    "supply_chain_bundle_keyring",
    "managed_policy_bundle_keyring_provenance",
    "policy_bundle_acceptance_checkpoint",
)
_LOCAL_DEVICE_KEY = "local-device"

IntegrityEvidence = Mapping[str, object]
EvidenceProvider = Callable[[bool, bool], IntegrityEvidence]


class ApprovalReuseDiagnosticUnavailableError(ValueError):
    """The resident could not diagnose a saved-allow miss; nothing was recomputed.

    Still a ``ValueError`` whose text is :data:`DIAGNOSTIC_UNAVAILABLE`.
    Callers fail closed on it and never treat the absence of a diagnosis as
    evidence that a saved allow is usable.
    """

    def __init__(self) -> None:
        super().__init__(DIAGNOSTIC_UNAVAILABLE)


def encode_key(key: bytes | None) -> str | None:
    return base64.urlsafe_b64encode(key).rstrip(b"=").decode("ascii") if key is not None else None


def _state_digest(connection: sqlite3.Connection, state_key: str) -> str | None:
    row = connection.execute("select payload_json from sync_state where state_key = ?", (state_key,)).fetchone()
    if row is None or row[0] is None:
        return None
    return hashlib.sha256(str(row[0]).encode("utf-8")).hexdigest()


def claim_evidence_binding(
    connection: sqlite3.Connection,
    *,
    bundle: bool,
    cloud_workspace_id: str | None = None,
) -> dict[str, object]:
    """Name the store-resident sources the claim evidence is gathered against.

    Read this *before* deriving the evidence it binds: a source that moves
    afterwards then differs from the binding when the resident re-reads it
    under the claim's write lock, and the claim is refused.
    """

    binding: dict[str, object] = {"sync_state_sha256": {}}
    if not bundle:
        return binding
    binding["sync_state_sha256"] = {key: _state_digest(connection, key) for key in BUNDLE_STATE_KEYS}
    # Absent values are omitted, not sent as null: the resident re-serializes the
    # request without its unset options, and the reply digest must match.
    if cloud_workspace_id is not None:
        binding["cloud_workspace_id"] = cloud_workspace_id
    device = connection.execute(
        "select installation_id, device_label from guard_devices where device_key = ?",
        (_LOCAL_DEVICE_KEY,),
    ).fetchone()
    if device is not None:
        binding["device"] = {"installation_id": str(device[0]), "device_label": str(device[1])}
    return binding


def _payload(
    response: dict[str, object] | None, request: dict[str, object], guard_home: Path
) -> dict[str, object] | None:
    """The ``ok`` payload of a reply bound to ``request``, else ``None``.

    ``_resident_request`` is called with ``record_success=False``, so resident
    health is recorded here: a reply that binds to the request and carries an
    ``ok`` payload counts as a success, any other reply the resident sent counts
    as a failure.
    """

    if response is None:
        return None
    payload = _bound_payload(response, request)
    identity = native_runtime_status().identity
    if identity is not None:
        if payload is None:
            native_record_resident_failure(identity.sha256, guard_home, reason="native_store_policy_binding")
        else:
            native_record_resident_success(identity.sha256, guard_home)
    return payload


def _bound_payload(response: dict[str, object], request: dict[str, object]) -> dict[str, object] | None:
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
    payload = _payload(response, request, Path(guard_home))
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
        payload = _payload(response, request, Path(guard_home))
        if payload is None:
            break
        if payload.get("need") == "integrity_evidence" and "evidence" not in request:
            evidence = evidence_provider(payload.get("policy") is True, payload.get("local_once") is True)
            request["evidence"] = {key: value for key, value in evidence.items() if value is not None}
            continue
        reason, stored_hash = payload.get("reason"), payload.get("stored_hash")
        if (
            set(payload) == {"reason", "stored_hash"}
            and (reason is None or isinstance(reason, str))
            and (stored_hash is None or isinstance(stored_hash, str))
        ):
            return reason, stored_hash
        break
    raise ApprovalReuseDiagnosticUnavailableError
