"""Resident bridge for local policy-row integrity: batch verify and sign.

Rust owns every canonical payload, SHA-256 digest and HMAC-SHA256 tag through
the resident ``policy_integrity_rows`` op. ``GuardStore`` ships the rows and
the key it already resolved, then stores what comes back. There is no local
computation to fall back to: when the resident is unavailable, or a reply is
unbound or malformed, :class:`NativePolicyIntegrityUnavailableError` is raised
and the caller's operation fails closed.

The same op decides startup's trusted control state from the store's local
rows: :func:`native_prepare_policy_integrity_generation`.

The reply digest binds every request field except ``integrity_key_b64``, so it
never covers key bytes.
"""

from __future__ import annotations

import base64
import json
import os
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from .native_context import _canonical_request_sha256
from .native_execution import _resident_request
from .native_runtime import NativeRuntimeStatus, native_runtime_status
from .native_runtime_resilience import native_record_resident_failure, native_record_resident_success
from .policy_integrity import PolicyIntegrityStatus, PolicyIntegrityVerificationResult

POLICY_INTEGRITY_ROWS_FEATURE = "policy-integrity-rows-v1"
POLICY_INTEGRITY_GENERATION_FEATURE = "policy-integrity-generation-v1"
POLICY_INTEGRITY_RECONCILE_FEATURE = "policy-integrity-reconcile-v1"
_REQUEST_SCHEMA = "guard-policy-integrity-rows-request.v1"
_RESULT_SCHEMA = "guard-policy-integrity-rows-result.v1"
_KEY_FIELD = "integrity_key_b64"
_MAX_ITEMS = 1024
_MAX_REQUEST_BYTES = 4 * 1024 * 1024
# Leaves room under the request cap for the envelope and the key fields.
_CHUNK_BYTES = 3 * 1024 * 1024
_TIMEOUT_SECONDS = 10.0
UNAVAILABLE = "native_policy_integrity_rows_unavailable"
# The columns the resident reads from a row; nothing else is shipped.
_ROW_COLUMNS = (
    "action",
    "artifact_hash",
    "artifact_id",
    "decision_id",
    "expires_at",
    "harness",
    "integrity_generation",
    "integrity_key_id",
    "integrity_version",
    "owner",
    "payload_hash",
    "payload_mac",
    "publisher",
    "reason",
    "scope",
    "signed_at",
    "source",
    "updated_at",
    "workspace",
)
_TALLY_FIELDS = frozenset({"rows", "has_legacy", "pending_candidates", "pending_valid", "current_valid"})
_SIGNATURE_FIELDS = frozenset(
    {"integrity_version", "integrity_generation", "payload_hash", "payload_mac", "integrity_key_id", "signed_at"}
)


class NativePolicyIntegrityUnavailableError(RuntimeError):
    """The resident did not verify or sign; nothing was computed locally."""

    def __init__(self) -> None:
        super().__init__(UNAVAILABLE)


@dataclass(frozen=True, slots=True)
class PolicyRowVerifyItem:
    row: Mapping[str, object]
    degraded_mode: bool
    trusted_generation: int | None = None


@dataclass(frozen=True, slots=True)
class PolicyRowSignItem:
    row: Mapping[str, object]
    generation: int
    signed_at: str


def native_verify_policy_rows(
    *,
    guard_home: Path | str,
    items: Sequence[PolicyRowVerifyItem],
    key: bytes | None,
    key_id: str | None,
) -> list[PolicyIntegrityVerificationResult]:
    """One verification result per item, in order.

    A degraded-mode item is never verified: the resident would only echo the
    row's stored fields under ``degraded_mode``, a status no caller honors. That
    answer is built here, so a home the resident cannot serve, such as a
    symlinked one, still reports its rows as degraded rather than failing.
    Every other item is answered by the resident.
    """

    wire = [_verify_wire(item) for item in items if not item.degraded_mode]
    outcomes = iter(_run(Path(guard_home), key=key, key_id=key_id, field="verify", items=wire))
    return [_degraded(item.row) if item.degraded_mode else _verification(next(outcomes)) for item in items]


def native_sign_policy_rows(
    *,
    guard_home: Path | str,
    items: Sequence[PolicyRowSignItem],
    key: bytes,
    key_id: str,
) -> list[dict[str, object]]:
    """The six integrity columns per item, in order, signed by the resident."""

    wire = [_sign_wire(item) for item in items]
    outcomes = _run(Path(guard_home), key=key, key_id=key_id, field="sign", items=wire)
    return [_signature(outcome, item) for outcome, item in zip(outcomes, items, strict=True)]


def native_prepare_policy_integrity_generation(
    *,
    guard_home: Path,
    store_path: Path,
    key: bytes,
    key_id: str,
    trusted_state: Mapping[str, object],
) -> tuple[dict[str, object], bool]:
    """The control state startup should trust, and whether every local row
    still verifies at ``trusted_state``'s generation.

    The resident reads ``store_path`` read-only, so the caller holds the
    store's shared gate around this call.
    """

    _ensure_verifier_key(guard_home, key)
    request = _request(key=key, key_id=key_id, verify=[], sign=[])
    request["generation"] = {
        "store_path": str(store_path),
        "guard_home": str(guard_home),
        "trusted_state": dict(trusted_state),
    }
    payload = _resident_payload(guard_home, request, required_feature=POLICY_INTEGRITY_GENERATION_FEATURE)
    outcome = payload.get("generation")
    if set(payload) != {"verify", "sign", "generation"} or not isinstance(outcome, dict):
        raise NativePolicyIntegrityUnavailableError()
    if payload["verify"] != [] or payload["sign"] != []:
        raise NativePolicyIntegrityUnavailableError()
    prepared_state, still_matches = outcome.get("prepared_state"), outcome.get("still_matches")
    if set(outcome) != {"prepared_state", "still_matches"} or not isinstance(prepared_state, dict):
        raise NativePolicyIntegrityUnavailableError()
    if not isinstance(still_matches, bool):
        raise NativePolicyIntegrityUnavailableError()
    return prepared_state, still_matches


def native_reconcile_policy_integrity_generation(
    *,
    guard_home: Path,
    key: bytes,
    key_id: str,
    trusted_state: Mapping[str, object],
    rows: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    """The control state the store should trust once the pending generation
    is decided over ``rows``.

    The caller ships its own rows because it holds an open transaction, whose
    rows the resident's read-only connection would not see. The returned state
    equals ``trusted_state`` when nothing about the pending generation changes.

    A store with more rows than one request holds sends them in chunks, the
    same way verify and sign batches are chunked. Each chunk comes back as
    counters that the next one carries, and the last asks for the decision, so
    a large store settles its pending generation instead of failing the request
    and dropping to degraded mode. The resident decides from the totals; this
    passes its counters back untouched.
    """

    _ensure_verifier_key(guard_home, key)
    chunks = _chunks([_wire_row(row) for row in rows]) or [[]]
    carried: dict[str, object] | None = None
    for index, chunk in enumerate(chunks):
        outcome = _reconcile_chunk(
            guard_home,
            key=key,
            key_id=key_id,
            trusted_state=trusted_state,
            rows=chunk,
            carried=carried,
            decide=index == len(chunks) - 1,
        )
        if index == len(chunks) - 1:
            next_state = outcome.get("next_state")
            if set(outcome) != {"next_state"} or not isinstance(next_state, dict):
                raise NativePolicyIntegrityUnavailableError()
            return next_state
        carried = _tally(outcome)
    raise NativePolicyIntegrityUnavailableError()


def _reconcile_chunk(
    guard_home: Path,
    *,
    key: bytes,
    key_id: str,
    trusted_state: Mapping[str, object],
    rows: list[dict[str, object]],
    carried: dict[str, object] | None,
    decide: bool,
) -> Mapping[str, object]:
    request = _request(key=key, key_id=key_id, verify=[], sign=[])
    section: dict[str, object] = {
        "trusted_state": dict(trusted_state),
        "rows": rows,
        "decide": decide,
    }
    if carried is not None:
        section["carried"] = carried
    request["reconcile"] = section
    payload = _resident_payload(guard_home, request, required_feature=POLICY_INTEGRITY_RECONCILE_FEATURE)
    outcome = payload.get("reconcile")
    if set(payload) != {"verify", "sign", "reconcile"} or not isinstance(outcome, dict):
        raise NativePolicyIntegrityUnavailableError()
    if payload["verify"] != [] or payload["sign"] != []:
        raise NativePolicyIntegrityUnavailableError()
    return outcome


def _tally(outcome: Mapping[str, object]) -> dict[str, object]:
    """The resident's running counters, carried unread into the next chunk.

    Nothing here interprets them: the decision over a chunked store is taken by
    the resident from the totals, exactly as it is taken over a store that fits
    in one request.
    """

    tally = outcome.get("tally")
    if set(outcome) != {"tally"} or not isinstance(tally, dict) or set(tally) != _TALLY_FIELDS:
        raise NativePolicyIntegrityUnavailableError()
    if not isinstance(tally["has_legacy"], bool):
        raise NativePolicyIntegrityUnavailableError()
    counts = (tally["rows"], tally["pending_candidates"], tally["pending_valid"], tally["current_valid"])
    if any(isinstance(count, bool) or not isinstance(count, int) or count < 0 for count in counts):
        raise NativePolicyIntegrityUnavailableError()
    return dict(tally)


def _run(
    guard_home: Path,
    *,
    key: bytes | None,
    key_id: str | None,
    field: str,
    items: list[dict[str, object]],
) -> list[Mapping[str, object]]:
    outcomes: list[Mapping[str, object]] = []
    chunks = _chunks(items)
    if chunks and key is not None:
        _ensure_verifier_key(guard_home, key)
    for chunk in chunks:
        outcomes.extend(_request_chunk(guard_home, key=key, key_id=key_id, field=field, items=chunk))
    return outcomes


def _chunks(items: list[dict[str, object]]) -> list[list[dict[str, object]]]:
    chunks: list[list[dict[str, object]]] = []
    current: list[dict[str, object]] = []
    current_bytes = 0
    for item in items:
        size = len(_dumps(item))
        if size > _CHUNK_BYTES:
            raise NativePolicyIntegrityUnavailableError()
        if current and (len(current) >= _MAX_ITEMS or current_bytes + size > _CHUNK_BYTES):
            chunks.append(current)
            current, current_bytes = [], 0
        current.append(item)
        current_bytes += size + 1
    if current:
        chunks.append(current)
    return chunks


def _ensure_verifier_key(guard_home: Path, key: bytes | None) -> None:
    """Provision the home's resident verifier key from the integrity key in hand.

    The resident refuses to start for a home without its verifier key. A store
    can sign or verify rows before any publisher has provisioned it, for
    example on a fresh home, so the key is derived here from the same master
    key the request carries. Provisioning never replaces an existing key, and
    without a key to derive from the request fails closed.
    """

    from .native_policy_snapshot_constants import (
        NATIVE_POLICY_VERIFIER_KEY_NAME,
        NATIVE_RUNTIME_STATE_DIRECTORY,
        NativePolicySnapshotError,
    )

    if (guard_home / NATIVE_RUNTIME_STATE_DIRECTORY / NATIVE_POLICY_VERIFIER_KEY_NAME).is_file():
        return
    if key is None:
        raise NativePolicyIntegrityUnavailableError()
    from .native_policy_snapshot_windows_key import provision_native_policy_verifier_key

    try:
        provision_native_policy_verifier_key(guard_home, key)
    except (NativePolicySnapshotError, OSError, ValueError):
        raise NativePolicyIntegrityUnavailableError() from None


def discard_row_signing_verifier_key(guard_home: Path) -> None:
    """Drop a verifier key that only row signing relied on, after a key reset.

    Row signing provisions the verifier from the integrity key, and a reset
    deletes that key. Left behind, the stale verifier marks the home as armed,
    so the store refuses to mint the replacement key and stays degraded. The
    verifier is kept whenever other native state is bound to it: an armed
    command-control marker, a generation floor or a published snapshot each
    needs its own explicit recovery, not an implicit verifier reset.
    """

    from .native_command_control_authority import AUTHORITY_FILE_NAME
    from .native_policy_snapshot_constants import (
        _RUST_GENERATION_FLOOR_NAME,
        _RUST_SNAPSHOT_STATE_NAME,
        NATIVE_POLICY_VERIFIER_KEY_NAME,
        NATIVE_RUNTIME_STATE_DIRECTORY,
    )

    state = guard_home / NATIVE_RUNTIME_STATE_DIRECTORY
    bound = (AUTHORITY_FILE_NAME, _RUST_GENERATION_FLOOR_NAME, _RUST_SNAPSHOT_STATE_NAME)
    if any(os.path.lexists(state / name) for name in bound):
        return
    with suppress(FileNotFoundError):
        os.unlink(state / NATIVE_POLICY_VERIFIER_KEY_NAME)


def _request_chunk(
    guard_home: Path,
    *,
    key: bytes | None,
    key_id: str | None,
    field: str,
    items: list[dict[str, object]],
) -> list[Mapping[str, object]]:
    request = _request(
        key=key,
        key_id=key_id,
        verify=items if field == "verify" else [],
        sign=items if field == "sign" else [],
    )
    payload = _resident_payload(guard_home, request)
    outcomes = payload.get(field)
    other = payload.get("sign" if field == "verify" else "verify")
    if not isinstance(outcomes, list) or len(outcomes) != len(items) or other != []:
        raise NativePolicyIntegrityUnavailableError()
    if "generation" in payload or "reconcile" in payload:
        raise NativePolicyIntegrityUnavailableError()
    if not all(isinstance(outcome, dict) for outcome in outcomes):
        raise NativePolicyIntegrityUnavailableError()
    return outcomes


def _request(
    *,
    key: bytes | None,
    key_id: str | None,
    verify: list[dict[str, object]],
    sign: list[dict[str, object]],
) -> dict[str, object]:
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"policy-integrity-rows-{uuid4().hex}",
        "verify": verify,
        "sign": sign,
    }
    if key is not None:
        request[_KEY_FIELD] = base64.urlsafe_b64encode(key).rstrip(b"=").decode("ascii")
    if key_id is not None:
        request["integrity_key_id"] = key_id
    return request


def _resident_payload(
    guard_home: Path,
    request: dict[str, object],
    *,
    required_feature: str = POLICY_INTEGRITY_ROWS_FEATURE,
) -> dict[str, object]:
    status = native_runtime_status()
    try:
        response = _resident_request(
            operation="policy_integrity_rows",
            request=request,
            guard_home=guard_home,
            timeout_seconds=_TIMEOUT_SECONDS,
            required_feature=required_feature,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_REQUEST_BYTES,
            record_success=False,
            status=status,
        )
    except (TypeError, ValueError):
        response = None
    payload = _bound_payload(response, request, guard_home, status)
    if payload is None:
        raise NativePolicyIntegrityUnavailableError()
    return payload


def _bound_payload(
    response: dict[str, object] | None,
    request: dict[str, object],
    guard_home: Path,
    status: NativeRuntimeStatus,
) -> dict[str, object] | None:
    """The ``ok`` payload of a reply bound to ``request``, else ``None``."""

    if response is None:
        return None
    try:
        digest = "sha256:" + _canonical_request_sha256(
            {name: value for name, value in request.items() if name != _KEY_FIELD}
        )
    except (TypeError, ValueError):
        return None
    bound = response.get("request_id") == request["request_id"] and response.get("request_sha256") == digest
    payload = response.get("payload")
    usable = response.get("status") == "ok" and response.get("code") == "ok" and isinstance(payload, dict)
    identity = status.identity
    if identity is not None:
        if bound and usable:
            native_record_resident_success(identity.sha256, guard_home)
        else:
            native_record_resident_failure(identity.sha256, guard_home, reason="native_policy_integrity_rows_binding")
    return payload if bound and usable and isinstance(payload, dict) else None


def _wire_row(row: Mapping[str, object]) -> dict[str, object]:
    """The integrity-relevant columns, as JSON the resident reads identically.

    The resident treats any value that is not a string, integer or boolean as
    absent for every column it reads, so other SQLite values (blobs, reals)
    travel as ``null``.
    """

    wire: dict[str, object] = {}
    for column in _ROW_COLUMNS:
        if column not in row:
            continue
        value = row[column]
        wire[column] = value if isinstance(value, str | int) else None
    return wire


def _verify_wire(item: PolicyRowVerifyItem) -> dict[str, object]:
    wire: dict[str, object] = {"row": _wire_row(item.row), "degraded_mode": bool(item.degraded_mode)}
    if item.trusted_generation is not None:
        wire["trusted_generation"] = int(item.trusted_generation)
    return wire


def _sign_wire(item: PolicyRowSignItem) -> dict[str, object]:
    return {"row": _wire_row(item.row), "generation": int(item.generation), "signed_at": str(item.signed_at)}


def _optional_text(outcome: Mapping[str, object], name: str) -> str | None:
    value = outcome.get(name)
    if value is not None and not isinstance(value, str):
        raise NativePolicyIntegrityUnavailableError()
    return value


def _verification_status(value: object) -> PolicyIntegrityStatus:
    if value == "valid":
        return "valid"
    if value == "missing_integrity":
        return "missing_integrity"
    if value == "tampered":
        return "tampered"
    if value == "unknown_key":
        return "unknown_key"
    if value == "rollback_detected":
        return "rollback_detected"
    if value == "degraded_mode":
        return "degraded_mode"
    raise NativePolicyIntegrityUnavailableError()


def _verification(outcome: Mapping[str, object]) -> PolicyIntegrityVerificationResult:
    return PolicyIntegrityVerificationResult(
        status=_verification_status(outcome.get("status")),
        payload_hash=_optional_text(outcome, "payload_hash"),
        key_id=_optional_text(outcome, "key_id"),
        message=_optional_text(outcome, "message"),
    )


def _degraded(row: Mapping[str, object]) -> PolicyIntegrityVerificationResult:
    def stored(name: str) -> str | None:
        value = row.get(name)
        return value if isinstance(value, str) and value else None

    return PolicyIntegrityVerificationResult(
        status="degraded_mode",
        payload_hash=stored("payload_hash"),
        key_id=stored("integrity_key_id"),
        message="policy_integrity_backend_unavailable",
    )


def _signature(outcome: Mapping[str, object], item: PolicyRowSignItem) -> dict[str, object]:
    if set(outcome) != _SIGNATURE_FIELDS:
        raise NativePolicyIntegrityUnavailableError()
    texts = ("payload_hash", "payload_mac", "integrity_key_id", "signed_at")
    if not all(isinstance(outcome[name], str) and outcome[name] for name in texts):
        raise NativePolicyIntegrityUnavailableError()
    version, generation = outcome["integrity_version"], outcome["integrity_generation"]
    if not isinstance(version, int) or isinstance(version, bool) or generation != item.generation:
        raise NativePolicyIntegrityUnavailableError()
    if outcome["signed_at"] != item.signed_at:
        raise NativePolicyIntegrityUnavailableError()
    return dict(outcome)


def _dumps(value: object) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as error:
        raise NativePolicyIntegrityUnavailableError() from error
