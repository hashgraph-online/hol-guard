"""Private native source-codec transport, without activation or Python semantics.

Key authentication is relative to the supplied key. The installation owner must
validate exact approval and an independent retained anchor before publishing.
Python JSON/subprocess key copies cannot guarantee zeroization or strong custody.
"""

from __future__ import annotations

import hashlib
import math
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from .native_business_document_compile import COMPILE_CAPABILITY, MAX_DOCUMENT_BYTES, UnverifiedBusinessDocument
from .native_policy_snapshot_codec import _canonical_json_bytes_v3, _strict_json_loads_v3, _valid_digest_v3
from .native_policy_snapshot_constants import BUSINESS_NATIVE_TIMEOUT_SECONDS, NativePolicySnapshotError

if TYPE_CHECKING:
    from .native_runtime_values import NativeRuntimeStatus

MAX_RECORD_BYTES = MAX_DOCUMENT_BYTES + 8192
CODEC_CAPABILITY = "native-business-source-codec-v1"
MAX_REQUEST_BYTES = 2 * MAX_RECORD_BYTES + 4096
# One native codec call. A complete installation spans several native processes
# and owns a larger budget; each call inside it still keeps this cap.
OPERATION_BUDGET_SECONDS = BUSINESS_NATIVE_TIMEOUT_SECONDS
_REQUIRED = {COMPILE_CAPABILITY, CODEC_CAPABILITY, "native-business-policy-retained-floor-v1"}
_VERIFICATION_FIELDS = frozenset(
    {
        "schema",
        "version",
        "authentication",
        "approval",
        "currentness",
        "installed",
        "source_digest",
        "record_digest",
        "mutation_revision",
        "business_policy",
        "retained_identity",
    }
)
_IDENTITY_FIELDS = frozenset(
    {
        "mutation_revision",
        "record_digest",
        "source_digest",
        "source_id",
        "source_revision",
        "business_policy_digest",
    }
)


@dataclass(frozen=True, slots=True, repr=False)
class KeyAuthenticatedBusinessSource:
    """Immutable content authenticated by Rust; no approval or currentness grant."""

    record_bytes: bytes
    binding_bytes: bytes
    retained_identity_bytes: bytes
    source_digest: str
    record_digest: str
    mutation_revision: int


def _invalid() -> NativePolicySnapshotError:
    return NativePolicySnapshotError("native_business_source_codec_response_invalid")


def _deadline(value: float | None, *, budget_seconds: float = OPERATION_BUDGET_SECONDS) -> float:
    if value is not None and (isinstance(value, bool) or not math.isfinite(value)):
        raise NativePolicySnapshotError("native_policy_snapshot_deadline_invalid")
    deadline = time.monotonic() + budget_seconds
    return deadline if value is None else min(deadline, value)


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise NativePolicySnapshotError("native_policy_snapshot_deadline_exceeded")
    return remaining


def _consumer(deadline: float, *, anchor: bool = False) -> NativeRuntimeStatus:
    from .native_runtime import native_runtime_status

    _remaining(deadline)
    status = native_runtime_status(deadline_monotonic=deadline)
    required = _REQUIRED | {"native-business-source-anchor-codec-v1"} if anchor else _REQUIRED
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or not set(status.capabilities.features) >= required
    ):
        raise NativePolicySnapshotError("native_business_source_consumer_unavailable")
    return status


def _operation(
    status: NativeRuntimeStatus,
    command: str,
    payload: dict[str, object],
    key: bytes,
    deadline: float,
) -> bytes:
    from .native_runtime import _run_native_process

    if command not in {
        "business-source-build",
        "business-source-verify",
        "business-source-anchor-build",
        "business-source-anchor-verify",
    }:
        raise _invalid()
    if type(key) is not bytes or len(key) != 32:
        raise NativePolicySnapshotError("native_business_source_key_invalid")
    assert status.identity is not None
    key_list = list(key)
    payload["verifier_key"] = key_list
    try:
        encoded = _canonical_json_bytes_v3(payload)
        if len(encoded) > MAX_REQUEST_BYTES:
            raise _invalid()
        output = _run_native_process(
            status.identity.path,
            (command, "--stdin"),
            input_text=encoded.decode("utf-8"),
            timeout_seconds=_remaining(deadline),
        )
    finally:
        payload.pop("verifier_key", None)
        key_list.clear()
    _remaining(deadline)
    if output is None:
        raise NativePolicySnapshotError("native_business_source_codec_refused")
    # The CLI appends one line delimiter; the authenticated record itself must
    # retain its exact canonical bytes. Do not normalize record content.
    result = output.removesuffix("\n").encode("utf-8")
    if len(result) > MAX_RECORD_BYTES:
        raise _invalid()
    return result


def _utf8(value: bytes) -> str:
    if type(value) is not bytes:
        raise _invalid()
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        raise _invalid() from None


def _verify(
    status: NativeRuntimeStatus,
    record: bytes,
    key: bytes,
    deadline: float,
    retained_identity_bytes: bytes | None = None,
) -> KeyAuthenticatedBusinessSource:
    if type(record) is not bytes or len(record) > MAX_RECORD_BYTES:
        raise _invalid()
    payload: dict[str, object] = {
        "schema": "guard.business-source-verify.v1",
        "version": 1,
        "record_json": _utf8(record),
    }
    if retained_identity_bytes is not None:
        if type(retained_identity_bytes) is not bytes or len(retained_identity_bytes) > 4096:
            raise _invalid()
        payload["retained_floor"] = _strict_json_loads_v3(retained_identity_bytes)
    response_bytes = _operation(
        status,
        "business-source-verify",
        payload,
        key,
        deadline,
    )
    response = _strict_json_loads_v3(response_bytes)
    record_digest = hashlib.sha256(record).hexdigest()
    if (
        not isinstance(response, dict)
        or set(response) != _VERIFICATION_FIELDS
        or response["schema"] != "guard.business-source-verification.v1"
        or type(response["version"]) is not int
        or response["version"] != 1
        or response["authentication"] != "provided_key_verified"
        or response["approval"] != "not_checked"
        or response["currentness"] != "not_checked"
        or response["installed"] is not False
        or not _valid_digest_v3(response["source_digest"])
        or response["record_digest"] != record_digest
        or type(response["mutation_revision"]) is not int
        or not 1 <= response["mutation_revision"] <= (1 << 64) - 1
        or not isinstance(response["business_policy"], dict)
        or response["business_policy"].get("sourceDocumentDigest") != response["source_digest"]
        or not isinstance(response["retained_identity"], dict)
    ):
        raise _invalid()
    identity = response["retained_identity"]
    binding_bytes = _canonical_json_bytes_v3(response["business_policy"])
    if (
        set(identity) != _IDENTITY_FIELDS
        or identity["mutation_revision"] != response["mutation_revision"]
        or type(identity["mutation_revision"]) is not int
        or identity["record_digest"] != record_digest
        or identity["source_digest"] != response["source_digest"]
        or identity["business_policy_digest"] != hashlib.sha256(binding_bytes).hexdigest()
        or not isinstance(identity["source_id"], str)
        or not identity["source_id"]
        or type(identity["source_revision"]) is not int
        or not 0 <= identity["source_revision"] <= (1 << 64) - 1
    ):
        raise _invalid()
    return KeyAuthenticatedBusinessSource(
        record,
        binding_bytes,
        _canonical_json_bytes_v3(identity),
        cast(str, response["source_digest"]),
        record_digest,
        response["mutation_revision"],
    )


def verify_business_source_record(
    record: bytes,
    verifier_key: bytes,
    *,
    deadline_monotonic: float | None = None,
    retained_identity_bytes: bytes | None = None,
) -> KeyAuthenticatedBusinessSource:
    deadline = _deadline(deadline_monotonic)
    return _verify(_consumer(deadline), record, verifier_key, deadline, retained_identity_bytes)


def build_business_source_record(
    candidate: UnverifiedBusinessDocument,
    verifier_key: bytes,
    mutation_revision: int,
    *,
    deadline_monotonic: float | None = None,
) -> KeyAuthenticatedBusinessSource:
    if type(mutation_revision) is not int or not 1 <= mutation_revision <= (1 << 64) - 1:
        raise NativePolicySnapshotError("native_business_source_revision_invalid")
    if len(candidate.source_bytes) > MAX_DOCUMENT_BYTES:
        raise NativePolicySnapshotError("native_business_document_bounds")
    deadline = _deadline(deadline_monotonic)
    status = _consumer(deadline)
    record = _operation(
        status,
        "business-source-build",
        {
            "schema": "guard.business-source-build.v1",
            "version": 1,
            "import_mode": "replace",
            "mutation_revision": mutation_revision,
            "source_json": _utf8(candidate.source_bytes),
        },
        verifier_key,
        deadline,
    )
    verified = _verify(status, record, verifier_key, deadline)
    identity = _strict_json_loads_v3(verified.retained_identity_bytes)
    if not isinstance(identity, dict):
        raise _invalid()
    if (
        verified.source_digest != candidate.source_digest
        or verified.binding_bytes != candidate.binding_bytes
        or verified.mutation_revision != mutation_revision
        or identity["source_id"] != candidate.source_id
        or identity["source_revision"] != candidate.source_revision
    ):
        raise _invalid()
    return verified
