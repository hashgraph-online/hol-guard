"""Immutable whole-source handoff to the offline Rust document compiler.

Compilation is unverified content. Approval, installation and mutation authority
belong to the import owner; this adapter never reads keys or installs a policy.
"""

from __future__ import annotations

import hashlib
import math
import time
from dataclasses import dataclass
from typing import cast

from .native_policy_snapshot_codec import _canonical_json_bytes_v3, _strict_json_loads_v3
from .native_policy_snapshot_constants import NativePolicySnapshotError
from .policy_document import GuardPolicyDocument, canonical_policy_document_bytes

MAX_DOCUMENT_BYTES = 1_048_576
COMPILE_CAPABILITY = "native-business-policy-document-compile-v1"
_RESPONSE_FIELDS = frozenset(
    {"schema", "source_digest", "source_id", "source_revision", "business_policy", "authority", "installed"}
)


@dataclass(frozen=True, slots=True, repr=False)
class UnverifiedBusinessDocument:
    """Owned bytes prevent a caller mutating content after its digest is bound."""

    source_bytes: bytes
    binding_bytes: bytes
    source_digest: str
    source_id: str
    source_revision: int

    def binding(self) -> dict[str, object]:
        # Each consumer gets a fresh wire copy. Rust owns business semantics.
        return cast(dict[str, object], _strict_json_loads_v3(self.binding_bytes))


def compile_business_policy_document(
    document: GuardPolicyDocument,
    *,
    deadline_monotonic: float | None = None,
) -> UnverifiedBusinessDocument:
    from .native_runtime import _run_native_process, native_runtime_status

    if deadline_monotonic is not None and (
        isinstance(deadline_monotonic, bool) or not math.isfinite(deadline_monotonic)
    ):
        raise NativePolicySnapshotError("native_policy_snapshot_deadline_invalid")
    deadline = (
        min(time.monotonic() + 5.0, deadline_monotonic) if deadline_monotonic is not None else time.monotonic() + 5.0
    )
    source = canonical_policy_document_bytes(document)
    if len(source) > MAX_DOCUMENT_BYTES:
        raise NativePolicySnapshotError("native_business_document_bounds")
    if deadline <= time.monotonic():
        raise NativePolicySnapshotError("native_policy_snapshot_deadline_exceeded")
    status = native_runtime_status(deadline_monotonic=deadline)
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or COMPILE_CAPABILITY not in status.capabilities.features
    ):
        raise NativePolicySnapshotError("native_business_document_consumer_unavailable")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise NativePolicySnapshotError("native_policy_snapshot_deadline_exceeded")
    output = _run_native_process(
        status.identity.path,
        ("compile-business-policy", "--stdin"),
        input_text=source.decode("utf-8"),
        timeout_seconds=remaining,
    )
    if deadline <= time.monotonic():
        raise NativePolicySnapshotError("native_policy_snapshot_deadline_exceeded")
    if output is None or len(output.encode("utf-8")) > MAX_DOCUMENT_BYTES:
        raise NativePolicySnapshotError("native_business_document_compile_refused")
    response = _strict_json_loads_v3(output.encode("utf-8"))
    digest = hashlib.sha256(source).hexdigest()
    if (
        not isinstance(response, dict)
        or set(response) != _RESPONSE_FIELDS
        or response["schema"] != "guard.business-policy-document-compile.v1"
        or response["authority"] != "unverified_source"
        or response["installed"] is not False
        or response["source_digest"] != digest
        or response["source_id"] != document.metadata.id
        or type(response["source_revision"]) is not int
        or response["source_revision"] != document.metadata.revision
        or not isinstance(response["business_policy"], dict)
        or response["business_policy"].get("sourceDocumentDigest") != digest
    ):
        raise NativePolicySnapshotError("native_business_document_compile_response_invalid")
    return UnverifiedBusinessDocument(
        source,
        _canonical_json_bytes_v3(response["business_policy"]),
        digest,
        document.metadata.id,
        document.metadata.revision,
    )
