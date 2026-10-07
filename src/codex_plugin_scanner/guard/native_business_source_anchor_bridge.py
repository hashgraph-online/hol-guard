"""Native marker transport; key origin is separate from durable retention.

The installation owner must compare the independent retained marker and apply
its approval/transaction protocol. A signed committed phase is not installation.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from . import native_business_source_bridge as source_api
from .native_policy_snapshot_codec import _canonical_json_bytes_v3, _strict_json_loads_v3, _valid_digest_v3

if TYPE_CHECKING:
    from .native_runtime_values import NativeRuntimeStatus

MAX_ANCHOR_BYTES = 4096
_FIELDS = frozenset(
    {
        "schema",
        "version",
        "authentication",
        "approval",
        "currentness",
        "retention",
        "installed",
        "anchor_digest",
        "phase",
        "retained_identity",
    }
)


@dataclass(frozen=True, slots=True, repr=False)
class KeyAuthenticatedBusinessSourceAnchor:
    anchor_bytes: bytes
    anchor_digest: str
    phase: Literal["closed", "committed"]
    retained_identity_bytes: bytes


def _verify(
    status: NativeRuntimeStatus,
    anchor: bytes,
    key: bytes,
    deadline: float,
) -> KeyAuthenticatedBusinessSourceAnchor:
    if type(anchor) is not bytes or len(anchor) > MAX_ANCHOR_BYTES:
        raise source_api._invalid()
    output = source_api._operation(
        status,
        "business-source-anchor-verify",
        {
            "schema": "guard.business-source-anchor-verify.v1",
            "version": 1,
            "anchor_json": source_api._utf8(anchor),
        },
        key,
        deadline,
    )
    response = _strict_json_loads_v3(output)
    digest = hashlib.sha256(anchor).hexdigest()
    if (
        not isinstance(response, dict)
        or set(response) != _FIELDS
        or response["schema"] != "guard.business-source-anchor-verification.v1"
        or type(response["version"]) is not int
        or response["version"] != 1
        or response["authentication"] != "provided_key_verified"
        or response["approval"] != "not_checked"
        or response["currentness"] != "not_checked"
        or response["retention"] != "not_checked"
        or response["installed"] is not False
        or response["anchor_digest"] != digest
        or response["phase"] not in {"closed", "committed"}
        or not isinstance(response["retained_identity"], dict)
    ):
        raise source_api._invalid()
    identity = response["retained_identity"]
    if (
        set(identity) != source_api._IDENTITY_FIELDS
        or type(identity["mutation_revision"]) is not int
        or not 1 <= identity["mutation_revision"] <= (1 << 64) - 1
        or type(identity["source_revision"]) is not int
        or not 0 <= identity["source_revision"] <= (1 << 64) - 1
        or not isinstance(identity["source_id"], str)
        or not identity["source_id"]
        or len(identity["source_id"].encode("utf-8")) > MAX_ANCHOR_BYTES
        or not all(
            _valid_digest_v3(identity[field]) for field in ("source_digest", "record_digest", "business_policy_digest")
        )
    ):
        raise source_api._invalid()
    return KeyAuthenticatedBusinessSourceAnchor(
        anchor,
        digest,
        response["phase"],
        _canonical_json_bytes_v3(identity),
    )


def verify_business_source_anchor(
    anchor: bytes,
    verifier_key: bytes,
    *,
    deadline_monotonic: float | None = None,
) -> KeyAuthenticatedBusinessSourceAnchor:
    deadline = source_api._deadline(deadline_monotonic)
    return _verify(source_api._consumer(deadline, anchor=True), anchor, verifier_key, deadline)


def build_business_source_anchor(
    source: source_api.KeyAuthenticatedBusinessSource,
    verifier_key: bytes,
    phase: Literal["closed", "committed"],
    *,
    deadline_monotonic: float | None = None,
) -> KeyAuthenticatedBusinessSourceAnchor:
    if phase not in {"closed", "committed"}:
        raise source_api._invalid()
    deadline = source_api._deadline(deadline_monotonic)
    status = source_api._consumer(deadline, anchor=True)
    result = source_api._operation(
        status,
        "business-source-anchor-build",
        {
            "schema": "guard.business-source-anchor-build.v1",
            "version": 1,
            "record_json": source_api._utf8(source.record_bytes),
            "phase": phase,
        },
        verifier_key,
        deadline,
    )
    verified = _verify(status, result, verifier_key, deadline)
    if verified.phase != phase or verified.retained_identity_bytes != source.retained_identity_bytes:
        raise source_api._invalid()
    return verified
