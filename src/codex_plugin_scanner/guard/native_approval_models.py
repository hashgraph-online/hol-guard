"""Opaque session models and request-envelope bindings for native approval.

The models keep the resident challenge and consumed receipt tied to one
immutable request context.  They do not verify signatures or make approval
decisions; Rust remains the authority for both operations.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import cast

from . import native_approval_protocol as _protocol

_SESSION_FACTORY_TOKEN = object()
_RECEIPT_FACTORY_TOKEN = object()


@dataclass(frozen=True, slots=True)
class NativeApprovalSession:
    """Opaque presentation state for one resident-issued challenge."""

    _challenge: Mapping[str, object] = field(repr=False)
    _envelope: bytes = field(repr=False)
    _provenance: object = field(repr=False, compare=False)
    _factory_token: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._factory_token is not _SESSION_FACTORY_TOKEN:
            raise ValueError("native_approval_session_invalid")

    @property
    def challenge(self) -> dict[str, object]:
        """Return only detached, privacy-safe challenge fields."""

        return dict(self._challenge)

    @property
    def request_id(self) -> str:
        return cast(str, self._challenge["request_id"])

    @property
    def request_digest(self) -> str:
        return cast(str, self._challenge["request_digest"])

    @property
    def action_digest(self) -> str:
        return cast(str, self._challenge["action_digest"])

    @property
    def policy_generation(self) -> int:
        return cast(int, self._challenge["policy_generation"])

    @property
    def policy_digest(self) -> str:
        return cast(str, self._challenge["policy_digest"])

    @property
    def harness(self) -> str:
        return cast(str, self._challenge["harness"])


@dataclass(frozen=True, slots=True)
class NativeConsumedReceipt:
    """A consumed native receipt carrying bridge-only provenance."""

    _receipt: Mapping[str, object] = field(repr=False)
    _provenance: object = field(repr=False, compare=False)
    _session: NativeApprovalSession = field(repr=False, compare=False)
    _factory_token: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._factory_token is not _RECEIPT_FACTORY_TOKEN:
            raise ValueError("native_approval_receipt_invalid")

    @property
    def receipt(self) -> dict[str, object]:
        """Return a detached copy; provenance remains private to the gate."""

        return dict(self._receipt)


def _safe_path(value: Path | str) -> str | None:
    try:
        path = str(value)
    except (TypeError, ValueError):
        return None
    return path if _protocol._bounded_text(path, maximum=_protocol._MAX_PATH_BYTES) else None


def _safe_harness(value: str) -> str | None:
    return value if _protocol._bounded_text(value, maximum=_protocol._MAX_HARNESS_BYTES) else None


def _safe_request_id_from_payload(payload: Mapping[str, object]) -> str | None:
    value = payload.get("request_id")
    if value is None:
        return None
    return cast(str, value) if _protocol._request_id(value) else None


def _build_envelope(
    *,
    payload: Mapping[str, object],
    harness: str,
    guard_home: Path,
    home_dir: Path,
    cwd: Path | None,
    policy_snapshot: Mapping[str, object],
    deadline_budget_ms: int,
) -> tuple[dict[str, object], bytes] | None:
    """Build a bounded hook envelope without exposing raw payload in a challenge."""

    if type(payload) is not dict or type(policy_snapshot) is not dict:
        return None
    safe_harness = _safe_harness(harness)
    safe_guard_home = _safe_path(guard_home)
    safe_home_dir = _safe_path(home_dir)
    safe_cwd = _safe_path(cwd) if cwd is not None else None
    generation = policy_snapshot.get("generation")
    if (
        safe_harness is None
        or safe_guard_home is None
        or safe_home_dir is None
        or (cwd is not None and safe_cwd is None)
        or not _protocol._positive_integer(generation)
        or deadline_budget_ms <= 0
        or deadline_budget_ms > _protocol._MAX_DEADLINE_BUDGET_MS
    ):
        return None
    request_id = _safe_request_id_from_payload(payload)
    if payload.get("request_id") is not None and request_id is None:
        return None
    policy_digest = policy_snapshot.get("policy_digest")
    runtime_identity = policy_snapshot.get("runtime_identity")
    if not _protocol._lower_hex(policy_digest, 64) or not _protocol._lower_hex(runtime_identity, 64):
        return None
    envelope: dict[str, object] = {
        "schema": _protocol._ENVELOPE_SCHEMA,
        "request_id": request_id,
        "harness": safe_harness,
        "event": "PreToolUse",
        "raw_payload": dict(payload),
        "deadline_budget_ms": deadline_budget_ms,
        "policy_generation": generation,
        "policy_snapshot": {
            "generation": generation,
            "policy_digest": policy_digest,
            "runtime_identity": runtime_identity,
        },
        "source": {
            "cwd": safe_cwd,
            "home_dir": safe_home_dir,
            "guard_home": safe_guard_home,
            "source_ref_external_allowed": False,
        },
    }
    encoded = _protocol._encode_json_object(envelope, maximum=_protocol._NATIVE_REQUEST_MAX_BYTES)
    return (envelope, encoded) if encoded is not None else None


_RECEIPT_BINDING_FIELDS = (
    "request_id",
    "request_digest",
    "action_digest",
    "policy_generation",
    "policy_digest",
    "rule_digest",
    "runtime_identity",
    "runtime_protocol_version",
    "runtime_package",
    "runtime_version",
    "runtime_binary_identity",
    "harness",
    "workspace_binding",
    "device_binding",
    "installation_binding",
    "publisher_binding",
    "artifact_binding",
    "scope_contract_version",
    "scope_contract_digest",
    "scope_binding",
    "resident_epoch",
    "nonce",
    "issued_at_ms",
    "expires_at_ms",
    "requested_action",
)


def _receipt_matches_session(receipt: Mapping[str, object], session: NativeApprovalSession) -> bool:
    return all(receipt.get(key) == session._challenge.get(key) for key in _RECEIPT_BINDING_FIELDS)


def _artifact_matches_session(artifact: Mapping[str, object], session: NativeApprovalSession) -> bool:
    """Bind signer output to the exact challenge shown to the user."""

    keys = (
        "request_id",
        "request_digest",
        "action_digest",
        "action_type",
        "operation",
        "intrinsic_action",
        "minimum_action",
        "floor_class",
        "approval_eligible",
        "policy_generation",
        "policy_digest",
        "rule_digest",
        "runtime_identity",
        "runtime_protocol_version",
        "runtime_package",
        "runtime_version",
        "runtime_binary_identity",
        "harness",
        "workspace_binding",
        "device_binding",
        "installation_binding",
        "publisher_binding",
        "artifact_binding",
        "scope_contract_version",
        "scope_contract_digest",
        "scope_binding",
        "resident_epoch",
        "nonce",
        "issued_at_ms",
        "expires_at_ms",
        "requested_action",
    )
    return all(artifact.get(key) == session._challenge.get(key) for key in keys)


def _new_session(challenge: Mapping[str, object], envelope: bytes) -> NativeApprovalSession:
    return NativeApprovalSession(
        _challenge=MappingProxyType(dict(challenge)),
        _envelope=bytes(envelope),
        _provenance=object(),
        _factory_token=_SESSION_FACTORY_TOKEN,
    )


def _new_consumed_receipt(receipt: Mapping[str, object], session: NativeApprovalSession) -> NativeConsumedReceipt:
    return NativeConsumedReceipt(
        _receipt=MappingProxyType(dict(receipt)),
        _provenance=session._provenance,
        _session=session,
        _factory_token=_RECEIPT_FACTORY_TOKEN,
    )


__all__ = [
    "NativeApprovalSession",
    "NativeConsumedReceipt",
]
