"""Authenticated mutable state and append-only revocation contracts."""

# pyright: reportAny=false, reportUnnecessaryIsInstance=false, reportUnusedCallResult=false

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import asdict, dataclass
from typing import Final, cast

from .workflow_capabilities import WorkflowCapabilityError, canonical_framed_payload, parse_utc_timestamp

AUTHORITY_STATE_SCHEMA: Final = "hol-guard.workflow-capability-authority-state.v1"
REVOCATION_SCHEMA: Final = "hol-guard.workflow-capability-revocation.v1"
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class WorkflowCapabilityAuthorityState:
    schema_version: str
    capability_id: str
    claim_sha256: str
    use_high_water: int
    observed_at: str
    revision: int
    revocation_id: str | None
    revoked_at: str | None

    def __post_init__(self) -> None:
        if self.schema_version != AUTHORITY_STATE_SCHEMA:
            raise WorkflowCapabilityError("unsupported_authority_state_schema")
        _identifier("capability_id", self.capability_id)
        _digest("claim_sha256", self.claim_sha256)
        parse_utc_timestamp(self.observed_at)
        if type(self.use_high_water) is not int or self.use_high_water < 0:
            raise WorkflowCapabilityError("invalid_authority_use_high_water")
        if type(self.revision) is not int or self.revision < 0:
            raise WorkflowCapabilityError("invalid_authority_revision")
        if (self.revocation_id is None) != (self.revoked_at is None):
            raise WorkflowCapabilityError("invalid_authority_revocation_binding")
        if self.revocation_id is not None:
            _identifier("revocation_id", self.revocation_id)
            parse_utc_timestamp(cast(str, self.revoked_at))

    @classmethod
    def from_dict(cls, payload: object) -> WorkflowCapabilityAuthorityState:
        values = _strict(payload, set(cls.__dataclass_fields__))
        return cls(
            schema_version=_string("schema_version", values["schema_version"]),
            capability_id=_string("capability_id", values["capability_id"]),
            claim_sha256=_string("claim_sha256", values["claim_sha256"]),
            use_high_water=_integer("use_high_water", values["use_high_water"]),
            observed_at=_string("observed_at", values["observed_at"]),
            revision=_integer("revision", values["revision"]),
            revocation_id=_optional_string("revocation_id", values["revocation_id"]),
            revoked_at=_optional_string("revoked_at", values["revoked_at"]),
        )


@dataclass(frozen=True, slots=True)
class WorkflowCapabilityRevocation:
    schema_version: str
    revocation_id: str
    capability_id: str
    claim_sha256: str
    reason_code: str
    revoked_at: str

    def __post_init__(self) -> None:
        if self.schema_version != REVOCATION_SCHEMA:
            raise WorkflowCapabilityError("unsupported_revocation_schema")
        _identifier("revocation_id", self.revocation_id)
        _identifier("capability_id", self.capability_id)
        _digest("claim_sha256", self.claim_sha256)
        if type(self.reason_code) is not str or re.fullmatch(r"[a-z][a-z0-9_.-]{0,63}", self.reason_code) is None:
            raise WorkflowCapabilityError("invalid_reason_code")
        parse_utc_timestamp(self.revoked_at)

    @classmethod
    def from_dict(cls, payload: object) -> WorkflowCapabilityRevocation:
        values = _strict(payload, set(cls.__dataclass_fields__))
        return cls(**{name: _string(name, value) for name, value in values.items()})


@dataclass(frozen=True, slots=True)
class SignedAuthorityState:
    state: WorkflowCapabilityAuthorityState
    key_id: str
    signature: str


@dataclass(frozen=True, slots=True)
class SignedRevocation:
    revocation: WorkflowCapabilityRevocation
    key_id: str
    signature: str


def sign_authority_state(state: WorkflowCapabilityAuthorityState, *, key: bytes, key_id: str) -> SignedAuthorityState:
    signature = _mac("authority-state", asdict(state), key=key, key_id=key_id)
    return SignedAuthorityState(state=state, key_id=key_id, signature=signature)


def verify_authority_state(signed: SignedAuthorityState, *, key: bytes, key_id: str) -> None:
    if type(signed) is not SignedAuthorityState or type(signed.state) is not WorkflowCapabilityAuthorityState:
        raise WorkflowCapabilityError("invalid_signed_authority_state")
    expected = sign_authority_state(signed.state, key=key, key_id=key_id)
    _verify_envelope(signed.key_id, signed.signature, expected.signature, key_id, "authority_state")


def sign_revocation(revocation: WorkflowCapabilityRevocation, *, key: bytes, key_id: str) -> SignedRevocation:
    signature = _mac("revocation", asdict(revocation), key=key, key_id=key_id)
    return SignedRevocation(revocation=revocation, key_id=key_id, signature=signature)


def verify_revocation(signed: SignedRevocation, *, key: bytes, key_id: str) -> None:
    if type(signed) is not SignedRevocation or type(signed.revocation) is not WorkflowCapabilityRevocation:
        raise WorkflowCapabilityError("invalid_signed_revocation")
    expected = sign_revocation(signed.revocation, key=key, key_id=key_id)
    _verify_envelope(signed.key_id, signed.signature, expected.signature, key_id, "revocation")


def encode_signed_authority_state(signed: SignedAuthorityState) -> str:
    return _canonical({"key_id": signed.key_id, "signature": signed.signature, "state": asdict(signed.state)})


def decode_signed_authority_state(encoded: str) -> SignedAuthorityState:
    payload = _decode(encoded, {"key_id", "signature", "state"}, "authority_state")
    signed = SignedAuthorityState(
        state=WorkflowCapabilityAuthorityState.from_dict(payload["state"]),
        key_id=_string("key_id", payload["key_id"]),
        signature=_string("signature", payload["signature"]),
    )
    if encode_signed_authority_state(signed) != encoded:
        raise WorkflowCapabilityError("authority_state_not_canonical")
    return signed


def encode_signed_revocation(signed: SignedRevocation) -> str:
    return _canonical({"key_id": signed.key_id, "revocation": asdict(signed.revocation), "signature": signed.signature})


def decode_signed_revocation(encoded: str) -> SignedRevocation:
    payload = _decode(encoded, {"key_id", "revocation", "signature"}, "revocation")
    signed = SignedRevocation(
        revocation=WorkflowCapabilityRevocation.from_dict(payload["revocation"]),
        key_id=_string("key_id", payload["key_id"]),
        signature=_string("signature", payload["signature"]),
    )
    if encode_signed_revocation(signed) != encoded:
        raise WorkflowCapabilityError("revocation_not_canonical")
    return signed


def _mac(purpose: str, payload: object, *, key: bytes, key_id: str) -> str:
    if type(key) is not bytes or len(key) < 32:
        raise WorkflowCapabilityError("invalid_capability_key")
    _identifier("key_id", key_id)
    authenticated = {"key_id": key_id, "payload": payload}
    return hmac.new(key, canonical_framed_payload(purpose, authenticated), hashlib.sha256).hexdigest()


def _verify_envelope(actual_key: str, actual: str, expected: str, key_id: str, purpose: str) -> None:
    if actual_key != key_id:
        raise WorkflowCapabilityError(f"{purpose}_key_mismatch")
    _digest("signature", actual)
    if not hmac.compare_digest(actual, expected):
        raise WorkflowCapabilityError(f"{purpose}_signature_invalid")


def _decode(encoded: str, keys: set[str], purpose: str) -> dict[str, object]:
    try:
        return _strict(json.loads(encoded), keys)
    except json.JSONDecodeError as error:
        raise WorkflowCapabilityError(f"{purpose}_payload_invalid") from error


def _canonical(payload: object) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _strict(payload: object, keys: set[str]) -> dict[str, object]:
    if type(payload) is not dict:
        raise WorkflowCapabilityError("invalid_contract_keys")
    typed = cast(dict[str, object], payload)
    if set(typed) != keys or not all(type(key) is str for key in typed):
        raise WorkflowCapabilityError("invalid_contract_keys")
    return typed


def _identifier(name: str, value: str) -> None:
    if type(value) is not str or _ID.fullmatch(value) is None or "*" in value:
        raise WorkflowCapabilityError(f"invalid_{name}")


def _digest(name: str, value: str) -> None:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise WorkflowCapabilityError(f"invalid_{name}")


def _string(name: str, value: object) -> str:
    if type(value) is not str:
        raise WorkflowCapabilityError(f"invalid_{name}")
    return value


def _optional_string(name: str, value: object) -> str | None:
    return None if value is None else _string(name, value)


def _integer(name: str, value: object) -> int:
    if type(value) is not int:
        raise WorkflowCapabilityError(f"invalid_{name}")
    return value
