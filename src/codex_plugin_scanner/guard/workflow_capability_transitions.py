"""Signed workflow-capability authority transition contracts."""

# pyright: reportAny=false, reportUnusedCallResult=false

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict, dataclass
from typing import Final, cast

from .workflow_capabilities import WorkflowCapabilityError, canonical_framed_payload, parse_utc_timestamp

AUTHORITY_TRANSITION_SCHEMA: Final = "hol-guard.workflow-capability-authority-transition.v1"
AUTHORITY_TRANSITION_ALGORITHM: Final = "hmac-sha256"
ZERO_TRANSITION_SHA256: Final = "0" * 64
_KINDS: Final = frozenset({"issued", "claimed", "revoked"})


@dataclass(frozen=True, slots=True)
class WorkflowCapabilityAuthorityTransition:
    schema_version: str
    algorithm: str
    sequence: int
    capability_id: str
    claim_sha256: str
    revision: int
    transition_kind: str
    previous_transition_sha256: str
    signed_state_sha256: str
    event_id: int | None
    event_name: str | None
    event_payload_sha256: str | None
    occurred_at: str
    use_number: int | None
    receipt_id: str | None
    revocation_id: str | None

    def __post_init__(self) -> None:
        if self.schema_version != AUTHORITY_TRANSITION_SCHEMA:
            raise WorkflowCapabilityError("unsupported_authority_transition_schema")
        if self.algorithm != AUTHORITY_TRANSITION_ALGORITHM:
            raise WorkflowCapabilityError("unsupported_authority_transition_algorithm")
        if type(self.sequence) is not int or self.sequence < 1:
            raise WorkflowCapabilityError("invalid_authority_transition_sequence")
        if type(self.revision) is not int or self.revision < 0:
            raise WorkflowCapabilityError("invalid_authority_transition_revision")
        _identifier("capability_id", self.capability_id)
        _digest("claim_sha256", self.claim_sha256)
        _digest("previous_transition_sha256", self.previous_transition_sha256)
        _digest("signed_state_sha256", self.signed_state_sha256)
        parse_utc_timestamp(self.occurred_at)
        if self.transition_kind not in _KINDS:
            raise WorkflowCapabilityError("invalid_authority_transition_kind")
        if type(self.event_id) is not int or self.event_id < 1:
            raise WorkflowCapabilityError("invalid_authority_transition_event")
        _identifier("event_name", cast(str, self.event_name))
        _digest("event_payload_sha256", cast(str, self.event_payload_sha256))
        if self.use_number is not None and (type(self.use_number) is not int or self.use_number < 1):
            raise WorkflowCapabilityError("invalid_authority_transition_use_number")
        if self.receipt_id is not None:
            _identifier("receipt_id", self.receipt_id)
        if self.revocation_id is not None:
            _identifier("revocation_id", self.revocation_id)
        if (self.transition_kind == "claimed") != (self.receipt_id is not None):
            raise WorkflowCapabilityError("invalid_authority_transition_receipt")
        if (self.transition_kind == "claimed") != (self.use_number is not None):
            raise WorkflowCapabilityError("invalid_authority_transition_use_number")
        if (self.transition_kind == "revoked") != (self.revocation_id is not None):
            raise WorkflowCapabilityError("invalid_authority_transition_revocation")

    @classmethod
    def from_dict(cls, payload: object) -> WorkflowCapabilityAuthorityTransition:
        values = _strict(payload, set(cls.__dataclass_fields__))
        return cls(
            schema_version=_string("schema_version", values["schema_version"]),
            algorithm=_string("algorithm", values["algorithm"]),
            sequence=_integer("sequence", values["sequence"]),
            capability_id=_string("capability_id", values["capability_id"]),
            claim_sha256=_string("claim_sha256", values["claim_sha256"]),
            revision=_integer("revision", values["revision"]),
            transition_kind=_string("transition_kind", values["transition_kind"]),
            previous_transition_sha256=_string("previous_transition_sha256", values["previous_transition_sha256"]),
            signed_state_sha256=_string("signed_state_sha256", values["signed_state_sha256"]),
            event_id=_optional_integer("event_id", values["event_id"]),
            event_name=_optional_string("event_name", values["event_name"]),
            event_payload_sha256=_optional_string("event_payload_sha256", values["event_payload_sha256"]),
            occurred_at=_string("occurred_at", values["occurred_at"]),
            use_number=_optional_integer("use_number", values["use_number"]),
            receipt_id=_optional_string("receipt_id", values["receipt_id"]),
            revocation_id=_optional_string("revocation_id", values["revocation_id"]),
        )


@dataclass(frozen=True, slots=True)
class SignedAuthorityTransition:
    transition: WorkflowCapabilityAuthorityTransition
    key_id: str
    signature: str


def sign_authority_transition(
    transition: WorkflowCapabilityAuthorityTransition, *, key: bytes, key_id: str
) -> SignedAuthorityTransition:
    _key(key)
    _identifier("key_id", key_id)
    payload = {"key_id": key_id, "transition": asdict(transition)}
    signature = hmac.new(key, canonical_framed_payload("authority-transition", payload), hashlib.sha256).hexdigest()
    return SignedAuthorityTransition(transition=transition, key_id=key_id, signature=signature)


def verify_authority_transition(signed: SignedAuthorityTransition, *, key: bytes, key_id: str) -> None:
    try:
        _verify_authority_transition_fields(signed, key=key, key_id=key_id)
    except WorkflowCapabilityError:
        raise
    except Exception as error:
        raise WorkflowCapabilityError("invalid_signed_authority_transition") from error


def _verify_authority_transition_fields(signed: SignedAuthorityTransition, *, key: bytes, key_id: str) -> None:
    if (
        type(signed) is not SignedAuthorityTransition
        or type(signed.transition) is not WorkflowCapabilityAuthorityTransition
    ):
        raise WorkflowCapabilityError("invalid_signed_authority_transition")
    if signed.key_id != key_id:
        raise WorkflowCapabilityError("authority_transition_key_mismatch")
    _digest("signature", signed.signature)
    expected = sign_authority_transition(signed.transition, key=key, key_id=key_id).signature
    if not hmac.compare_digest(signed.signature, expected):
        raise WorkflowCapabilityError("authority_transition_signature_invalid")


def encode_signed_authority_transition(signed: SignedAuthorityTransition) -> str:
    return _canonical({"key_id": signed.key_id, "signature": signed.signature, "transition": asdict(signed.transition)})


def decode_signed_authority_transition(encoded: str) -> SignedAuthorityTransition:
    try:
        payload = _strict(json.loads(encoded), {"key_id", "signature", "transition"})
    except json.JSONDecodeError as error:
        raise WorkflowCapabilityError("authority_transition_payload_invalid") from error
    signed = SignedAuthorityTransition(
        transition=WorkflowCapabilityAuthorityTransition.from_dict(payload["transition"]),
        key_id=_string("key_id", payload["key_id"]),
        signature=_string("signature", payload["signature"]),
    )
    if encode_signed_authority_transition(signed) != encoded:
        raise WorkflowCapabilityError("authority_transition_not_canonical")
    return signed


def authority_transition_sha256(signed: SignedAuthorityTransition) -> str:
    return hashlib.sha256(
        canonical_framed_payload("authority-transition-digest", encode_signed_authority_transition(signed))
    ).hexdigest()


def _canonical(payload: object) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _strict(payload: object, keys: set[str]) -> dict[str, object]:
    if type(payload) is not dict:
        raise WorkflowCapabilityError("invalid_contract_keys")
    typed = cast(dict[str, object], payload)
    if set(typed) != keys:
        raise WorkflowCapabilityError("invalid_contract_keys")
    return typed


def _identifier(name: str, value: str) -> None:
    if type(value) is not str or not value or len(value) > 256 or value.strip() != value or "*" in value:
        raise WorkflowCapabilityError(f"invalid_{name}")
    if any(character.isspace() or ord(character) < 33 or ord(character) > 126 for character in value):
        raise WorkflowCapabilityError(f"invalid_{name}")


def _digest(name: str, value: str) -> None:
    if type(value) is not str or len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise WorkflowCapabilityError(f"invalid_{name}")


def _key(value: bytes) -> None:
    if type(value) is not bytes or len(value) < 32:
        raise WorkflowCapabilityError("invalid_capability_key")


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


def _optional_integer(name: str, value: object) -> int | None:
    return None if value is None else _integer(name, value)
