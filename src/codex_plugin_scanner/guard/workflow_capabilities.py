"""Workflow-capability contract shapes.

Transport and presentation only: the resident holds the capability key, signs
every claim and verifies every envelope, so nothing here touches key material.
"""

# pyright: reportAny=false, reportUnnecessaryIsInstance=false, reportUnusedCallResult=false

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Final, cast

WORKFLOW_CAPABILITY_SCHEMA: Final = "hol-guard.workflow-capability.v1"
WORKFLOW_CAPABILITY_ENVELOPE_SCHEMA: Final = "hol-guard.workflow-capability-envelope.v1"
WORKFLOW_CAPABILITY_RECEIPT_SCHEMA: Final = "hol-guard.workflow-capability-receipt.v1"
WORKFLOW_CAPABILITY_RECEIPT_ENVELOPE_SCHEMA: Final = "hol-guard.workflow-capability-receipt-envelope.v1"
WORKFLOW_CAPABILITY_ALGORITHM: Final = "hmac-sha256"
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$")


class WorkflowCapabilityError(ValueError):
    """Raised when a capability contract fails closed."""


@dataclass(frozen=True, slots=True, order=True)
class WorkflowCapabilityRuleBinding:
    rule_id: str
    rule_version: str

    def __post_init__(self) -> None:
        validate_workflow_capability_identifier("rule_id", self.rule_id)
        validate_workflow_capability_identifier("rule_version", self.rule_version)

    @classmethod
    def from_dict(cls, payload: object) -> WorkflowCapabilityRuleBinding:
        values = _strict_object(payload, set(cls.__dataclass_fields__))
        return cls(
            rule_id=_require_string("rule_id", values["rule_id"]),
            rule_version=_require_string("rule_version", values["rule_version"]),
        )


@dataclass(frozen=True, slots=True)
class WorkflowCapabilityBinding:
    """Exact immutable execution and authority context."""

    operation_id: str
    resource_type: str
    resource_sha256: str
    repository_sha256: str
    workspace_sha256: str
    executable_sha256: str
    launch_sha256: str
    policy_id: str
    policy_version: str
    effect_id: str
    effect_version: str
    decision_id: str
    decision_version: str
    rules: tuple[WorkflowCapabilityRuleBinding, ...]

    def __post_init__(self) -> None:
        if type(self.rules) is not tuple or not all(type(rule) is WorkflowCapabilityRuleBinding for rule in self.rules):
            raise WorkflowCapabilityError("invalid_rule_bindings")
        for name in (
            "operation_id",
            "resource_type",
            "policy_id",
            "policy_version",
            "effect_id",
            "effect_version",
            "decision_id",
            "decision_version",
        ):
            validate_workflow_capability_identifier(name, getattr(self, name))
        for name in (
            "resource_sha256",
            "repository_sha256",
            "workspace_sha256",
            "executable_sha256",
            "launch_sha256",
        ):
            _validate_sha256(name, getattr(self, name))
        if not self.rules or len(self.rules) > 32 or self.rules != tuple(sorted(set(self.rules))):
            raise WorkflowCapabilityError("invalid_rule_bindings")

    @classmethod
    def from_dict(cls, payload: object) -> WorkflowCapabilityBinding:
        values = _strict_object(payload, set(cls.__dataclass_fields__))
        rules = values.pop("rules")
        if type(rules) is not list:
            raise WorkflowCapabilityError("invalid_rule_bindings")
        typed_rules = cast(list[object], rules)
        return cls(
            **{key: _require_string(key, value) for key, value in values.items()},
            rules=tuple(WorkflowCapabilityRuleBinding.from_dict(rule) for rule in typed_rules),
        )


@dataclass(frozen=True, slots=True)
class WorkflowCapabilityClaim:
    """Unsigned immutable claim; signing turns it into persisted authority."""

    schema_version: str
    algorithm: str
    capability_id: str
    approval_provenance_id: str
    task_id: str
    nonce: str
    issuer_id: str
    subject_id: str
    binding: WorkflowCapabilityBinding
    issued_at: str
    not_before: str
    expires_at: str
    max_uses: int

    def __post_init__(self) -> None:
        if self.schema_version != WORKFLOW_CAPABILITY_SCHEMA:
            raise WorkflowCapabilityError("unsupported_capability_schema")
        if self.algorithm != WORKFLOW_CAPABILITY_ALGORITHM:
            raise WorkflowCapabilityError("unsupported_capability_algorithm")
        if type(self.binding) is not WorkflowCapabilityBinding:
            raise WorkflowCapabilityError("invalid_capability_binding")
        for name in ("capability_id", "approval_provenance_id", "task_id", "issuer_id", "subject_id"):
            validate_workflow_capability_identifier(name, getattr(self, name))
        if type(self.nonce) is not str or not re.fullmatch(r"[0-9a-f]{32,64}", self.nonce):
            raise WorkflowCapabilityError("invalid_nonce")
        issued = parse_utc_timestamp(self.issued_at)
        not_before = parse_utc_timestamp(self.not_before)
        expires = parse_utc_timestamp(self.expires_at)
        if not issued <= not_before < expires:
            raise WorkflowCapabilityError("invalid_capability_time_window")
        if (expires - issued).total_seconds() > 86_400:
            raise WorkflowCapabilityError("capability_ttl_exceeds_alpha_limit")
        if type(self.max_uses) is not int or not 1 <= self.max_uses <= 50:
            raise WorkflowCapabilityError("invalid_capability_max_uses")

    @classmethod
    def from_dict(cls, payload: object) -> WorkflowCapabilityClaim:
        values = _strict_object(payload, set(cls.__dataclass_fields__))
        max_uses = values["max_uses"]
        if type(max_uses) is not int:
            raise WorkflowCapabilityError("invalid_capability_max_uses")
        return cls(
            schema_version=_require_string("schema_version", values["schema_version"]),
            algorithm=_require_string("algorithm", values["algorithm"]),
            capability_id=_require_string("capability_id", values["capability_id"]),
            approval_provenance_id=_require_string("approval_provenance_id", values["approval_provenance_id"]),
            task_id=_require_string("task_id", values["task_id"]),
            nonce=_require_string("nonce", values["nonce"]),
            issuer_id=_require_string("issuer_id", values["issuer_id"]),
            subject_id=_require_string("subject_id", values["subject_id"]),
            binding=WorkflowCapabilityBinding.from_dict(values["binding"]),
            issued_at=_require_string("issued_at", values["issued_at"]),
            not_before=_require_string("not_before", values["not_before"]),
            expires_at=_require_string("expires_at", values["expires_at"]),
            max_uses=max_uses,
        )


@dataclass(frozen=True, slots=True)
class SignedWorkflowCapability:
    envelope_schema: str
    algorithm: str
    claim: WorkflowCapabilityClaim
    key_id: str
    signature: str

    def __post_init__(self) -> None:
        if type(self.claim) is not WorkflowCapabilityClaim:
            raise WorkflowCapabilityError("invalid_capability_claim")
        if self.envelope_schema != WORKFLOW_CAPABILITY_ENVELOPE_SCHEMA:
            raise WorkflowCapabilityError("unsupported_capability_envelope")
        if self.algorithm != WORKFLOW_CAPABILITY_ALGORITHM or self.algorithm != self.claim.algorithm:
            raise WorkflowCapabilityError("unsupported_capability_algorithm")
        validate_workflow_capability_identifier("key_id", self.key_id)
        _validate_sha256("signature", self.signature)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: object) -> SignedWorkflowCapability:
        values = _strict_object(payload, set(cls.__dataclass_fields__))
        return cls(
            envelope_schema=_require_string("envelope_schema", values["envelope_schema"]),
            algorithm=_require_string("algorithm", values["algorithm"]),
            claim=WorkflowCapabilityClaim.from_dict(values["claim"]),
            key_id=_require_string("key_id", values["key_id"]),
            signature=_require_string("signature", values["signature"]),
        )


@dataclass(frozen=True, slots=True)
class WorkflowCapabilityReceipt:
    schema_version: str
    receipt_id: str
    capability_id: str
    task_id: str
    invocation_id: str
    approval_provenance_id: str
    claim_sha256: str
    binding: WorkflowCapabilityBinding
    use_number: int
    event_id: int
    claimed_at: str

    def __post_init__(self) -> None:
        if type(self.binding) is not WorkflowCapabilityBinding:
            raise WorkflowCapabilityError("invalid_receipt_binding")
        if self.schema_version != WORKFLOW_CAPABILITY_RECEIPT_SCHEMA:
            raise WorkflowCapabilityError("unsupported_receipt_schema")
        for name in ("receipt_id", "capability_id", "task_id", "invocation_id", "approval_provenance_id"):
            validate_workflow_capability_identifier(name, getattr(self, name))
        _validate_sha256("claim_sha256", self.claim_sha256)
        parse_utc_timestamp(self.claimed_at)
        if type(self.use_number) is not int or self.use_number < 1:
            raise WorkflowCapabilityError("invalid_receipt_use_number")
        if type(self.event_id) is not int or self.event_id < 1:
            raise WorkflowCapabilityError("invalid_receipt_event_id")

    @classmethod
    def from_dict(cls, payload: object) -> WorkflowCapabilityReceipt:
        values = _strict_object(payload, set(cls.__dataclass_fields__))
        use_number = values["use_number"]
        event_id = values["event_id"]
        if type(use_number) is not int:
            raise WorkflowCapabilityError("invalid_receipt_use_number")
        if type(event_id) is not int:
            raise WorkflowCapabilityError("invalid_receipt_event_id")
        return cls(
            schema_version=_require_string("schema_version", values["schema_version"]),
            receipt_id=_require_string("receipt_id", values["receipt_id"]),
            capability_id=_require_string("capability_id", values["capability_id"]),
            task_id=_require_string("task_id", values["task_id"]),
            invocation_id=_require_string("invocation_id", values["invocation_id"]),
            approval_provenance_id=_require_string("approval_provenance_id", values["approval_provenance_id"]),
            claim_sha256=_require_string("claim_sha256", values["claim_sha256"]),
            binding=WorkflowCapabilityBinding.from_dict(values["binding"]),
            use_number=use_number,
            event_id=event_id,
            claimed_at=_require_string("claimed_at", values["claimed_at"]),
        )


@dataclass(frozen=True, slots=True)
class SignedWorkflowCapabilityReceipt:
    envelope_schema: str
    algorithm: str
    receipt: WorkflowCapabilityReceipt
    key_id: str
    signature: str

    def __post_init__(self) -> None:
        if type(self.receipt) is not WorkflowCapabilityReceipt:
            raise WorkflowCapabilityError("invalid_capability_receipt")
        if self.envelope_schema != WORKFLOW_CAPABILITY_RECEIPT_ENVELOPE_SCHEMA:
            raise WorkflowCapabilityError("unsupported_receipt_envelope")
        if self.algorithm != WORKFLOW_CAPABILITY_ALGORITHM:
            raise WorkflowCapabilityError("unsupported_receipt_algorithm")
        validate_workflow_capability_identifier("key_id", self.key_id)
        _validate_sha256("signature", self.signature)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: object) -> SignedWorkflowCapabilityReceipt:
        values = _strict_object(payload, set(cls.__dataclass_fields__))
        return cls(
            envelope_schema=_require_string("envelope_schema", values["envelope_schema"]),
            algorithm=_require_string("algorithm", values["algorithm"]),
            receipt=WorkflowCapabilityReceipt.from_dict(values["receipt"]),
            key_id=_require_string("key_id", values["key_id"]),
            signature=_require_string("signature", values["signature"]),
        )


def format_utc_timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise WorkflowCapabilityError("timestamp_timezone_required")
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_utc_timestamp(value: str) -> datetime:
    if type(value) is not str or not _TIMESTAMP_PATTERN.fullmatch(value):
        raise WorkflowCapabilityError("invalid_canonical_timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as error:
        raise WorkflowCapabilityError("invalid_canonical_timestamp") from error
    return parsed.replace(tzinfo=timezone.utc)


def _strict_object(payload: object, expected_keys: set[str]) -> dict[str, object]:
    if type(payload) is not dict:
        raise WorkflowCapabilityError("invalid_contract_keys")
    raw = cast(dict[object, object], payload)
    typed: dict[str, object] = {}
    for key, value in raw.items():
        if type(key) is not str:
            raise WorkflowCapabilityError("invalid_contract_keys")
        typed[key] = value
    if set(typed) != expected_keys:
        raise WorkflowCapabilityError("invalid_contract_keys")
    return typed


def _require_string(name: str, value: object) -> str:
    if type(value) is not str:
        raise WorkflowCapabilityError(f"invalid_{name}")
    return value


def validate_workflow_capability_identifier(name: str, value: str) -> None:
    if type(value) is not str or not _IDENTIFIER_PATTERN.fullmatch(value) or "*" in value:
        raise WorkflowCapabilityError(f"invalid_{name}")


def _validate_sha256(name: str, value: str) -> None:
    if type(value) is not str or not _SHA256_PATTERN.fullmatch(value):
        raise WorkflowCapabilityError(f"invalid_{name}")
