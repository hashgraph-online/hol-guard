"""Fresh, mutation-bound approval proofs for extension-control authority changes."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

from ..approval_gate import (
    ApprovalGateGrant,
    ApprovalGateInput,
    consume_extension_control_grant,
    require_extension_control,
)
from .extension_control_authority import layers_to_json
from .extension_control_contract import ExtensionControlLayer

EXTENSION_CONTROL_PREVIEW_SCHEMA = "guard.extension-control-preview.v1"
EXTENSION_CONTROL_PROOF_ACTION = "commit-layers"
EXTENSION_CONTROL_ENROLLMENT_SCHEMA = "guard.extension-control-enrollment.v1"
EXTENSION_CONTROL_ENROLLMENT_ACTION = "enroll-authority"
_MAX_IDENTITY_LENGTH = 256


class ExtensionControlProofError(PermissionError):
    """Raised when an extension-control proof is malformed or mismatched."""


@dataclass(frozen=True, slots=True)
class ExtensionControlEnrollment:
    catalog_digest: str
    actor_id: str
    nonce: str

    def __post_init__(self) -> None:
        if len(self.catalog_digest) != 64 or any(
            character not in "0123456789abcdef" for character in self.catalog_digest
        ):
            raise ExtensionControlProofError("invalid catalog digest")
        for value in (self.actor_id, self.nonce):
            if not value.strip() or len(value) > _MAX_IDENTITY_LENGTH:
                raise ExtensionControlProofError("invalid enrollment identity")

    @property
    def canonical_digest(self) -> str:
        payload = {
            "action": EXTENSION_CONTROL_ENROLLMENT_ACTION,
            "actor_id": self.actor_id,
            "catalog_digest": self.catalog_digest,
            "nonce": self.nonce,
            "schema_version": EXTENSION_CONTROL_ENROLLMENT_SCHEMA,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
        framed = f"{EXTENSION_CONTROL_ENROLLMENT_SCHEMA}\x00{len(canonical)}\x00{canonical}"
        return hashlib.sha256(framed.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ExtensionControlEnrollmentProof:
    proof_id: str
    grant: ApprovalGateGrant
    actor_id: str
    catalog_digest: str
    enrollment_digest: str
    nonce: str
    session_nonce: str

    def __repr__(self) -> str:
        return "ExtensionControlEnrollmentProof(<redacted>)"


def issue_extension_control_enrollment_proof(
    guard_home: Path,
    enrollment: ExtensionControlEnrollment,
    *,
    approval_gate_input: ApprovalGateInput | None,
    session_nonce: str,
    terminal_input: TextIO,
    now: str | None = None,
) -> ExtensionControlEnrollmentProof:
    """Issue a one-shot enrollment proof only from an attested local terminal."""

    if not terminal_input.isatty():
        raise ExtensionControlProofError("extension control enrollment requires an interactive local terminal")
    if not session_nonce.strip() or len(session_nonce) > _MAX_IDENTITY_LENGTH:
        raise ExtensionControlProofError("invalid proof session nonce")
    digest = enrollment.canonical_digest
    grant = require_extension_control(
        guard_home,
        approval_gate_input=approval_gate_input,
        action=EXTENSION_CONTROL_ENROLLMENT_ACTION,
        subject=digest,
        session_nonce=session_nonce,
        now=now,
    )
    return ExtensionControlEnrollmentProof(
        proof_id=secrets.token_hex(32),
        grant=grant,
        actor_id=enrollment.actor_id,
        catalog_digest=enrollment.catalog_digest,
        enrollment_digest=digest,
        nonce=enrollment.nonce,
        session_nonce=session_nonce,
    )


def validate_extension_control_enrollment_proof(
    proof: ExtensionControlEnrollmentProof,
    enrollment: ExtensionControlEnrollment,
) -> None:
    """Validate every immutable first-enrollment binding."""

    _validate_proof_identifier(proof.proof_id)
    observed = (proof.actor_id, proof.catalog_digest, proof.nonce)
    expected = (enrollment.actor_id, enrollment.catalog_digest, enrollment.nonce)
    if observed != expected or not hmac.compare_digest(proof.enrollment_digest, enrollment.canonical_digest):
        raise ExtensionControlProofError("extension control enrollment proof does not match enrollment")


def consume_extension_control_enrollment_proof(
    guard_home: Path,
    proof: ExtensionControlEnrollmentProof,
    enrollment: ExtensionControlEnrollment,
    *,
    now: str | None = None,
) -> None:
    """Consume one exact first-enrollment proof."""

    validate_extension_control_enrollment_proof(proof, enrollment)
    consume_extension_control_grant(
        guard_home,
        proof.grant,
        action=EXTENSION_CONTROL_ENROLLMENT_ACTION,
        subject=proof.enrollment_digest,
        session_nonce=proof.session_nonce,
        now=now,
    )


def _validate_proof_identifier(proof_id: str) -> None:
    if len(proof_id) != 64 or any(character not in "0123456789abcdef" for character in proof_id):
        raise ExtensionControlProofError("invalid extension control proof identifier")


@dataclass(frozen=True, slots=True)
class ExtensionControlMutation:
    previous_revision: int
    catalog_digest: str
    layers: tuple[ExtensionControlLayer, ...]
    actor_id: str
    idempotency_key: str
    nonce: str

    def _canonical_layers(self) -> tuple[ExtensionControlLayer, ...]:
        return tuple(
            ExtensionControlLayer(
                schema_version=layer.schema_version,
                kind=layer.kind,
                catalog_digest=layer.catalog_digest,
                global_lockdown=layer.global_lockdown,
                controls=tuple(
                    sorted(
                        layer.controls,
                        key=lambda control: (
                            control.target.kind.value,
                            control.target.target_id,
                            control.state.value,
                        ),
                    )
                ),
            )
            for layer in sorted(self.layers, key=lambda value: value.kind.value)
        )

    def __post_init__(self) -> None:
        if type(self.previous_revision) is not int or self.previous_revision < 0:
            raise ExtensionControlProofError("invalid previous revision")
        if len(self.catalog_digest) != 64 or any(
            character not in "0123456789abcdef" for character in self.catalog_digest
        ):
            raise ExtensionControlProofError("invalid catalog digest")
        for value in (self.actor_id, self.idempotency_key, self.nonce):
            if not value.strip() or len(value) > _MAX_IDENTITY_LENGTH:
                raise ExtensionControlProofError("invalid mutation identity")

    @property
    def canonical_digest(self) -> str:
        canonical_layers = self._canonical_layers()
        payload = {
            "action": EXTENSION_CONTROL_PROOF_ACTION,
            "actor_id": self.actor_id,
            "catalog_digest": self.catalog_digest,
            "idempotency_key": self.idempotency_key,
            "layers": json.loads(layers_to_json(canonical_layers)),
            "nonce": self.nonce,
            "previous_revision": self.previous_revision,
            "schema_version": EXTENSION_CONTROL_PREVIEW_SCHEMA,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
        framed = f"{EXTENSION_CONTROL_PREVIEW_SCHEMA}\x00{len(canonical)}\x00{canonical}"
        return hashlib.sha256(framed.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ExtensionControlProof:
    proof_id: str
    grant: ApprovalGateGrant
    actor_id: str
    previous_revision: int
    catalog_digest: str
    canonical_diff_digest: str
    idempotency_key: str
    nonce: str
    session_nonce: str

    def __repr__(self) -> str:
        return "ExtensionControlProof(<redacted>)"


def issue_extension_control_proof(
    guard_home: Path,
    mutation: ExtensionControlMutation,
    *,
    approval_gate_input: ApprovalGateInput | None,
    session_nonce: str,
    now: str | None = None,
) -> ExtensionControlProof:
    """Issue one strict local proof bound to an exact canonical mutation."""

    if not session_nonce.strip() or len(session_nonce) > _MAX_IDENTITY_LENGTH:
        raise ExtensionControlProofError("invalid proof session nonce")
    digest = mutation.canonical_digest
    grant = require_extension_control(
        guard_home,
        approval_gate_input=approval_gate_input,
        action=EXTENSION_CONTROL_PROOF_ACTION,
        subject=digest,
        session_nonce=session_nonce,
        now=now,
    )
    proof_id = secrets.token_hex(32)
    return ExtensionControlProof(
        proof_id=proof_id,
        grant=grant,
        actor_id=mutation.actor_id,
        previous_revision=mutation.previous_revision,
        catalog_digest=mutation.catalog_digest,
        canonical_diff_digest=digest,
        idempotency_key=mutation.idempotency_key,
        nonce=mutation.nonce,
        session_nonce=session_nonce,
    )


def validate_extension_control_proof(
    proof: ExtensionControlProof,
    mutation: ExtensionControlMutation,
) -> None:
    """Validate every immutable proof binding without consuming its grant."""

    _validate_proof_identifier(proof.proof_id)
    expected = (
        mutation.actor_id,
        mutation.previous_revision,
        mutation.catalog_digest,
        mutation.idempotency_key,
        mutation.nonce,
    )
    observed = (
        proof.actor_id,
        proof.previous_revision,
        proof.catalog_digest,
        proof.idempotency_key,
        proof.nonce,
    )
    if observed != expected or not hmac.compare_digest(proof.canonical_diff_digest, mutation.canonical_digest):
        raise ExtensionControlProofError("extension control proof does not match mutation")


def consume_extension_control_proof(
    guard_home: Path,
    proof: ExtensionControlProof,
    mutation: ExtensionControlMutation,
    *,
    now: str | None = None,
) -> None:
    """Validate every mutation binding and consume the proof exactly once."""

    validate_extension_control_proof(proof, mutation)
    consume_extension_control_grant(
        guard_home,
        proof.grant,
        action=EXTENSION_CONTROL_PROOF_ACTION,
        subject=proof.canonical_diff_digest,
        session_nonce=proof.session_nonce,
        now=now,
    )
