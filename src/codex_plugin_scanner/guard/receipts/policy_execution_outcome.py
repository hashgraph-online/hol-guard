"""Bounded self-attested completion evidence from an executed subprocess."""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Protocol

from ..models import GuardReceipt
from ..policy_publication_binding import PolicyPublicationBinding
from ..policy_rule_identity import PolicyRuleIdentity, package_policy_rule_identity
from ..runtime.actions import GuardActionEnvelope

_SCHEMA = "guard.policy-execution-outcome.v1"
_RECEIPT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", re.ASCII)
_FIELDS = frozenset(
    {
        "schemaVersion",
        "receiptId",
        "completedAt",
        "outcome",
        "source",
        "trust",
        "policyId",
        "ruleId",
        "policyVersion",
        "bundleVersion",
        "bundleHash",
        "installationId",
    }
)


class ExecutionReceiptStore(Protocol):
    def add_receipt(
        self, receipt: GuardReceipt, *, action_envelope: GuardActionEnvelope | dict[str, object] | None = None
    ) -> None: ...


def safe_policy_execution_outcome(value: object) -> dict[str, object] | None:
    """Retain only the complete public completion schema during redaction."""
    if not isinstance(value, Mapping) or set(value) != _FIELDS:
        return None
    if (
        (value.get("schemaVersion"), value.get("source"), value.get("trust"))
        != (
            _SCHEMA,
            "guard_subprocess",
            "self_attested",
        )
        or not isinstance(value.get("outcome"), str)
        or value.get("outcome") not in {"succeeded", "failed"}
    ):
        return None
    identity = PolicyRuleIdentity.from_mapping(value)
    publication = PolicyPublicationBinding.from_mapping(
        {key: value[key] for key in ("bundleVersion", "bundleHash", "installationId")}
    )
    receipt_id, completed_at = value.get("receiptId"), value.get("completedAt")
    if identity is None or publication is None or not isinstance(receipt_id, str) or not isinstance(completed_at, str):
        return None
    try:
        if _RECEIPT_ID.fullmatch(receipt_id) is None:
            return None
        timestamp = datetime.fromisoformat(completed_at.replace("Z", "+00:00"))
        if (
            len(completed_at) > 40
            or timestamp.tzinfo is None
            or timestamp.utcoffset() != timezone.utc.utcoffset(timestamp)
        ):
            return None
    except (TypeError, ValueError, OverflowError):
        return None
    return dict(value)


def completed_policy_execution_outcome(
    *, identity: PolicyRuleIdentity | None, receipt_id: str, completed_at: str, returncode: int
) -> dict[str, object] | None:
    if identity is None or identity.publication is None or type(returncode) is not int:
        return None
    return safe_policy_execution_outcome(
        {
            "schemaVersion": _SCHEMA,
            "receiptId": receipt_id,
            "completedAt": completed_at,
            "outcome": "succeeded" if returncode == 0 else "failed",
            "source": "guard_subprocess",
            "trust": "self_attested",
            **identity.to_dict(),
            **identity.publication.to_dict(),
        }
    )


def persist_completed_package_receipt(
    *,
    store: ExecutionReceiptStore,
    receipt: GuardReceipt,
    metadata: Mapping[str, object],
    evaluation: object,
    final_action: object,
    returncode: int,
) -> None:
    """Called only after subprocess.run returns an actual terminal result.

    Identity was captured from the authenticated final winning rule before
    launch. Do not read mutable current policy or infer completion from allow.
    """
    witness = completed_policy_execution_outcome(
        identity=package_policy_rule_identity(evaluation, final_action),
        receipt_id=receipt.receipt_id,
        completed_at=datetime.now(timezone.utc).isoformat(),
        returncode=returncode,
    )
    if returncode != 0 and witness is None:
        return
    envelope = dict(metadata)
    if witness is not None:
        envelope["policyExecutionOutcome"] = witness
    store.add_receipt(receipt, action_envelope=envelope)
