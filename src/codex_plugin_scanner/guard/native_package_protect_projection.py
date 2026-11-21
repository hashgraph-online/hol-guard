"""Resident bridge for the package-protect ``protect_projection`` query.

The resident owns the verdict, receipt and every user-facing surface of one
package-protect projection. Python hands over the authority and evaluation it
assembled, then persists the receipt and merges the surfaces into its payload.
A missing or malformed answer raises
:class:`~.native_package_audit_projection.NativePackageAuditProjectionError`;
there is no Python fallback.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from .models import GuardReceipt
from .native_package_audit_projection import NativePackageAuditProjectionError, _send

_FIELD_KEYS = (
    "request",
    "targets",
    "verdict",
    "receipt",
    "matched_advisories",
    "supply_chain_evaluation",
    "executed",
)
_RESULT_KEYS = frozenset(
    {
        "fields",
        "verdict_action",
        "risk_signals",
        "event_payload",
        "execution_permitted",
        "execution_exit_code",
        "policy_exit_code",
    }
)
_ACTIONS = frozenset({"allow", "warn", "review", "require-reapproval", "sandbox-required", "block"})


@dataclass(frozen=True, slots=True)
class NativePackageProtectProjection:
    """One resident-built projection; persist ``receipt`` and merge ``fields``."""

    fields: dict[str, object]
    receipt: GuardReceipt
    receipt_policy_metadata: dict[str, object]
    verdict_action: str
    risk_signals: tuple[str, ...]
    event_payload: dict[str, object]
    execution_permitted: bool
    execution_exit_code: int
    policy_exit_code: int


def native_package_protect_projection(
    store: Any,
    *,
    authority: Any,
    evaluation: Any,
    command: Sequence[str],
    executed: bool,
    blocking: bool | None = None,
    project_execution_action: bool = True,
) -> NativePackageProtectProjection:
    """Project one authority/evaluation pair through the resident."""

    intent = authority.intent
    artifact = authority.artifact
    payload = _send(
        {
            "query": "protect_projection",
            "intent": {
                "package_manager": intent.package_manager,
                "intent_kind": intent.intent_kind,
                "redacted_command": intent.redacted_command,
                "manifest_paths": list(intent.manifest_paths),
                "lockfile_paths": list(intent.lockfile_paths),
                "targets": [target.to_execution_dict() for target in intent.targets],
            },
            "artifact": {
                "artifact_id": artifact.artifact_id,
                "name": artifact.name,
                "source_scope": artifact.source_scope,
            },
            "execution_context": authority.execution_context.to_evidence(),
            "artifact_hash": authority.artifact_hash,
            "additional_policy_context": authority.additional_policy_context,
            "observe_mode": authority.observe_mode,
            "invoking_harness": authority.invoking_harness,
            "evaluation": evaluation.to_dict(),
            "command": [str(item) for item in command],
            "blocking": blocking,
            "executed": executed,
            "project_execution_action": project_execution_action,
        },
        store,
    )
    return _decode(payload)


def _decode(payload: dict[str, Any]) -> NativePackageProtectProjection:
    fields = payload.get("fields")
    action = payload.get("verdict_action")
    signals = payload.get("risk_signals")
    if (
        set(payload) != _RESULT_KEYS
        or not isinstance(fields, dict)
        or set(fields) != set(_FIELD_KEYS)
        or action not in _ACTIONS
        or not isinstance(signals, list)
        or not all(isinstance(item, str) for item in signals)
        or not isinstance(payload.get("event_payload"), dict)
        or not isinstance(payload.get("execution_permitted"), bool)
        or payload.get("execution_exit_code") not in {0, 2}
        or payload.get("policy_exit_code") not in {0, 2}
    ):
        raise NativePackageAuditProjectionError("Native package protect projection invalid")
    receipt_fields = fields.get("receipt")
    if not isinstance(receipt_fields, dict) or not isinstance(receipt_fields.get("action_envelope_json"), dict):
        raise NativePackageAuditProjectionError("Native package protect projection invalid")
    metadata = receipt_fields["action_envelope_json"]
    stored = {key: value for key, value in receipt_fields.items() if key != "action_envelope_json"}
    try:
        stored["changed_capabilities"] = tuple(stored["changed_capabilities"])
        stored["scanner_evidence"] = tuple(stored["scanner_evidence"])
        receipt = GuardReceipt(**stored)
    except (KeyError, TypeError) as error:
        raise NativePackageAuditProjectionError("Native package protect projection invalid") from error
    return NativePackageProtectProjection(
        fields=fields,
        receipt=receipt,
        receipt_policy_metadata=metadata,
        verdict_action=action,
        risk_signals=tuple(signals),
        event_payload=payload["event_payload"],
        execution_permitted=payload["execution_permitted"],
        execution_exit_code=payload["execution_exit_code"],
        policy_exit_code=payload["policy_exit_code"],
    )
