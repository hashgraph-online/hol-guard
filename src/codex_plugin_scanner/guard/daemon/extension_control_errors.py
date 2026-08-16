"""Shared extension-control daemon API errors.

Kept separate from the API service so helper evaluators can raise the same
public error type without creating an import cycle.
"""

from __future__ import annotations

from dataclasses import dataclass

_RECOVERY_ACTIONS = {
    "approval_required": "provide_local_approval",
    "authority_conflict": "refresh_effective_controls",
    "authority_unavailable": "enroll_or_repair_authority",
    "catalog_conflict": "refresh_catalog",
    "immutable_extension": "remove_local_override",
    "immutable_permission": "remove_local_override",
    "managed_layer_mutation": "managed_policy_read_only",
    "proof_invalid": "request_new_proof",
    "proof_mismatch": "request_new_proof",
    "proof_not_found": "request_new_proof",
    "revision_conflict": "refresh_effective_controls",
}


@dataclass(frozen=True, slots=True)
class ExtensionControlApiError(Exception):
    """Stable error envelope shared by inspection, Test Lab, and mutation APIs."""

    status: int
    code: str

    def to_payload(self) -> dict[str, object]:
        payload: dict[str, object] = {"error": self.code}
        action = _RECOVERY_ACTIONS.get(self.code)
        if action is not None:
            payload["recovery"] = {"action": action}
        return payload
