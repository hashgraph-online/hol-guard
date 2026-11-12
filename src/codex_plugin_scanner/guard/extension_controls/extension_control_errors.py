"""Shared extension-control daemon API errors.

Kept separate from the API service so helper evaluators can raise the same
public error type without creating an import cycle.
"""

from __future__ import annotations

_RECOVERY_ACTIONS = {
    "approval_required": "provide_local_approval",
    "authority_apply_failed": "refresh_effective_controls",
    "authority_conflict": "refresh_effective_controls",
    "authority_unavailable": "enroll_or_repair_authority",
    "authority_unread": "refresh_effective_controls",
    "catalog_conflict": "refresh_catalog",
    "immutable_extension": "remove_local_override",
    "immutable_permission": "remove_local_override",
    "managed_layer_mutation": "managed_policy_read_only",
    "pack_preparation_unavailable": "retry_pack_preparation",
    "proof_invalid": "request_new_proof",
    "proof_mismatch": "request_new_proof",
    "proof_not_found": "request_new_proof",
    "revision_conflict": "refresh_effective_controls",
}

# A classified, non-sensitive cause narrows a generic failure code to the step
# that actually failed. It never carries a path, a URL or an exception message.
# Every cause the classifier can return needs an entry: the code-level fallback
# below is `retry_pack_preparation`, and a client that acts on it would retry a
# withdrawn pack or a broken install forever.
_CAUSE_RECOVERY_ACTIONS = {
    "installed_runtime_incomplete": "repair_guard_installation",
    "installed_runtime_unresponsive": "retry_pack_preparation",
    "internal": "inspect_daemon_log",
    "local_storage": "repair_local_cache",
    # The request outgrew the one frame the runtime reads. The install is
    # intact, so `repair_guard_installation` would be a lie, and the request is
    # rebuilt byte-for-byte on a retry, so `retry_pack_preparation` is another.
    # No local command prunes the state the request is built from either:
    # `recover-authority` answers `authority_not_recoverable` on a healthy
    # authority and would leave that state untouched if it ran. What the daemon
    # log does carry is which record grew, so that is what this points at
    # rather than a command that cannot change the outcome.
    "native_request_too_large": "inspect_daemon_log",
    "offline": "retry_when_reachable",
    # The control authority is already protected when preparation runs, so
    # `recover-authority` answers `authority_not_recoverable` here. What is
    # missing is a publication this install can authenticate.
    "pack_authority_unavailable": "update_guard_or_reconnect",
    "pack_revoked": "refresh_catalog",
    "release_unavailable": "retry_when_reachable",
}


class ExtensionControlApiError(Exception):
    """Stable error envelope shared by inspection, Test Lab, and mutation APIs."""

    def __init__(self, status: int, code: str, *, cause: str | None = None) -> None:
        super().__init__(status, code)
        self.status = status
        self.code = code
        self.cause = cause

    def to_payload(self) -> dict[str, object]:
        payload: dict[str, object] = {"error": self.code}
        if self.cause is not None:
            payload["cause"] = self.cause
        action = _CAUSE_RECOVERY_ACTIONS.get(self.cause or "") or _RECOVERY_ACTIONS.get(self.code)
        if action is not None:
            payload["recovery"] = {"action": action}
        return payload
