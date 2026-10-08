"""Classify security rejections that cannot be treated as lost responses."""

from __future__ import annotations

_SECURITY_NATIVE_CODES = frozenset(
    {
        "native_client_auth_rejected",
        "native_client_peer_identity_failed",
        "native_resident_auth_rejected",
        "native_workspace_review_decision_expired",
        "native_workspace_review_authority_expired",
    }
)
_SECURITY_TOKENS = ("signature", "tenant", "revoked", "tamper", "replay", "binding", "mismatch", "grant")


def native_transport_security_rejection(code: str) -> bool:
    return code in _SECURITY_NATIVE_CODES or any(token in code for token in _SECURITY_TOKENS)


