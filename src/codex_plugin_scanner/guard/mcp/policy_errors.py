"""Stable machine-readable error codes for MCP policy authoring tools.

Every error returned through the guard-mcp.v1 envelope uses one of these
codes.  No raw exception text, SQLite error, file path, or credential
material ever escapes through MCP.
"""

from __future__ import annotations

INVALID_ARGUMENTS = "invalid_arguments"
POLICY_TOO_LARGE = "policy_too_large"
POLICY_PARSE_FAILED = "policy_parse_failed"
POLICY_SCHEMA_INVALID = "policy_schema_invalid"
POLICY_COMPILE_FAILED = "policy_compile_failed"
POLICY_AUTHORITY_DENIED = "policy_authority_denied"
POLICY_IMPORT_DISABLED = "policy_import_disabled"
MCP_POLICY_WRITE_DISABLED = "mcp_policy_write_disabled"
CANDIDATE_DIGEST_MISMATCH = "candidate_digest_mismatch"
CURRENT_DIGEST_MISMATCH = "current_digest_mismatch"
POLICY_NO_CHANGES = "policy_no_changes"
IDEMPOTENCY_CONFLICT = "idempotency_conflict"
APPROVAL_REQUIRED = "approval_required"
APPROVAL_DECLINED = "approval_declined"
APPROVAL_EXPIRED = "approval_expired"
APPROVAL_ALREADY_RESOLVED = "approval_already_resolved"
APPROVAL_GATE_REQUIRED = "approval_gate_required"
APPROVAL_GATE_DENIED = "approval_gate_denied"
POLICY_REQUEST_NOT_FOUND = "policy_request_not_found"
POLICY_WRITE_CONFLICT = "policy_write_conflict"
POLICY_WRITE_FAILED = "policy_write_failed"
STALE_POLICY_GENERATION = "stale_policy_generation"


_ALL_CODES = frozenset(
    {
        INVALID_ARGUMENTS,
        POLICY_TOO_LARGE,
        POLICY_PARSE_FAILED,
        POLICY_SCHEMA_INVALID,
        POLICY_COMPILE_FAILED,
        POLICY_AUTHORITY_DENIED,
        POLICY_IMPORT_DISABLED,
        MCP_POLICY_WRITE_DISABLED,
        CANDIDATE_DIGEST_MISMATCH,
        CURRENT_DIGEST_MISMATCH,
        POLICY_NO_CHANGES,
        IDEMPOTENCY_CONFLICT,
        APPROVAL_REQUIRED,
        APPROVAL_DECLINED,
        APPROVAL_EXPIRED,
        APPROVAL_ALREADY_RESOLVED,
        APPROVAL_GATE_REQUIRED,
        APPROVAL_GATE_DENIED,
        POLICY_REQUEST_NOT_FOUND,
        POLICY_WRITE_CONFLICT,
        POLICY_WRITE_FAILED,
        STALE_POLICY_GENERATION,
    }
)


class PolicyToolError(Exception):
    """Bounded MCP policy tool error carrying a stable code."""

    __slots__ = ("code", "message", "retryable")

    def __init__(self, code: str, message: str, *, retryable: bool = False) -> None:
        if code not in _ALL_CODES:
            raise ValueError(f"unknown_policy_error_code:{code}")
        self.code = code
        self.message = message
        self.retryable = retryable
        super().__init__(message[:512])

    def to_payload(self) -> dict[str, object]:
        return {
            "code": self.code,
            "message": self.message[:512],
            "retryable": self.retryable,
        }


__all__ = [
    "APPROVAL_ALREADY_RESOLVED",
    "APPROVAL_DECLINED",
    "APPROVAL_EXPIRED",
    "APPROVAL_GATE_DENIED",
    "APPROVAL_GATE_REQUIRED",
    "APPROVAL_REQUIRED",
    "CANDIDATE_DIGEST_MISMATCH",
    "CURRENT_DIGEST_MISMATCH",
    "IDEMPOTENCY_CONFLICT",
    "MCP_POLICY_WRITE_DISABLED",
    "POLICY_AUTHORITY_DENIED",
    "POLICY_COMPILE_FAILED",
    "POLICY_IMPORT_DISABLED",
    "POLICY_NO_CHANGES",
    "POLICY_PARSE_FAILED",
    "POLICY_REQUEST_NOT_FOUND",
    "POLICY_SCHEMA_INVALID",
    "POLICY_WRITE_CONFLICT",
    "POLICY_WRITE_FAILED",
    "STALE_POLICY_GENERATION",
    "PolicyToolError",
]
