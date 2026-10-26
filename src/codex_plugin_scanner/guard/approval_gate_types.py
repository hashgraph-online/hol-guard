"""Public value types and wire decoders for the local approval gate."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, cast

from .approval_gate_state import ApprovalGatePublicConfig, optional_bool, optional_string

ApprovalGatePurpose = Literal[
    "approval_decision",
    "policy_write",
    "policy_clear",
    "policy_import",
    "policy_export_provenance",
    "evidence_clear",
    "queue_clear",
    "settings_write",
    "native_policy",
    "tool_call_policy",
    "headless_policy_sync",
    "supply_chain_firewall",
    "extension_control_mutation",
    "local_cli_trust_mutation",
    "protection_lifecycle",
]


class ApprovalGateError(PermissionError):
    """Raised when an approval gate check fails."""

    def __init__(self, code: str, message: str, *, status: int = 403) -> None:
        super().__init__(message)
        self.code = code
        self.status = status

    def to_payload(self) -> dict[str, object]:
        return {"error": self.code, "message": str(self)}


@dataclass(frozen=True, slots=True)
class ApprovalGateInput:
    """Password material supplied for one local approval gate check."""

    password: str | None = None
    new_password: str | None = None
    confirm_password: str | None = None
    totp_code: str | None = None
    use_cooldown: bool | None = None
    revoke_cooldown: bool = False
    require_fresh_totp: bool = False


@dataclass(frozen=True, slots=True)
class ApprovalGateGrant:
    """Short-lived proof produced only after the local gate is satisfied."""

    grant_id: str
    purpose: ApprovalGatePurpose
    issued_at: str
    expires_at: str
    action: str
    scope: str
    subject: str
    session_nonce: str
    factor_set: tuple[str, ...]
    strict: bool
    used_cooldown: bool
    cooldown_expires_at: str | None
    password_verified: bool
    totp_verified: bool


def grant_from_wire(payload: object) -> ApprovalGateGrant | None:
    """Reconstruct an ``ApprovalGateGrant`` from a resident op grant dict."""
    if not isinstance(payload, dict):
        return None
    try:
        return ApprovalGateGrant(
            grant_id=str(payload["grant_id"]),
            purpose=cast(ApprovalGatePurpose, str(payload["purpose"])),
            issued_at=str(payload["issued_at"]),
            expires_at=str(payload["expires_at"]),
            action=str(payload["action"]),
            scope=str(payload["scope"]),
            subject=str(payload["subject"]),
            session_nonce=str(payload["session_nonce"]),
            factor_set=tuple(str(f) for f in payload["factor_set"]),
            strict=bool(payload["strict"]),
            used_cooldown=bool(payload["used_cooldown"]),
            cooldown_expires_at=(
                None if payload.get("cooldown_expires_at") is None else str(payload["cooldown_expires_at"])
            ),
            password_verified=bool(payload["password_verified"]),
            totp_verified=bool(payload["totp_verified"]),
        )
    except (KeyError, TypeError, ValueError):
        return None


def config_from_wire(payload: object) -> ApprovalGatePublicConfig | None:
    """Reconstruct ``ApprovalGatePublicConfig`` from a resident op dict."""
    if not isinstance(payload, dict):
        return None
    try:
        return ApprovalGatePublicConfig(
            enabled=bool(payload["enabled"]),
            configured=bool(payload["configured"]),
            cooldown_seconds=int(payload["cooldown_seconds"]),
            cooldown_active=bool(payload["cooldown_active"]),
            cooldown_expires_at=payload.get("cooldown_expires_at"),
            locked_until=payload.get("locked_until"),
            fail_closed=bool(payload["fail_closed"]),
            strict_all_decisions=bool(payload["strict_all_decisions"]),
            totp_enabled=bool(payload["totp_enabled"]),
            totp_pending=bool(payload["totp_pending"]),
            totp_recent_satisfied=bool(payload.get("totp_recent_satisfied", False)),
        )
    except (KeyError, TypeError, ValueError):
        return None


def input_from_mapping(payload: object) -> ApprovalGateInput | None:
    """Build gate input from daemon or dashboard payload without retaining extras."""

    if not isinstance(payload, dict):
        return None
    gate_payload = payload.get("approval_gate")
    gate_mapping = gate_payload if isinstance(gate_payload, dict) else {}
    password = optional_string(payload.get("approval_password")) or optional_string(gate_mapping.get("password"))
    current_password = optional_string(gate_mapping.get("current_password"))
    totp_code = optional_string(payload.get("approval_totp_code")) or optional_string(gate_mapping.get("totp_code"))
    return ApprovalGateInput(
        password=current_password or password,
        new_password=optional_string(gate_mapping.get("new_password")),
        confirm_password=optional_string(gate_mapping.get("confirm_password")),
        totp_code=totp_code,
        use_cooldown=optional_bool(payload.get("approval_gate_use_cooldown"), gate_mapping.get("use_cooldown")),
        revoke_cooldown=optional_bool(gate_mapping.get("revoke_cooldown"), False) is True,
    )
