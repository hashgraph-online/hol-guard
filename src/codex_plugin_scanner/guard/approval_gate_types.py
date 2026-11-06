"""Public value types and wire decoders for the local approval gate."""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Callable
from dataclasses import dataclass, field, replace
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

# How a caller takes part in a Yanez Pulse approval when the gate asks for one:
# "off" never creates a Pulse request, "wait" creates one and waits for the
# YID app (CLI), "defer" creates one and hands back its id to poll (dashboard).
PulseMode = Literal["off", "wait", "defer"]
PulseStatusCallback = Callable[[str, dict[str, object]], None]


class ApprovalGateError(PermissionError):
    """Raised when an approval gate check fails."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        status: int = 403,
        details: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.status = status
        self.details = dict(details or {})

    def to_payload(self) -> dict[str, object]:
        return {**self.details, "error": self.code, "message": str(self)}


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
    pulse_request_id: str | None = None
    pulse_agent_key: str | None = field(default=None, repr=False)
    pulse_recovery_code: str | None = field(default=None, repr=False)
    pulse_mode: PulseMode = "off"
    # A bulk approval's request ids, so the YID app can summarize the batch.
    # Sent only as a ``pulse_request`` parameter; the resident uses them only
    # when they hash to the batch subject the grant is bound to.
    pulse_batch_request_ids: tuple[str, ...] = ()
    pulse_on_status: PulseStatusCallback | None = field(default=None, compare=False, repr=False)


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
            pulse_enabled=payload.get("pulse_enabled") is True,
            pulse_cooldown_seconds=int(payload.get("pulse_cooldown_seconds") or 0),
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
    pulse_request_id = optional_string(payload.get("approval_pulse_request_id")) or optional_string(
        gate_mapping.get("pulse_request_id")
    )
    wants_pulse = payload.get("approval_gate_pulse") is True or gate_mapping.get("pulse") is True
    if pulse_request_id is not None:
        # The YID approval is the proof now; the resident refuses a password or code beside it.
        password = current_password = totp_code = None
    return ApprovalGateInput(
        password=current_password or password,
        new_password=optional_string(gate_mapping.get("new_password")),
        confirm_password=optional_string(gate_mapping.get("confirm_password")),
        totp_code=totp_code,
        use_cooldown=optional_bool(payload.get("approval_gate_use_cooldown"), gate_mapping.get("use_cooldown")),
        revoke_cooldown=optional_bool(gate_mapping.get("revoke_cooldown"), False) is True,
        pulse_request_id=pulse_request_id,
        pulse_mode="defer" if wants_pulse and pulse_request_id is None else "off",
    )


def settings_input_from_payload(payload: object) -> ApprovalGateInput | None:
    """Build gate input for a settings save.

    The proof usually sits in ``settings.approval_gate``. The dashboard's Pulse
    fields (``approval_gate_pulse`` and ``approval_pulse_request_id``) are
    top-level, like on every other gated route, so they are applied on top.
    """

    if not isinstance(payload, dict):
        return None
    settings = payload.get("settings")
    gate_payload = settings.get("approval_gate") if isinstance(settings, dict) else None
    gate_input = input_from_mapping({"approval_gate": gate_payload}) if isinstance(gate_payload, dict) else None
    if payload.get("approval_password") or payload.get("approval_totp_code"):
        gate_input = input_from_mapping(payload) or gate_input
    pulse = input_from_mapping({key: payload[key] for key in _PULSE_PAYLOAD_KEYS if key in payload})
    if pulse is None or (pulse.pulse_mode == "off" and pulse.pulse_request_id is None):
        return gate_input
    base = gate_input or ApprovalGateInput()
    if pulse.pulse_request_id is not None:
        # The YID approval is the proof now; the resident refuses a password or code beside it.
        base = replace(base, password=None, totp_code=None)
    return replace(base, pulse_mode=pulse.pulse_mode, pulse_request_id=pulse.pulse_request_id)


_PULSE_PAYLOAD_KEYS = ("approval_gate_pulse", "approval_pulse_request_id")

# Proof and proof-use fields: they say how the change is approved, not what it is.
_SETTINGS_PROOF_KEYS = frozenset(
    {"password", "current_password", "totp_code", "pulse", "pulse_request_id", "use_cooldown"}
)


def settings_write_subject(settings: object, key: str) -> str:
    """Name one exact settings change, so a grant for it covers no other change.

    The grant's subject is bound into a Pulse request, so an approval in the
    YID app cannot be resubmitted with different settings. The digest is
    keyed (the daemon's token), so a new password inside the change cannot be
    guessed from a subject that reaches a log.
    """
    changes = settings if isinstance(settings, dict) else {}
    gate = changes.get("approval_gate")
    if isinstance(gate, dict):
        changes = {
            **changes,
            "approval_gate": {name: value for name, value in gate.items() if name not in _SETTINGS_PROOF_KEYS},
        }
    canonical = json.dumps(changes, sort_keys=True, separators=(",", ":"), default=str)
    digest = hmac.new(key.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"settings:{digest}"
