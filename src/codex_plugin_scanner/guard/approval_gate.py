"""Local approval gate: transport and presentation for the native authority.

The resident ``approval_gate`` op decides eligibility, identity/context
matching, grant issue/claim/consume ordering, lockout, cooldown, TOTP and
policy revalidation. This module marshals one request per call, binds it to the
resident's answer, and presents the result. It never recomputes a verdict.

A provisioned resident that fails to answer raises
``native_approval_gate_unavailable`` (fail closed). The one thing Python still
observes itself is whether a guard home has *ever* configured the gate (the
state file exists); a home that never did has nothing to enforce, so read-only
checks on it succeed without a resident.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from .approval_gate_state import APPROVAL_GATE_STATE_FILE, ApprovalGatePublicConfig
from .approval_gate_types import (
    ApprovalGateError,
    ApprovalGateGrant,
    ApprovalGateInput,
    ApprovalGatePurpose,
    config_from_wire,
    grant_from_wire,
    input_from_mapping,
)
from .native_approval_gate import approval_gate_native as _approval_gate_native_impl

if TYPE_CHECKING:
    from .models import PolicyDecision

# Public names other modules import from here; the types live in approval_gate_types.
__all__ = [
    "ApprovalGateError",
    "ApprovalGateGrant",
    "ApprovalGateInput",
    "ApprovalGatePublicConfig",
    "ApprovalGatePurpose",
    "begin_totp_enrollment",
    "confirm_totp_enrollment",
    "consume_extension_control_grant",
    "consume_local_cli_trust_grant",
    "disable_totp",
    "input_from_mapping",
    "public_config",
    "recent_totp_satisfied",
    "require_approval_decision",
    "require_extension_control",
    "require_high_risk",
    "require_local_cli_trust",
    "require_policy_clear",
    "require_policy_write",
    "require_request_resolution",
    "require_settings_write",
    "revoke_cooldown",
    "unlock_cooldown",
    "update_settings",
    "validate_grant",
    "validate_settings_update",
]

# Test seams for the wire decoders.
_approval_gate_native: Callable[..., dict[str, object] | None] = _approval_gate_native_impl
_config_from_wire = config_from_wire
_grant_from_wire = grant_from_wire

_UNCONFIGURED_CONFIG = ApprovalGatePublicConfig(
    enabled=False,
    configured=False,
    cooldown_seconds=0,
    cooldown_active=False,
    cooldown_expires_at=None,
    locked_until=None,
    fail_closed=False,
    strict_all_decisions=False,
    totp_enabled=False,
    totp_pending=False,
)


def _unavailable() -> ApprovalGateError:
    return ApprovalGateError(
        "native_approval_gate_unavailable",
        "The native approval authority did not answer. Retry the approval.",
        status=503,
    )


# Only explicit configuration operations establish a home's resident verifier
# key, plus any call on a home whose gate is already configured (state written
# by an earlier release has no key yet and must stay answerable). A home that
# never configured the gate is never given a key by a passive check.
_CONFIGURATION_METHODS = frozenset(
    {
        "update_settings",
        "validate_settings_update",
        "revoke_cooldown",
        "unlock_cooldown",
        "begin_totp_enrollment",
        "confirm_totp_enrollment",
        "disable_totp",
    }
)


def _provisions_prerequisite(method: str, guard_home: Path) -> bool:
    return method in _CONFIGURATION_METHODS or (Path(guard_home) / APPROVAL_GATE_STATE_FILE).exists()


def _native(method: str, guard_home: Path, **kwargs: object) -> dict[str, object]:
    """One resident round trip; no resident means no authority (fail closed)."""
    payload = _approval_gate_native(
        method,
        guard_home,
        provision_prerequisite=_provisions_prerequisite(method, guard_home),
        **kwargs,
    )
    if payload is None:
        raise _unavailable()
    return payload


def _native_or_unconfigured(method: str, guard_home: Path, **kwargs: object) -> dict[str, object] | None:
    """Like ``_native``, but ``None`` for a home that never configured the gate."""
    payload = _approval_gate_native(
        method,
        guard_home,
        provision_prerequisite=_provisions_prerequisite(method, guard_home),
        **kwargs,
    )
    if payload is not None:
        return payload
    if (Path(guard_home) / APPROVAL_GATE_STATE_FILE).exists():
        raise _unavailable()
    return None


def _config(payload: dict[str, object]) -> ApprovalGatePublicConfig:
    config = config_from_wire(payload)
    if config is None:
        raise _unavailable()
    return config


def _grant(payload: dict[str, object]) -> ApprovalGateGrant | None:
    """``None`` only when the resident answered "no gate required"."""
    wire = payload.get("grant")
    if wire is None and "grant" in payload:
        return None
    grant = grant_from_wire(wire)
    if grant is None:
        raise _unavailable()
    return grant


def public_config(guard_home: Path, *, now: str | None = None) -> ApprovalGatePublicConfig:
    payload = _native_or_unconfigured("public_config", guard_home, now=now)
    return _UNCONFIGURED_CONFIG if payload is None else _config(payload)


def recent_totp_satisfied(guard_home: Path, *, now: str | None = None) -> bool:
    """Return whether this local OS session has a valid recent TOTP proof."""
    payload = _native_or_unconfigured("recent_totp_satisfied", guard_home, now=now)
    return payload is not None and payload.get("satisfied") is True


def update_settings(
    guard_home: Path,
    payload: object,
    *,
    approval_gate_grant: ApprovalGateGrant | None = None,
    now: str | None = None,
) -> ApprovalGatePublicConfig:
    return _config(
        _native(
            "update_settings",
            guard_home,
            params=payload if isinstance(payload, dict) else {},
            approval_gate_grant=approval_gate_grant,
            now=now,
        )
    )


def validate_settings_update(
    guard_home: Path,
    payload: object,
    *,
    approval_gate_grant: ApprovalGateGrant | None = None,
    now: str | None = None,
) -> None:
    _native(
        "validate_settings_update",
        guard_home,
        params=payload if isinstance(payload, dict) else {},
        approval_gate_grant=approval_gate_grant,
        now=now,
    )


def revoke_cooldown(guard_home: Path, *, now: str | None = None) -> ApprovalGatePublicConfig:
    return _config(_native("revoke_cooldown", guard_home, now=now))


def unlock_cooldown(
    guard_home: Path,
    *,
    duration_seconds: int,
    approval_gate_input: ApprovalGateInput | None = None,
    now: str | None = None,
) -> ApprovalGatePublicConfig:
    return _config(
        _native(
            "unlock_cooldown",
            guard_home,
            duration_seconds=duration_seconds,
            approval_gate_input=approval_gate_input,
            now=now,
        )
    )


def begin_totp_enrollment(
    guard_home: Path,
    *,
    approval_gate_input: ApprovalGateInput | None = None,
    device_label: str = "local-device",
    now: str | None = None,
) -> dict[str, object]:
    return _native(
        "begin_totp_enrollment",
        guard_home,
        approval_gate_input=approval_gate_input,
        device_label=device_label,
        now=now,
    )


def confirm_totp_enrollment(
    guard_home: Path,
    *,
    approval_gate_input: ApprovalGateInput | None = None,
    now: str | None = None,
) -> ApprovalGatePublicConfig:
    return _config(_native("confirm_totp_enrollment", guard_home, approval_gate_input=approval_gate_input, now=now))


def disable_totp(
    guard_home: Path,
    *,
    approval_gate_input: ApprovalGateInput | None = None,
    now: str | None = None,
) -> ApprovalGatePublicConfig:
    return _config(_native("disable_totp", guard_home, approval_gate_input=approval_gate_input, now=now))


def require_approval_decision(
    guard_home: Path,
    *,
    action: str,
    scope: str,
    approval_gate_input: ApprovalGateInput | None = None,
    approval_gate_grant: ApprovalGateGrant | None = None,
    subject: str | None = None,
    session_nonce: str | None = None,
    now: str | None = None,
) -> ApprovalGateGrant | None:
    payload = _native_or_unconfigured(
        "require_approval_decision",
        guard_home,
        params={"action": action, "scope": scope, "subject": subject, "session_nonce": session_nonce},
        approval_gate_input=approval_gate_input,
        approval_gate_grant=approval_gate_grant,
        now=now,
    )
    return None if payload is None else _grant(payload)


def require_policy_write(
    guard_home: Path,
    *,
    decision: PolicyDecision,
    approval_gate_grant: ApprovalGateGrant | None = None,
    now: str | None = None,
) -> None:
    _native_or_unconfigured(
        "require_policy_write",
        guard_home,
        params={"action": decision.action, "scope": decision.scope},
        approval_gate_grant=approval_gate_grant,
        now=now,
    )


def require_request_resolution(
    guard_home: Path,
    *,
    resolution_action: str,
    resolution_scope: str,
    approval_gate_grant: ApprovalGateGrant | None = None,
    now: str | None = None,
) -> None:
    _native_or_unconfigured(
        "require_request_resolution",
        guard_home,
        params={"action": resolution_action, "scope": resolution_scope},
        approval_gate_grant=approval_gate_grant,
        now=now,
    )


def require_policy_clear(
    guard_home: Path,
    *,
    approval_gate_grant: ApprovalGateGrant | None = None,
    now: str | None = None,
) -> None:
    _native_or_unconfigured("require_policy_clear", guard_home, approval_gate_grant=approval_gate_grant, now=now)


def require_settings_write(
    guard_home: Path,
    *,
    approval_gate_grant: ApprovalGateGrant | None = None,
    now: str | None = None,
) -> None:
    _native_or_unconfigured("require_settings_write", guard_home, approval_gate_grant=approval_gate_grant, now=now)


def require_high_risk(
    guard_home: Path,
    *,
    purpose: ApprovalGatePurpose,
    approval_gate_input: ApprovalGateInput | None = None,
    approval_gate_grant: ApprovalGateGrant | None = None,
    action: str | None = None,
    scope: str | None = None,
    subject: str | None = None,
    session_nonce: str | None = None,
    now: str | None = None,
) -> ApprovalGateGrant | None:
    payload = _native_or_unconfigured(
        "require_high_risk",
        guard_home,
        params={"action": action, "scope": scope, "subject": subject, "session_nonce": session_nonce},
        approval_gate_input=approval_gate_input,
        approval_gate_grant=approval_gate_grant,
        purpose=purpose,
        now=now,
    )
    return None if payload is None else _grant(payload)


def require_extension_control(
    guard_home: Path,
    *,
    approval_gate_input: ApprovalGateInput | None,
    action: str,
    subject: str,
    session_nonce: str,
    now: str | None = None,
) -> ApprovalGateGrant:
    """Issue a strict proof for one exact extension-control mutation."""

    payload = _native_or_unconfigured(
        "require_extension_control",
        guard_home,
        params={"action": action, "subject": subject, "session_nonce": session_nonce},
        approval_gate_input=approval_gate_input,
        now=now,
    )
    if payload is None:
        raise ApprovalGateError(
            "approval_gate_configuration_required",
            "Configure the approval gate before changing extension controls.",
            status=423,
        )
    return _issued(payload)


def consume_extension_control_grant(
    guard_home: Path,
    approval_gate_grant: ApprovalGateGrant,
    *,
    action: str,
    subject: str,
    session_nonce: str,
    now: str | None = None,
) -> None:
    """Atomically validate and consume one extension-control approval grant."""

    _native(
        "consume_extension_control_grant",
        guard_home,
        params={"action": action, "subject": subject, "session_nonce": session_nonce},
        approval_gate_grant=approval_gate_grant,
        now=now,
    )


def require_local_cli_trust(
    guard_home: Path,
    *,
    approval_gate_input: ApprovalGateInput | None,
    action: str,
    subject: str,
    session_nonce: str,
    now: str | None = None,
) -> ApprovalGateGrant:
    """Issue a strict proof for one exact local CLI allow-list mutation."""

    payload = _native_or_unconfigured(
        "require_local_cli_trust",
        guard_home,
        params={"action": action, "subject": subject, "session_nonce": session_nonce},
        approval_gate_input=approval_gate_input,
        now=now,
    )
    if payload is None:
        raise ApprovalGateError(
            "approval_gate_configuration_required",
            "Configure the approval gate before changing CLI allow-list settings.",
            status=423,
        )
    return _issued(payload)


def consume_local_cli_trust_grant(
    guard_home: Path,
    approval_gate_grant: ApprovalGateGrant,
    *,
    action: str,
    subject: str,
    session_nonce: str,
    now: str | None = None,
) -> None:
    """Atomically validate and consume one local CLI trust approval grant."""

    _native(
        "consume_local_cli_trust_grant",
        guard_home,
        params={"action": action, "subject": subject, "session_nonce": session_nonce},
        approval_gate_grant=approval_gate_grant,
        now=now,
    )


def _issued(payload: dict[str, object]) -> ApprovalGateGrant:
    grant = grant_from_wire(payload.get("grant"))
    if grant is None:
        raise _unavailable()
    return grant


def validate_grant(
    guard_home: Path,
    approval_gate_grant: ApprovalGateGrant | None,
    *,
    purpose: ApprovalGatePurpose | None,
    strict: bool,
    action: str | None = None,
    scope: str | None = None,
    subject: str | None = None,
    session_nonce: str | None = None,
    now: str | None = None,
) -> None:
    payload = _native_or_unconfigured(
        "validate_grant",
        guard_home,
        params={"action": action, "scope": scope, "subject": subject, "session_nonce": session_nonce},
        approval_gate_grant=approval_gate_grant,
        strict=strict,
        purpose=purpose,
        now=now,
    )
    if payload is None:
        raise ApprovalGateError("approval_gate_required", "Approval password is required.")
