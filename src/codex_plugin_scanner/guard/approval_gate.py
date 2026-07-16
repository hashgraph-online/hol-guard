"""Local approval password gate enforcement."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .approval_gate_state import (
    APPROVAL_GATE_ALLOWED_COOLDOWNS,
    APPROVAL_GATE_STATE_FILE,
    ApprovalGatePublicConfig,
)
from .approval_gate_state import (
    cooldown_active as _cooldown_active,
)
from .approval_gate_state import (
    default_state as _default_state,
)
from .approval_gate_state import (
    enabled as _enabled,
)
from .approval_gate_state import (
    epoch as _epoch,
)
from .approval_gate_state import (
    is_future as _is_future,
)
from .approval_gate_state import (
    iso_from_epoch as _iso_from_epoch,
)
from .approval_gate_state import (
    optional_bool as _optional_bool,
)
from .approval_gate_state import (
    optional_string as _optional_string,
)
from .approval_gate_state import (
    prune_grants as _prune_grants,
)
from .approval_gate_state import (
    record_failed_attempt as _record_failed_attempt,
)
from .approval_gate_state import (
    verifier as _verifier,
)
from .approval_gate_state import (
    verify_password as _verify_password,
)
from .approval_gate_state import (
    write_state as _write_state,
)
from .models import PolicyDecision
from .totp import TotpSecretStore, build_otpauth_uri, generate_totp_secret, verify_totp_code

APPROVAL_GATE_MIN_PASSWORD_LENGTH = 8
APPROVAL_GATE_GRANT_TTL_SECONDS = 30
APPROVAL_GATE_HASH_ITERATIONS = 310_000
APPROVAL_GATE_TOTP_SKEW_STEPS = 1
APPROVAL_GATE_TOTP_PENDING_TTL_SECONDS = 600

ApprovalGatePurpose = Literal[
    "approval_decision",
    "policy_write",
    "policy_clear",
    "policy_import",
    "policy_export_provenance",
    "queue_clear",
    "settings_write",
    "native_policy",
    "tool_call_policy",
    "headless_policy_sync",
    "supply_chain_firewall",
]

_ACTIVE_GRANTS: dict[str, dict[str, object]] = {}


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


@dataclass(frozen=True, slots=True)
class ApprovalGateGrant:
    """Short-lived proof produced only after the local gate is satisfied."""

    grant_id: str
    purpose: ApprovalGatePurpose
    issued_at: str
    strict: bool
    used_cooldown: bool
    cooldown_expires_at: str | None
    totp_verified: bool


def input_from_mapping(payload: object) -> ApprovalGateInput | None:
    """Build gate input from daemon or dashboard payload without retaining extras."""

    if not isinstance(payload, dict):
        return None
    gate_payload = payload.get("approval_gate")
    gate_mapping = gate_payload if isinstance(gate_payload, dict) else {}
    password = _optional_string(payload.get("approval_password")) or _optional_string(gate_mapping.get("password"))
    current_password = _optional_string(gate_mapping.get("current_password"))
    totp_code = _optional_string(payload.get("approval_totp_code")) or _optional_string(gate_mapping.get("totp_code"))
    return ApprovalGateInput(
        password=current_password or password,
        new_password=_optional_string(gate_mapping.get("new_password")),
        confirm_password=_optional_string(gate_mapping.get("confirm_password")),
        totp_code=totp_code,
        use_cooldown=_optional_bool(payload.get("approval_gate_use_cooldown"), gate_mapping.get("use_cooldown")),
        revoke_cooldown=_optional_bool(gate_mapping.get("revoke_cooldown"), False) is True,
    )


def public_config(guard_home: Path, *, now: str | None = None) -> ApprovalGatePublicConfig:
    state = _load_state(guard_home)
    now_epoch = _epoch(now)
    cooldown_expires_at = _optional_string(state.get("cooldown_expires_at"))
    locked_until = _optional_string(state.get("locked_until"))
    return ApprovalGatePublicConfig(
        enabled=_enabled(state),
        configured=_verifier(state) is not None,
        cooldown_seconds=_cooldown_seconds(state),
        cooldown_active=_is_future(cooldown_expires_at, now_epoch),
        cooldown_expires_at=cooldown_expires_at if _is_future(cooldown_expires_at, now_epoch) else None,
        locked_until=locked_until if _is_future(locked_until, now_epoch) else None,
        fail_closed=bool(state.get("fail_closed") is True),
        strict_all_decisions=bool(state.get("strict_all_decisions") is True),
        totp_enabled=bool(state.get("totp_enabled") is True),
        totp_pending=_has_pending_totp(state, now_epoch),
    )


def update_settings(
    guard_home: Path,
    payload: object,
    *,
    approval_gate_grant: ApprovalGateGrant | None = None,
    now: str | None = None,
) -> ApprovalGatePublicConfig:
    next_state = _next_settings_state(
        guard_home,
        payload,
        approval_gate_grant=approval_gate_grant,
        now=now,
    )
    if next_state is not None:
        _write_state(guard_home, next_state, now=now)
    return public_config(guard_home, now=now)


def validate_settings_update(
    guard_home: Path,
    payload: object,
    *,
    approval_gate_grant: ApprovalGateGrant | None = None,
    now: str | None = None,
) -> None:
    _next_settings_state(
        guard_home,
        payload,
        approval_gate_grant=approval_gate_grant,
        now=now,
    )


def _next_settings_state(
    guard_home: Path,
    payload: object,
    *,
    approval_gate_grant: ApprovalGateGrant | None,
    now: str | None,
) -> dict[str, object] | None:
    if not isinstance(payload, dict):
        return None
    state = _load_state(guard_home)
    gate_was_enabled = _enabled(state)
    gate_input = input_from_mapping({"approval_gate": payload}) or ApprovalGateInput()
    requested_enabled = _optional_bool(payload.get("enabled"), state.get("enabled"))
    next_state = dict(state)
    if gate_input.revoke_cooldown:
        next_state.pop("cooldown_expires_at", None)
    if gate_was_enabled:
        validate_grant(
            guard_home,
            approval_gate_grant,
            purpose="settings_write",
            strict=True,
            now=now,
        )
    if requested_enabled is True and not gate_was_enabled:
        if gate_input.new_password is None:
            raise ApprovalGateError("approval_gate_password_required", "Approval gate password is required.")
        _require_password_confirmation(gate_input.new_password, gate_input.confirm_password)
        next_state["verifier"] = create_verifier(gate_input.new_password)
    elif gate_was_enabled and gate_input.new_password:
        _require_password_confirmation(gate_input.new_password, gate_input.confirm_password)
        next_state["verifier"] = create_verifier(gate_input.new_password)
    if requested_enabled is not None:
        next_state["enabled"] = requested_enabled
    if "cooldown_seconds" in payload:
        next_state["cooldown_seconds"] = _coerce_cooldown_seconds(payload.get("cooldown_seconds"))
    if "strict_all_decisions" in payload:
        next_state["strict_all_decisions"] = bool(payload.get("strict_all_decisions") is True)
    if next_state.get("enabled") is True and _verifier(next_state) is None:
        raise ApprovalGateError("approval_gate_password_required", "Approval gate password is required.")
    return next_state


def revoke_cooldown(guard_home: Path, *, now: str | None = None) -> ApprovalGatePublicConfig:
    state = _load_state(guard_home)
    state.pop("cooldown_expires_at", None)
    _write_state(guard_home, state, now=now)
    return public_config(guard_home, now=now)


def unlock_cooldown(
    guard_home: Path,
    *,
    duration_seconds: int,
    approval_gate_input: ApprovalGateInput | None = None,
    now: str | None = None,
) -> ApprovalGatePublicConfig:
    state = _load_state(guard_home)
    if not _enabled(state):
        raise ApprovalGateError("approval_gate_required", "Approval password is required.")
    if _verifier(state) is None:
        raise ApprovalGateError(
            "approval_gate_recovery_required",
            "Approval gate is enabled but no verifier is configured.",
            status=423,
        )
    if _totp_enabled(state):
        raise ApprovalGateError("approval_gate_totp_required", "Cooldown unlock is unavailable while TOTP is enabled.")
    seconds = _coerce_cooldown_seconds(duration_seconds)
    if seconds == 0:
        raise ApprovalGateError("approval_gate_invalid_cooldown", "Cooldown unlock requires 900 or 3600 seconds.")
    now_epoch = _epoch(now)
    locked_until = _optional_string(state.get("locked_until"))
    if _is_future(locked_until, now_epoch):
        raise ApprovalGateError("approval_gate_locked", "Approval gate is temporarily locked.", status=423)
    gate_input = approval_gate_input or ApprovalGateInput()
    if gate_input.password is None:
        raise ApprovalGateError("approval_gate_required", "Approval password is required.")
    if not _verify_password(gate_input.password, _verifier(state)):
        _record_failed_attempt(guard_home, state, now=now)
        raise ApprovalGateError("approval_gate_invalid_password", "Approval password is invalid.")
    state["failed_attempts"] = 0
    state.pop("locked_until", None)
    state["cooldown_expires_at"] = _iso_from_epoch(now_epoch + seconds)
    _write_state(guard_home, state, now=now)
    return public_config(guard_home, now=now)


def begin_totp_enrollment(
    guard_home: Path,
    *,
    approval_gate_input: ApprovalGateInput | None = None,
    device_label: str = "local-device",
    now: str | None = None,
) -> dict[str, object]:
    state = _load_state(guard_home)
    if not _enabled(state):
        raise ApprovalGateError("approval_gate_required", "Approval password is required.")
    if _totp_enabled(state):
        raise ApprovalGateError("approval_gate_totp_enabled", "TOTP is already enabled.")
    _verify_or_raise(
        guard_home,
        state,
        purpose="settings_write",
        approval_gate_input=approval_gate_input,
        strict=True,
        now=now,
    )
    store = TotpSecretStore(guard_home)
    pending_secret_id = str(state.get("totp_pending_secret_id") or "")
    if pending_secret_id:
        store.delete_secret(pending_secret_id)
    secret = generate_totp_secret()
    next_secret_id = secrets.token_urlsafe(12)
    store.set_secret(next_secret_id, secret)
    now_epoch = _epoch(now)
    state["totp_pending_secret_id"] = next_secret_id
    state["totp_pending_expires_at"] = _iso_from_epoch(now_epoch + APPROVAL_GATE_TOTP_PENDING_TTL_SECONDS)
    state["totp_enabled"] = bool(state.get("totp_enabled") is True)
    state.pop("cooldown_expires_at", None)
    _write_state(guard_home, state, now=now)
    return {
        "pending": True,
        "manual_key": secret,
        "expires_at": state["totp_pending_expires_at"],
        "otpauth_uri": build_otpauth_uri(secret=secret, device_label=device_label),
    }


def confirm_totp_enrollment(
    guard_home: Path,
    *,
    approval_gate_input: ApprovalGateInput | None = None,
    now: str | None = None,
) -> ApprovalGatePublicConfig:
    state = _load_state(guard_home)
    if not _enabled(state):
        raise ApprovalGateError("approval_gate_required", "Approval password is required.")
    _verify_or_raise(
        guard_home,
        state,
        purpose="settings_write",
        approval_gate_input=approval_gate_input,
        strict=True,
        now=now,
    )
    pending_secret_id = _optional_string(state.get("totp_pending_secret_id"))
    pending_expires_at = _optional_string(state.get("totp_pending_expires_at"))
    now_epoch = _epoch(now)
    if pending_secret_id is None or not _is_future(pending_expires_at, now_epoch):
        raise ApprovalGateError("approval_gate_totp_pending_required", "No pending TOTP enrollment is available.")
    gate_input = approval_gate_input or ApprovalGateInput()
    if gate_input.totp_code is None:
        raise ApprovalGateError("approval_gate_totp_required", "TOTP code is required.")
    store = TotpSecretStore(guard_home)
    pending_secret = store.get_secret(pending_secret_id)
    if pending_secret is None:
        raise ApprovalGateError(
            "approval_gate_recovery_required",
            "Approval gate TOTP secret is unavailable.",
            status=423,
        )
    accepted_counter = verify_totp_code(
        secret=pending_secret,
        code=gate_input.totp_code,
        now_epoch=now_epoch,
        skew_steps=APPROVAL_GATE_TOTP_SKEW_STEPS,
        last_accepted_counter=None,
    )
    if accepted_counter is None:
        _record_failed_attempt(guard_home, state, now=now)
        raise ApprovalGateError(
            "approval_gate_totp_invalid",
            "That authenticator code is wrong. Open your authenticator app and enter the current six-digit code.",
        )
    active_secret_id = _optional_string(state.get("totp_secret_id"))
    if active_secret_id is not None and active_secret_id != pending_secret_id:
        store.delete_secret(active_secret_id)
    state["totp_secret_id"] = pending_secret_id
    state["totp_enabled"] = True
    state["totp_last_counter"] = accepted_counter
    state["failed_attempts"] = 0
    state.pop("locked_until", None)
    state.pop("totp_pending_secret_id", None)
    state.pop("totp_pending_expires_at", None)
    state.pop("cooldown_expires_at", None)
    _write_state(guard_home, state, now=now)
    return public_config(guard_home, now=now)


def disable_totp(
    guard_home: Path,
    *,
    approval_gate_input: ApprovalGateInput | None = None,
    now: str | None = None,
) -> ApprovalGatePublicConfig:
    state = _load_state(guard_home)
    if not _enabled(state):
        raise ApprovalGateError("approval_gate_required", "Approval password is required.")
    now_epoch = _epoch(now)
    locked_until = _optional_string(state.get("locked_until"))
    if _is_future(locked_until, now_epoch):
        raise ApprovalGateError("approval_gate_locked", "Approval gate is temporarily locked.", status=423)
    gate_input = approval_gate_input or ApprovalGateInput()
    secret_id = _optional_string(state.get("totp_secret_id"))
    if secret_id is None:
        if _totp_enabled(state):
            raise ApprovalGateError(
                "approval_gate_recovery_required",
                "Approval gate TOTP secret is unavailable.",
                status=423,
            )
        state["totp_enabled"] = False
        _write_state(guard_home, state, now=now)
        return public_config(guard_home, now=now)
    if gate_input.totp_code is None:
        raise ApprovalGateError("approval_gate_totp_required", "TOTP code is required.")
    secret = TotpSecretStore(guard_home).get_secret(secret_id)
    if secret is None:
        raise ApprovalGateError(
            "approval_gate_recovery_required",
            "Approval gate TOTP secret is unavailable.",
            status=423,
        )
    accepted_counter = verify_totp_code(
        secret=secret,
        code=gate_input.totp_code,
        now_epoch=now_epoch,
        skew_steps=APPROVAL_GATE_TOTP_SKEW_STEPS,
        last_accepted_counter=_optional_int(state.get("totp_last_counter")),
    )
    if accepted_counter is None:
        _record_failed_attempt(guard_home, state, now=now)
        raise ApprovalGateError(
            "approval_gate_totp_invalid",
            "That authenticator code is wrong. Open your authenticator app and enter the current six-digit code.",
        )
    state["failed_attempts"] = 0
    state.pop("locked_until", None)
    state["totp_enabled"] = False
    state.pop("totp_secret_id", None)
    state.pop("totp_last_counter", None)
    pending_secret_id = _optional_string(state.get("totp_pending_secret_id"))
    state.pop("totp_pending_secret_id", None)
    state.pop("totp_pending_expires_at", None)
    store = TotpSecretStore(guard_home)
    store.delete_secret(secret_id)
    if pending_secret_id is not None:
        store.delete_secret(pending_secret_id)
    _write_state(guard_home, state, now=now)
    return public_config(guard_home, now=now)


def require_approval_decision(
    guard_home: Path,
    *,
    action: str,
    scope: str,
    approval_gate_input: ApprovalGateInput | None = None,
    approval_gate_grant: ApprovalGateGrant | None = None,
    now: str | None = None,
) -> ApprovalGateGrant | None:
    state = _load_state(guard_home)
    if not _requires_decision_gate(state, action=action, scope=scope):
        return None
    strict = _is_strict_approval_action(action=action, scope=scope)
    if approval_gate_grant is not None:
        validate_grant(
            guard_home,
            approval_gate_grant,
            purpose="approval_decision",
            strict=strict,
            now=now,
        )
        return approval_gate_grant
    return _verify_or_raise(
        guard_home,
        state,
        purpose="approval_decision",
        approval_gate_input=approval_gate_input,
        strict=strict,
        now=now,
    )


def require_policy_write(
    guard_home: Path,
    *,
    decision: PolicyDecision,
    approval_gate_grant: ApprovalGateGrant | None = None,
    now: str | None = None,
) -> None:
    state = _load_state(guard_home)
    if not _requires_decision_gate(state, action=decision.action, scope=decision.scope):
        return
    validate_grant(
        guard_home,
        approval_gate_grant,
        purpose=None,
        strict=_is_strict_approval_action(action=decision.action, scope=decision.scope),
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
    state = _load_state(guard_home)
    if not _requires_decision_gate(state, action=resolution_action, scope=resolution_scope):
        return
    validate_grant(
        guard_home,
        approval_gate_grant,
        purpose=None,
        strict=_is_strict_approval_action(action=resolution_action, scope=resolution_scope),
        now=now,
    )


def require_policy_clear(
    guard_home: Path,
    *,
    approval_gate_grant: ApprovalGateGrant | None = None,
    now: str | None = None,
) -> None:
    if not _enabled(_load_state(guard_home)):
        return
    validate_grant(guard_home, approval_gate_grant, purpose="policy_clear", strict=True, now=now)


def require_settings_write(
    guard_home: Path,
    *,
    approval_gate_grant: ApprovalGateGrant | None = None,
    now: str | None = None,
) -> None:
    if not _enabled(_load_state(guard_home)):
        return
    validate_grant(guard_home, approval_gate_grant, purpose="settings_write", strict=True, now=now)


def require_high_risk(
    guard_home: Path,
    *,
    purpose: ApprovalGatePurpose,
    approval_gate_input: ApprovalGateInput | None = None,
    approval_gate_grant: ApprovalGateGrant | None = None,
    now: str | None = None,
) -> ApprovalGateGrant | None:
    state = _load_state(guard_home)
    if not _enabled(state):
        return None
    if approval_gate_grant is not None:
        validate_grant(guard_home, approval_gate_grant, purpose=purpose, strict=True, now=now)
        return approval_gate_grant
    return _verify_or_raise(
        guard_home,
        state,
        purpose=purpose,
        approval_gate_input=approval_gate_input,
        strict=True,
        now=now,
    )


def create_verifier(password: str) -> dict[str, object]:
    if len(password) < APPROVAL_GATE_MIN_PASSWORD_LENGTH:
        raise ApprovalGateError("approval_gate_weak_password", "Approval gate password is too weak.")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, APPROVAL_GATE_HASH_ITERATIONS)
    return {
        "algorithm": "pbkdf2_sha256",
        "iterations": APPROVAL_GATE_HASH_ITERATIONS,
        "salt": base64.b64encode(salt).decode("ascii"),
        "hash": base64.b64encode(digest).decode("ascii"),
    }


def validate_grant(
    guard_home: Path,
    approval_gate_grant: ApprovalGateGrant | None,
    *,
    purpose: ApprovalGatePurpose | None,
    strict: bool,
    now: str | None = None,
) -> None:
    state = _load_state(guard_home)
    if approval_gate_grant is None:
        if _totp_enabled(state):
            raise ApprovalGateError("approval_gate_totp_required", "TOTP code is required.")
        raise ApprovalGateError("approval_gate_required", "Approval password is required.")
    metadata = _ACTIVE_GRANTS.get(approval_gate_grant.grant_id)
    if metadata is None:
        raise ApprovalGateError("approval_gate_required", "Approval password is required.")
    now_epoch = _epoch(now)
    if metadata.get("guard_home") != str(guard_home):
        raise ApprovalGateError("approval_gate_required", "Approval password is required.")
    expires_epoch = _optional_float(metadata.get("expires_epoch")) or 0.0
    if expires_epoch <= now_epoch:
        _ACTIVE_GRANTS.pop(approval_gate_grant.grant_id, None)
        raise ApprovalGateError("approval_gate_required", "Approval password is required.")
    if purpose is not None and approval_gate_grant.purpose != purpose:
        raise ApprovalGateError("approval_gate_required", "Approval password is required.")
    if strict and not approval_gate_grant.strict:
        raise ApprovalGateError("approval_gate_required", "Approval password is required.")
    if _totp_enabled(state):
        _validate_totp_state_or_raise(guard_home, state)
        if not approval_gate_grant.totp_verified:
            raise ApprovalGateError("approval_gate_totp_required", "TOTP code is required.")


def audit_payload(
    *,
    purpose: ApprovalGatePurpose,
    grant: ApprovalGateGrant | None,
    action: str | None = None,
    scope: str | None = None,
) -> dict[str, object]:
    return {
        "approval_gate": {
            "purpose": purpose,
            "satisfied": grant is not None,
            "used_cooldown": bool(grant.used_cooldown) if grant is not None else False,
            "cooldown_expires_at": grant.cooldown_expires_at if grant is not None else None,
            "action": action,
            "scope": scope,
        }
    }


def _verify_or_raise(
    guard_home: Path,
    state: dict[str, object],
    *,
    purpose: ApprovalGatePurpose,
    approval_gate_input: ApprovalGateInput | None,
    strict: bool,
    now: str | None,
) -> ApprovalGateGrant:
    now_epoch = _epoch(now)
    locked_until = _optional_string(state.get("locked_until"))
    if _is_future(locked_until, now_epoch):
        raise ApprovalGateError("approval_gate_locked", "Approval gate is temporarily locked.", status=423)
    gate_input = approval_gate_input or ApprovalGateInput()
    if _totp_enabled(state):
        if gate_input.totp_code is None:
            raise ApprovalGateError("approval_gate_totp_required", "TOTP code is required.")
        accepted_counter = _verify_totp_or_raise(
            guard_home,
            state,
            code=gate_input.totp_code,
            now_epoch=now_epoch,
        )
        state["totp_last_counter"] = accepted_counter
        state["failed_attempts"] = 0
        state.pop("locked_until", None)
        state.pop("cooldown_expires_at", None)
        _write_state(guard_home, state, now=now)
        return _register_grant(
            guard_home,
            purpose=purpose,
            strict=strict,
            used_cooldown=False,
            cooldown_expires_at=None,
            totp_verified=True,
            now=now,
        )
    if _verifier(state) is None:
        raise ApprovalGateError(
            "approval_gate_recovery_required",
            "Approval gate is enabled but no verifier is configured.",
            status=423,
        )
    if not strict and _cooldown_active(state, now_epoch):
        return _register_grant(
            guard_home,
            purpose=purpose,
            strict=False,
            used_cooldown=True,
            cooldown_expires_at=_optional_string(state.get("cooldown_expires_at")),
            totp_verified=False,
            now=now,
        )
    if gate_input.password is None:
        raise ApprovalGateError("approval_gate_required", "Approval password is required.")
    if not _verify_password(gate_input.password, _verifier(state)):
        _record_failed_attempt(guard_home, state, now=now)
        raise ApprovalGateError("approval_gate_invalid_password", "Approval password is invalid.")
    state["failed_attempts"] = 0
    state.pop("locked_until", None)
    cooldown_expires_at: str | None = None
    if not strict and _cooldown_seconds(state) > 0 and gate_input.use_cooldown is not False:
        cooldown_expires_at = _iso_from_epoch(now_epoch + _cooldown_seconds(state))
        state["cooldown_expires_at"] = cooldown_expires_at
    _write_state(guard_home, state, now=now)
    return _register_grant(
        guard_home,
        purpose=purpose,
        strict=strict,
        used_cooldown=False,
        cooldown_expires_at=cooldown_expires_at,
        totp_verified=False,
        now=now,
    )


def _register_grant(
    guard_home: Path,
    *,
    purpose: ApprovalGatePurpose,
    strict: bool,
    used_cooldown: bool,
    cooldown_expires_at: str | None,
    totp_verified: bool,
    now: str | None,
) -> ApprovalGateGrant:
    now_epoch = _epoch(now)
    grant = ApprovalGateGrant(
        grant_id=secrets.token_urlsafe(24),
        purpose=purpose,
        issued_at=_iso_from_epoch(now_epoch),
        strict=strict,
        used_cooldown=used_cooldown,
        cooldown_expires_at=cooldown_expires_at,
        totp_verified=totp_verified,
    )
    _ACTIVE_GRANTS[grant.grant_id] = {
        "guard_home": str(guard_home),
        "expires_epoch": now_epoch + APPROVAL_GATE_GRANT_TTL_SECONDS,
    }
    _prune_grants(_ACTIVE_GRANTS, now_epoch)
    return grant


def _totp_enabled(state: dict[str, object]) -> bool:
    return bool(state.get("totp_enabled") is True)


def _has_pending_totp(state: dict[str, object], now_epoch: float) -> bool:
    pending_secret_id = _optional_string(state.get("totp_pending_secret_id"))
    pending_expires_at = _optional_string(state.get("totp_pending_expires_at"))
    return pending_secret_id is not None and _is_future(pending_expires_at, now_epoch)


def _verify_totp_or_raise(
    guard_home: Path,
    state: dict[str, object],
    *,
    code: str,
    now_epoch: float,
) -> int:
    secret = _validate_totp_state_or_raise(guard_home, state)
    accepted_counter = verify_totp_code(
        secret=secret,
        code=code,
        now_epoch=now_epoch,
        skew_steps=APPROVAL_GATE_TOTP_SKEW_STEPS,
        last_accepted_counter=_optional_int(state.get("totp_last_counter")),
    )
    if accepted_counter is None:
        _record_failed_attempt(guard_home, state, now=_iso_from_epoch(now_epoch))
        raise ApprovalGateError(
            "approval_gate_totp_invalid",
            "That authenticator code is wrong. Open your authenticator app and enter the current six-digit code.",
        )
    return accepted_counter


def _validate_totp_state_or_raise(guard_home: Path, state: dict[str, object]) -> str:
    secret_id = _optional_string(state.get("totp_secret_id"))
    if secret_id is None:
        raise ApprovalGateError(
            "approval_gate_recovery_required",
            "Approval gate TOTP secret is unavailable.",
            status=423,
        )
    secret = TotpSecretStore(guard_home).get_secret(secret_id)
    if secret is None:
        raise ApprovalGateError(
            "approval_gate_recovery_required",
            "Approval gate TOTP secret is unavailable.",
            status=423,
        )
    return secret


def _requires_decision_gate(state: dict[str, object], *, action: str, scope: str) -> bool:
    if not _enabled(state):
        return False
    if _is_high_risk_action(action=action, scope=scope):
        return True
    return bool(state.get("strict_all_decisions") is True)


def _is_high_risk_action(*, action: str, scope: str) -> bool:
    return action == "allow" or scope == "global"


def _is_strict_approval_action(*, action: str, scope: str) -> bool:
    del action
    return scope == "global"


def _require_password_confirmation(password: str, confirmation: str | None) -> None:
    if confirmation is None or not hmac.compare_digest(password, confirmation):
        raise ApprovalGateError(
            "approval_gate_password_mismatch",
            "Approval gate password confirmation does not match.",
        )


def _load_state(guard_home: Path) -> dict[str, object]:
    path = guard_home / APPROVAL_GATE_STATE_FILE
    if not path.is_file():
        return _default_state()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _fail_closed_state()
    if not isinstance(payload, dict):
        return _fail_closed_state()
    state = _default_state()
    state.update(payload)
    try:
        state["cooldown_seconds"] = _coerce_cooldown_seconds(state.get("cooldown_seconds"))
    except ApprovalGateError:
        state["cooldown_seconds"] = 0
    return state


def _fail_closed_state() -> dict[str, object]:
    state = _default_state()
    state.update({"enabled": True, "fail_closed": True})
    return state


def _cooldown_seconds(state: dict[str, object]) -> int:
    return _coerce_cooldown_seconds(state.get("cooldown_seconds"))


def _coerce_cooldown_seconds(value: object) -> int:
    if isinstance(value, int):
        seconds = value
    elif isinstance(value, str) and value.strip():
        try:
            seconds = int(value)
        except ValueError:
            seconds = 0
    else:
        seconds = 0
    if seconds not in APPROVAL_GATE_ALLOWED_COOLDOWNS:
        raise ApprovalGateError(
            "approval_gate_invalid_cooldown",
            "Approval cooldown must be 0 (every approval), 900 (15 minutes), or 3600 (1 hour) seconds.",
        )
    return seconds


def _optional_int(value: object) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip():
        try:
            return int(value)
        except ValueError:
            return None
    return None


def _optional_float(value: object) -> float | None:
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str) and value.strip():
        try:
            return float(value)
        except ValueError:
            return None
    return None
