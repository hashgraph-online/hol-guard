"""Approval-gate setup and update-channel writes, run behind ``desktop library-call``.

Each call returns the one reply its route writes:
``{"status": int, "body": {...}, "no_store": bool}``. The native daemon owns
the route, the caller check and the body read.
"""

from __future__ import annotations

from collections.abc import Mapping
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..store import GuardStore

_PRESENTATION_ONLY_KEYS = frozenset(
    {
        "presentation_mode",
        "presentation_mode_explicit",
        "presentation_schema_version",
        "presentation_revision",
    }
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _reply(body: Mapping[str, object], status: int = 200, *, no_store: bool = False) -> dict[str, object]:
    return {"status": status, "body": dict(body), "no_store": no_store}


def _payload(args: Mapping[str, Any]) -> dict[str, object]:
    payload = args.get("payload")
    if not isinstance(payload, dict):
        from ..library_calls import LibraryCallError

        raise LibraryCallError("invalid_arguments")
    return payload


def settings_response_payload(guard_home: Path, settings: dict[str, object]) -> dict[str, object]:
    from ..protection_capabilities import protection_capability_payloads

    return {
        "guard_home": str(guard_home),
        "config_path": str(guard_home / "config.toml"),
        "settings": settings,
        "protection_capabilities": protection_capability_payloads(),
    }


def _hand_settings_to_cigar(guard_home: Path) -> None:
    """Give saved CIGAR settings to the native service right away.

    Prompt hooks read the native copy, which otherwise refreshes only on the
    next context call. Without this, turning project context back on leaves
    every prompt without context until something asks for CIGAR's status.
    """

    from .. import native_context_assistance
    from ..native_context_assistance import ContextAssistanceError

    with suppress(ContextAssistanceError):
        native_context_assistance.control("status", guard_home=guard_home)


def _requeue_privacy_projection(store: GuardStore, level: str) -> None:
    from ..runtime.runner import _requeue_cloud_review_privacy_projection

    _requeue_cloud_review_privacy_projection(store, level=level, changed_at=_now())  # type: ignore[arg-type]


def _apply_settings(store: GuardStore, payload: dict[str, object], *, missing_error: str) -> dict[str, object]:
    from ..approval_gate import ApprovalGateError, require_high_risk
    from ..approval_gate import input_from_mapping as gate_input_from_mapping
    from ..approval_gate import update_settings as update_gate_settings
    from ..approval_gate import validate_settings_update as validate_gate_settings
    from ..config import editable_guard_settings, load_guard_config, update_guard_settings
    from ..package_firewall_entitlement import package_firewall_entitlement_or_denied

    settings = payload.get("settings")
    if not isinstance(settings, dict):
        return _reply({"error": missing_error}, 400)
    guard_home = store.guard_home
    previous_redaction_level = load_guard_config(guard_home).receipt_redaction_level
    gate_payload = settings.get("approval_gate")
    gate_input = gate_input_from_mapping({"approval_gate": gate_payload}) if isinstance(gate_payload, dict) else None
    if payload.get("approval_password") or payload.get("approval_totp_code"):
        proof_input = gate_input_from_mapping(payload)
        if proof_input is not None:
            gate_input = proof_input
    presentation_only = gate_payload is None and bool(settings) and set(settings).issubset(_PRESENTATION_ONLY_KEYS)
    config_settings = {key: value for key, value in settings.items() if key != "approval_gate"}
    try:
        grant = (
            None
            if presentation_only
            else require_high_risk(guard_home, purpose="settings_write", approval_gate_input=gate_input)
        )
        if isinstance(gate_payload, dict):
            validate_gate_settings(guard_home, gate_payload, approval_gate_grant=grant)
        entitlement = package_firewall_entitlement_or_denied(store)
        config = update_guard_settings(
            guard_home,
            config_settings,
            approval_gate_grant=grant,
            cloud_sync_entitled=bool(entitlement.get("allowed")),
            skip_approval_gate=presentation_only,
        )
        if isinstance(gate_payload, dict):
            update_gate_settings(guard_home, gate_payload, approval_gate_grant=grant)
            config = load_guard_config(guard_home)
        if config.receipt_redaction_level != previous_redaction_level:
            _requeue_privacy_projection(store, config.receipt_redaction_level)
    except ApprovalGateError as error:
        return _reply(error.to_payload(), error.status)
    except ValueError as error:
        return _reply({"error": "invalid_settings", "message": str(error)}, 400)
    if "context_assistance" in config_settings:
        _hand_settings_to_cigar(guard_home)
    return _reply(settings_response_payload(guard_home, editable_guard_settings(config)))


def _approval_gate_setup_is_allowed(payload: object) -> bool:
    if not isinstance(payload, dict) or set(payload) != {"settings"}:
        return False
    settings = payload.get("settings")
    if not isinstance(settings, dict) or set(settings) != {"approval_gate"}:
        return False
    gate_payload = settings.get("approval_gate")
    return (
        isinstance(gate_payload, dict)
        and set(gate_payload) == {"enabled", "new_password", "confirm_password"}
        and gate_payload.get("enabled") is True
    )


def approval_gate_setup(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """``POST /v1/protection/repair/approval-gate/setup``: first-time gate setup only."""

    from ..approval_gate import public_config

    payload = _payload(args)
    if not _approval_gate_setup_is_allowed(payload):
        return _reply({"error": "invalid_settings"}, 400)
    gate_config = public_config(store.guard_home)
    if gate_config.configured or gate_config.enabled:
        return _reply({"error": "approval_gate_setup_unavailable"}, 409)
    return _apply_settings(store, payload, missing_error="invalid_settings")


def update_channel(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """``POST /v1/update/channel``; the daemon forbids revalidation of the reply."""

    from ..approval_gate import ApprovalGateError, require_high_risk
    from ..approval_gate import input_from_mapping as gate_input_from_mapping
    from ..cli.update_commands import build_guard_update_status_payload
    from ..config import update_guard_update_channel

    payload = _payload(args)
    guard_home = store.guard_home
    try:
        grant = require_high_risk(
            guard_home,
            purpose="settings_write",
            approval_gate_input=gate_input_from_mapping(payload),
        )
        update_guard_update_channel(guard_home, payload.get("update_channel"), approval_gate_grant=grant)
    except ApprovalGateError as error:
        return _reply(error.to_payload(), error.status)
    except ValueError as error:
        return _reply({"error": "invalid_update_channel", "message": str(error)}, 400)
    return _reply(build_guard_update_status_payload(guard_home=guard_home), no_store=True)


SETTINGS_CALLS = {
    "route.approval_gate_setup": approval_gate_setup,
    "route.update_channel": update_channel,
}
