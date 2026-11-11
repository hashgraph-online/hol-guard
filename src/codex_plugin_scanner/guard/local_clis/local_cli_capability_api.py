"""Capability choices carried by a local CLI preview or apply request.

The request body may hold ``capabilities: {name: on|off}``. Unknown names or
states are refused, capabilities belong only to a ``surface='cli'``
connector, and turning one on needs the same request to leave the CLI
allowed. The store enforces the same rules again inside the apply
transaction; this module only refuses early with a precise code.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..store_local_cli_capabilities import (
    LocalCliCapabilityError,
    LocalCliCapabilityState,
    capability_choices_digest,
    validated_capability_choices,
)
from .local_cli_api_contract import LocalCliApiError

if TYPE_CHECKING:
    from ..store import GuardStore

_MESSAGES = {
    "invalid_capabilities": "Capabilities must name loopback-network, state-dir-read or state-dir-write as on or off.",
    "capabilities_require_cli_surface": "Only a local CLI connector has capabilities.",
    "capabilities_require_allowed_grant": "Allow this CLI before turning a capability on.",
}


def capability_choices_from_payload(
    store: GuardStore,
    payload: dict[str, object],
    *,
    cli_id: str,
    state: str,
) -> dict[str, LocalCliCapabilityState]:
    """Validated choices, or a ``LocalCliApiError`` naming the refusal."""

    try:
        choices = validated_capability_choices(payload.get("capabilities"))
    except LocalCliCapabilityError as exc:
        raise capability_api_error(exc) from exc
    if not choices:
        return {}
    if store.read_local_cli_surface(cli_id) != "cli":
        raise capability_api_error(LocalCliCapabilityError("capabilities_require_cli_surface"))
    if state == "unset" or ("on" in choices.values() and state != "allowed"):
        raise capability_api_error(LocalCliCapabilityError("capabilities_require_allowed_grant"))
    return choices


def capability_subject_suffix(choices: dict[str, LocalCliCapabilityState]) -> str:
    """Bind the choices into the one-use proof subject; empty when none."""

    return f":capabilities:{capability_choices_digest(choices)}" if choices else ""


def capability_api_error(error: LocalCliCapabilityError) -> LocalCliApiError:
    code = str(error) if str(error) in _MESSAGES else "invalid_capabilities"
    return LocalCliApiError(400, code, _MESSAGES[code])


__all__ = ["capability_api_error", "capability_choices_from_payload", "capability_subject_suffix"]
