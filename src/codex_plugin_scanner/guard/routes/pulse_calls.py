"""Yanez Pulse setup routes, run behind ``desktop library-call``.

``POST /v1/approval-gate/pulse/{enroll,confirm,poll,disable,recover}``. The
native daemon owns the route, the header-token check and the body read; each
call returns the one reply its route writes:
``{"status": int, "body": {...}, "no_store": bool}``.

Every call only reaches the resident through ``approval_gate``. The agent key
and recovery code arrive in the request body from the dashboard, go straight
to the resident, and are never logged or echoed. The one exception is the
recovery code that ``confirm`` returns once.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any

from ..store import GuardStore
from .settings_calls import settings_response_payload

# The only Pulse routes. The daemon checks the header token for exactly these
# paths, so dispatch must not reach a handler through any other path.
PULSE_ACTIONS = frozenset({"enroll", "confirm", "poll", "disable", "recover"})
PULSE_ROUTE_PATHS = frozenset(f"/v1/approval-gate/pulse/{action}" for action in PULSE_ACTIONS)


def _reply(body: Mapping[str, object], status: int = 200) -> dict[str, object]:
    return {"status": status, "body": dict(body), "no_store": True}


def _text(payload: Mapping[str, object], key: str) -> str | None:
    value = payload.get(key)
    return value.strip() if isinstance(value, str) and value.strip() else None


def _settings_with_gate(guard_home: Path, gate: dict[str, object]) -> dict[str, object]:
    from ..config import editable_guard_settings, load_guard_config

    settings = editable_guard_settings(load_guard_config(guard_home))
    settings["approval_gate"] = gate
    return settings_response_payload(guard_home, settings)


def _confirmed_reply(guard_home: Path, confirmed: dict[str, object]) -> dict[str, object]:
    """Answer a confirmed setup. Pulse is on now and the recovery code exists only here.

    If the full settings response cannot be built or encoded, the gate state
    the resident returned and the recovery code are sent instead, so the user
    never loses the code.
    """
    recovery_code = confirmed.pop("recovery_code", None)
    try:
        response = _settings_with_gate(guard_home, dict(confirmed))
        response["pulse_recovery_code"] = recovery_code
        json.dumps(response)  # the reply's encoding; a failure falls back below
    except Exception:  # the code must reach the user whatever failed
        response = {"approval_gate": confirmed, "pulse_recovery_code": recovery_code}
    return _reply(response)


def _run(guard_home: Path, action: str, payload: dict[str, object]) -> dict[str, object]:
    from ..approval_gate import (
        ApprovalGateError,
        begin_pulse_enrollment,
        confirm_pulse_enrollment,
        disable_pulse,
        poll_pulse_approval,
        recover_pulse,
        require_high_risk,
    )
    from ..approval_gate import input_from_mapping as gate_input_from_mapping
    from ..approval_gate import public_config as gate_public_config

    if action == "enroll":
        gate_input = gate_input_from_mapping(payload)
        if gate_input is None:
            raise ApprovalGateError("approval_gate_required", "Approval password is required.")
        if payload.get("step") == "authorize":
            # Step 1 of the dashboard setup: check the password (and code) only.
            return _reply(begin_pulse_enrollment(guard_home, approval_gate_input=gate_input, authorize_only=True))
        enrollment = begin_pulse_enrollment(
            guard_home,
            approval_gate_input=replace(gate_input, pulse_agent_key=_text(payload, "pulse_agent_key")),
            # Passed as sent: the resident accepts only "medium" or "high".
            min_tier=payload.get("min_tier"),
        )
        response = _settings_with_gate(guard_home, gate_public_config(guard_home).to_dict())
        response["pulse_enrollment"] = enrollment
        return _reply(response)
    if action == "poll":
        request_id = _text(payload, "request_id")
        if request_id is None:
            raise ApprovalGateError("approval_gate_pulse_invalid_request", "A Pulse request id is required.")
        return _reply({"status": poll_pulse_approval(guard_home, request_id)})
    if action == "confirm":
        cooldown = payload.get("cooldown_seconds") or 0
        if not isinstance(cooldown, (int, float, str)):
            raise TypeError("cooldown_seconds")
        confirmed = confirm_pulse_enrollment(
            guard_home,
            request_id=_text(payload, "request_id") or "",
            cooldown_seconds=int(cooldown),
        )
        return _confirmed_reply(guard_home, confirmed)
    if action == "disable":
        # Same path as every other strict settings write: with no Pulse
        # request id yet, this answers 202 with one to approve and poll.
        gate_input = gate_input_from_mapping({**payload, "approval_gate_pulse": True})
        grant = require_high_risk(
            guard_home,
            purpose="settings_write",
            approval_gate_input=gate_input,
            settings_change={"kind": "pulse_disable"},
        )
        return _reply(_settings_with_gate(guard_home, disable_pulse(guard_home, approval_gate_grant=grant).to_dict()))
    # recover
    gate_input = gate_input_from_mapping(payload)
    if gate_input is None:
        raise ApprovalGateError("approval_gate_required", "Approval password is required.")
    gate = recover_pulse(
        guard_home,
        approval_gate_input=replace(gate_input, pulse_recovery_code=_text(payload, "pulse_recovery_code")),
    )
    return _reply(_settings_with_gate(guard_home, gate.to_dict()))


def approval_gate_pulse(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """``POST /v1/approval-gate/pulse/<action>``."""

    from ..approval_gate import ApprovalGateError
    from ..library_calls import LibraryCallError

    action = args.get("action")
    payload = args.get("payload")
    if action not in PULSE_ACTIONS or not isinstance(payload, dict):
        raise LibraryCallError("invalid_arguments")
    try:
        return _run(store.guard_home, str(action), payload)
    except ApprovalGateError as error:
        return _reply(error.to_payload(), error.status)
    except (TypeError, ValueError, OverflowError):
        error = ApprovalGateError("approval_gate_pulse_invalid_request", "The Pulse request is invalid.", status=400)
        return _reply(error.to_payload(), error.status)


PULSE_CALLS = {"route.approval_gate_pulse": approval_gate_pulse}
