"""Yanez Pulse setup routes for the local approval center.

Every route here is POST-only, needs the daemon header token, and only calls
the resident through ``approval_gate``. The agent key and recovery code
arrive in the request body from the dashboard, go straight to the resident,
and are never logged or echoed. The one exception is the recovery code that
``confirm`` returns once.
"""

# pyright: reportAttributeAccessIssue=false, reportUnknownMemberType=false

from __future__ import annotations

import json
from dataclasses import replace

from ..approval_gate import (
    ApprovalGateError,
    begin_pulse_enrollment,
    confirm_pulse_enrollment,
    disable_pulse,
    poll_pulse_approval,
    recover_pulse,
    require_high_risk,
)
from ..approval_gate import input_from_mapping as approval_gate_input_from_mapping
from ..approval_gate import public_config as approval_gate_public_config
from ..config import editable_guard_settings, load_guard_config
from .server_common import _settings_response_payload

# The only Pulse routes. The daemon checks the header token for exactly these
# paths, so dispatch must not reach a handler through any other path.
PULSE_ROUTE_PATHS = frozenset(
    f"/v1/approval-gate/pulse/{action}" for action in ("enroll", "confirm", "poll", "disable", "recover")
)


def _text(payload: dict[str, object], key: str) -> str | None:
    value = payload.get(key)
    return value.strip() if isinstance(value, str) and value.strip() else None


class _ControlPulseRoutes:
    def _pulse_settings_response(self, gate: dict[str, object]) -> dict[str, object]:
        guard_home = self.server.store.guard_home
        settings = editable_guard_settings(load_guard_config(guard_home))
        settings["approval_gate"] = gate
        return _settings_response_payload(guard_home, settings)

    def _write_pulse_confirmed(self, confirmed: dict[str, object]) -> None:
        """Answer a confirmed setup. Pulse is on now and the recovery code exists only here.

        If the full settings response cannot be built or encoded, the gate
        state the resident returned and the recovery code are sent instead, so
        the user never loses the code.
        """
        recovery_code = confirmed.pop("recovery_code", None)
        try:
            response = self._pulse_settings_response(dict(confirmed))
            response["pulse_recovery_code"] = recovery_code
            json.dumps(response)  # the encoding _write_json uses; a failure falls back below
        except Exception:  # the code must reach the user whatever failed
            response = {"approval_gate": confirmed, "pulse_recovery_code": recovery_code}
        self._write_json(response)

    def _handle_approval_gate_pulse_route(self, action: str, payload: dict[str, object]) -> None:
        guard_home = self.server.store.guard_home
        try:
            if action == "enroll":
                gate_input = approval_gate_input_from_mapping(payload)
                if gate_input is None:
                    raise ApprovalGateError("approval_gate_required", "Approval password is required.")
                if payload.get("step") == "authorize":
                    # Step 1 of the dashboard setup: check the password (and code) only.
                    self._write_json(
                        begin_pulse_enrollment(guard_home, approval_gate_input=gate_input, authorize_only=True)
                    )
                    return
                enrollment = begin_pulse_enrollment(
                    guard_home,
                    approval_gate_input=replace(gate_input, pulse_agent_key=_text(payload, "pulse_agent_key")),
                    # Passed as sent: the resident accepts only "medium" or "high".
                    min_tier=payload.get("min_tier"),
                )
                response = self._pulse_settings_response(approval_gate_public_config(guard_home).to_dict())
                response["pulse_enrollment"] = enrollment
                self._write_json(response)
                return
            if action == "poll":
                request_id = _text(payload, "request_id")
                if request_id is None:
                    raise ApprovalGateError("approval_gate_pulse_invalid_request", "A Pulse request id is required.")
                self._write_json({"status": poll_pulse_approval(guard_home, request_id)})
                return
            if action == "confirm":
                cooldown_seconds = int(payload.get("cooldown_seconds") or 0)
                confirmed = confirm_pulse_enrollment(
                    guard_home,
                    request_id=_text(payload, "request_id") or "",
                    cooldown_seconds=cooldown_seconds,
                )
                self._write_pulse_confirmed(confirmed)
                return
            if action == "disable":
                # Same path as every other strict settings write: with no Pulse
                # request id yet, this answers 202 with one to approve and poll.
                gate_input = approval_gate_input_from_mapping({**payload, "approval_gate_pulse": True})
                grant = require_high_risk(guard_home, purpose="settings_write", approval_gate_input=gate_input)
                self._write_json(
                    self._pulse_settings_response(disable_pulse(guard_home, approval_gate_grant=grant).to_dict())
                )
                return
            if action == "recover":
                gate_input = approval_gate_input_from_mapping(payload)
                if gate_input is None:
                    raise ApprovalGateError("approval_gate_required", "Approval password is required.")
                gate = recover_pulse(
                    guard_home,
                    approval_gate_input=replace(gate_input, pulse_recovery_code=_text(payload, "pulse_recovery_code")),
                )
                self._write_json(self._pulse_settings_response(gate.to_dict()))
                return
        except ApprovalGateError as error:
            self._write_approval_gate_error(error)
            return
        except (TypeError, ValueError, OverflowError):
            self._write_approval_gate_error(
                ApprovalGateError("approval_gate_pulse_invalid_request", "The Pulse request is invalid.", status=400)
            )
            return
        self._write_json({"error": "not_found"}, status=404)
