"""Policy mutation routes."""

from __future__ import annotations

from . import server as _server


def _handle_policy_upsert(self: _server._GuardDaemonHandler, payload: dict[str, object]) -> None:
    harness = payload.get("harness")
    scope = payload.get("scope")
    action = payload.get("action")
    if (
        not isinstance(harness, str)
        or not harness.strip()
        or not isinstance(scope, str)
        or not scope.strip()
        or not isinstance(action, str)
        or not action.strip()
    ):
        self._write_json({"saved": False, "error": "missing_required_fields"}, status=400)
        return
    normalized_harness = harness.strip()
    normalized_scope = scope.strip()
    normalized_action = action.strip()
    if not _server._is_decision_scope(normalized_scope) or not _server._is_guard_action(normalized_action):
        self._write_json({"saved": False, "error": "unsupported_policy_value"}, status=400)
        return
    if normalized_scope == "global" and normalized_action == "allow":
        self._write_json({"saved": False, "error": "broad_allow_requires_narrow_scope"}, status=400)
        return
    record = {
        "harness": normalized_harness,
        "scope": normalized_scope,
        "action": normalized_action,
        "artifact_id": self._optional_string(payload.get("artifact_id")),
        "workspace": self._optional_string(payload.get("workspace")),
        "publisher": self._optional_string(payload.get("publisher")),
        "reason": self._optional_string(payload.get("reason")),
    }
    if not self._scope_target_is_valid(
        normalized_scope,
        artifact_id=record["artifact_id"],
        workspace=record["workspace"],
        publisher=record["publisher"],
    ):
        self._write_json({"saved": False, "error": "missing_scope_target"}, status=400)
        return
    store = self.server.store  # type: ignore[attr-defined]
    decision = _server.PolicyDecision(
        harness=normalized_harness,
        scope=normalized_scope,
        action=normalized_action,
        artifact_id=record["artifact_id"],
        workspace=record["workspace"],
        publisher=record["publisher"],
        reason=record["reason"],
    )
    try:
        approval_gate_grant = _server.require_high_risk(
            store.guard_home,
            purpose="policy_write",
            approval_gate_input=_server.approval_gate_input_from_mapping(payload),
        )
        store.upsert_policy(
            decision,
            _server._now(),
            approval_gate_grant=approval_gate_grant,
        )
    except _server.ApprovalGateError as error:
        payload = error.to_payload()
        payload["saved"] = False
        self._write_json(payload, status=error.status)
        return
    except ValueError as error:
        self._write_json({"saved": False, "error": str(error)}, status=400)
        return
    self._write_json({"saved": True, "decision": record})


def _handle_policy_resolve(self: _server._GuardDaemonHandler, payload: dict[str, object]) -> None:
    from .policy_authority_api import PolicyAuthorityApiError, resolve_policy_decision

    try:
        result = resolve_policy_decision(self.server.store, payload, now=_server._now())  # type: ignore[attr-defined]
    except PolicyAuthorityApiError as error:
        self._write_json({"error": str(error)}, status=400)
        return
    self._write_json(result, extra_headers={"Cache-Control": "no-store"})


def _handle_policy_claim(self: _server._GuardDaemonHandler, payload: dict[str, object]) -> None:
    from .policy_authority_api import PolicyAuthorityApiError, claim_policy_decision

    try:
        result = claim_policy_decision(self.server.store, payload, now=_server._now())  # type: ignore[attr-defined]
    except PolicyAuthorityApiError as error:
        self._write_json({"error": str(error)}, status=400)
        return
    self._write_json(result, status=200 if result["claimed"] else 409)
