"""MCP policy request and decision routes."""

from __future__ import annotations

from . import server as _server


def _handle_mcp_policy_request_get(self: _server._GuardDaemonHandler, request_id: str) -> None:
    """Return sanitized MCP policy request details for the dashboard.

        GET /v1/mcp-policy/requests/<id>

        Returns the request status, digests, mode, timestamps, and a
        sanitized semantic diff summary.  Never returns the canonical
        policy YAML or the full plan JSON — the dashboard renders the
        diff summary only.
        """  # fmt: skip
    import json as _json

    from codex_plugin_scanner.guard.mcp.policy_store import MCPolicyRequestRepository

    store = self.server.store  # type: ignore[attr-defined]
    repo = MCPolicyRequestRepository(store)
    request = repo.get_request(request_id)
    if request is None:
        self._write_json({"error": "not_found"}, status=404)
        return

    result: dict[str, object] = {}
    if request.result_json:
        try:
            parsed_result: object = _json.loads(request.result_json)
            if _server._is_string_object_dict(parsed_result):
                result = parsed_result
        except _json.JSONDecodeError:
            pass

    plan_summary: dict[str, object] = {}
    if request.plan_json:
        try:
            parsed_plan: object = _json.loads(request.plan_json)
            if _server._is_string_object_dict(parsed_plan):
                plan_summary = parsed_plan
        except _json.JSONDecodeError:
            pass

    inserted_value = result.get("inserted", 0)
    replaced_value = result.get("replaced", 0)
    inserted = inserted_value if isinstance(inserted_value, (bool, int)) else 0
    replaced = replaced_value if isinstance(replaced_value, (bool, int)) else 0
    additions_value = plan_summary.get("additions", [])
    replacements_value = plan_summary.get("replacements", [])
    removals_value = plan_summary.get("removals", [])
    additions = additions_value if isinstance(additions_value, list) else []
    replacements = replacements_value if isinstance(replacements_value, list) else []
    removals = removals_value if isinstance(removals_value, list) else []

    self._write_json(
        {
            "requestId": request.request_id,
            "status": request.status,
            "documentId": request.policy_document_id,
            "candidateDigest": request.policy_document_digest,
            "expectedCurrentDigest": request.expected_current_digest,
            "expectedPolicyGeneration": request.expected_policy_generation,
            "mode": request.mode,
            "createdAt": request.created_at,
            "expiresAt": request.expires_at,
            "resolvedAt": request.resolved_at,
            "failureCode": request.failure_code,
            "isTerminal": request.is_terminal,
            "isExpired": request.is_expired,
            "result": {
                "inserted": _server._safe_int(inserted),
                "replaced": _server._safe_int(replaced),
            },
            "writePlan": {
                "additions": list(additions),
                "replacements": list(replacements),
                "removals": list(removals),
            },
            "semanticDiff": {
                "additionCount": len(additions),
                "replacementCount": len(replacements),
                "removalCount": len(removals),
            },
            "activeEnforcementWarning": request.status == "pending" and not request.is_expired,
        }
    )


def _handle_mcp_policy_decision(self: _server._GuardDaemonHandler, request_id: str, payload: dict[str, object]) -> None:
    """Resolve an MCP policy creation request via human approval.

        POST /v1/mcp-policy/requests/<id>/decision
        Body: {"action": "approve" | "decline", ...approval_gate_input}

        On approve: obtains the ApprovalGateGrant via require_high_risk
        (purpose="policy_import"), then calls apply_pending_policy_request
        with the grant.  On decline: calls decline_pending_policy_request.
        """  # fmt: skip

    from codex_plugin_scanner.guard.mcp.policy_errors import PolicyToolError
    from codex_plugin_scanner.guard.mcp.policy_tools import (
        apply_pending_policy_request,
        decline_pending_policy_request,
    )

    action = payload.get("action")
    if not isinstance(action, str) or action.strip() not in {"approve", "decline"}:
        self._write_json(
            {"resolved": False, "error": "missing_required_fields"},
            status=400,
        )
        return
    action = action.strip()
    store = self.server.store  # type: ignore[attr-defined]
    guard_home = store.guard_home

    if action == "decline":
        try:
            decline_result = decline_pending_policy_request(store, request_id)
        except PolicyToolError as error:
            if error.code == "approval_already_resolved":
                # VPC047: a terminal/expired/declined request is stable.
                # Return the honest current state so the dashboard renders
                # disabled controls instead of an error.
                from codex_plugin_scanner.guard.mcp.policy_store import (
                    MCPolicyRequestRepository,
                )

                repo = MCPolicyRequestRepository(store)
                current = repo.get_request(request_id)
                if current is not None:
                    self._write_json(
                        {
                            "resolved": True,
                            "requestId": current.request_id,
                            "status": current.status,
                            "resolvedAt": current.resolved_at,
                        }
                    )
                    return
            self._write_json(
                {"resolved": False, "error": error.code, "message": error.message},
                status=400,
            )
            return
        self._write_json({"resolved": True, **decline_result})
        return

    # action == "approve" — obtain the grant and apply.
    try:
        approval_gate_grant = _server.require_high_risk(
            guard_home,
            purpose="policy_import",
            approval_gate_input=_server.approval_gate_input_from_mapping(payload),
        )
    except _server.ApprovalGateError as error:
        self._write_approval_gate_error(error)
        return

    try:
        apply_result = apply_pending_policy_request(
            store,
            request_id,
            approval_gate_grant=approval_gate_grant,
        )
    except PolicyToolError as error:
        if error.code == "approval_already_resolved":
            # VPC047: re-approving a terminal request is stable; return
            # the honest current state so controls render disabled.
            from codex_plugin_scanner.guard.mcp.policy_store import (
                MCPolicyRequestRepository,
            )

            repo = MCPolicyRequestRepository(store)
            current = repo.get_request(request_id)
            if current is not None:
                self._write_json(
                    {
                        "resolved": True,
                        "requestId": current.request_id,
                        "status": current.status,
                        "resolvedAt": current.resolved_at,
                    }
                )
                return
        self._write_json(
            {"resolved": False, "error": error.code, "message": error.message},
            status=400,
        )
        return
    self._write_json({"resolved": True, **apply_result})
