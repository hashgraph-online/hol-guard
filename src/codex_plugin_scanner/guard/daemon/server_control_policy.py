"""Policy, approval-request and approval-gate route handlers for the daemon control plane."""

# pyright: reportAttributeAccessIssue=false, reportUnknownMemberType=false

from __future__ import annotations

import json

from ..approval_gate import (
    ApprovalGateError,
    require_high_risk,
)
from ..approval_gate import input_from_mapping as approval_gate_input_from_mapping
from ..approval_scope_support import (
    IneligibleApprovalScopeError,
    StaleApprovalScopeContractError,
)
from ..approvals import (
    bulk_allow_read_only_once,
)
from ..codex_resume import ResumeUnavailableError, get_request_resume_status, retry_request_resume
from ..models import (
    PolicyDecision,
)
from ..native_approval_scope import ApprovalScopeUnavailableError
from ..native_daemon_handler import (
    native_body_handler,
)
from .server_common import (
    _now,
)


class _ControlPolicyRoutes:
    """Handler methods for control-plane routes."""

    @staticmethod
    def _policy_memory_payload(value: object) -> dict[str, object]:
        if isinstance(value, dict):
            return dict(value)
        if isinstance(value, str) and value.strip():
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError:
                return {}
            return parsed if isinstance(parsed, dict) else {}
        return {}

    def _handle_policy_clear(self, payload: dict[str, object]) -> None:
        guard_home = self.server.store.guard_home  # type: ignore[attr-defined]
        verdict = self._native_handler_decision(
            lambda: native_body_handler("policy_clear", payload, guard_home=guard_home)
        )
        if verdict is None:
            return
        fields = verdict.fields
        try:
            approval_gate_grant = require_high_risk(
                guard_home,
                purpose="policy_clear",
                approval_gate_input=approval_gate_input_from_mapping(payload),
            )
            cleared = self.server.store.clear_policy_decisions(  # type: ignore[attr-defined]
                fields["harness"],
                fields["source"],
                scope=fields["scope"],
                artifact_id=fields["artifact_id"],
                artifact_hash=fields["artifact_hash"],
                artifact_id_is_null=fields["artifact_id_is_null"],
                artifact_hash_is_null=fields["artifact_hash_is_null"],
                workspace=fields["workspace"],
                publisher=fields["publisher"],
                approval_gate_grant=approval_gate_grant,
            )
        except ApprovalGateError as error:
            payload = error.to_payload()
            payload["cleared"] = 0
            self._write_json(payload, status=error.status)
            return
        self._write_json({"cleared": cleared, **verdict.body})

    def _handle_requests_clear(self, payload: dict[str, object]) -> None:
        guard_home = self.server.store.guard_home  # type: ignore[attr-defined]
        verdict = self._native_handler_decision(
            lambda: native_body_handler("requests_clear", payload, guard_home=guard_home)
        )
        if verdict is None:
            return
        status = verdict.fields["status"]
        try:
            require_high_risk(
                guard_home,
                purpose="queue_clear",
                approval_gate_input=approval_gate_input_from_mapping(payload),
            )
            cleared = self.server.store.clear_approval_requests(  # type: ignore[attr-defined]
                harness=verdict.fields["harness"],
                status=status,
            )
        except ApprovalGateError as error:
            payload = error.to_payload()
            payload["cleared"] = 0
            payload["status"] = status
            self._write_json(payload, status=error.status)
            return
        self._write_json({"cleared": cleared, **verdict.body})

    def _handle_bulk_allow_read_once(self, payload: dict[str, object]) -> None:
        guard_home = self.server.store.guard_home  # type: ignore[attr-defined]
        verdict = self._native_handler_decision(
            lambda: native_body_handler("bulk_allow", payload, guard_home=guard_home)
        )
        if verdict is None:
            return
        normalized_ids = verdict.fields["request_ids"]
        try:
            result = bulk_allow_read_only_once(
                store=self.server.store,  # type: ignore[attr-defined]
                request_ids=normalized_ids,
                approval_gate_input=approval_gate_input_from_mapping(payload),
            )
        except ApprovalScopeUnavailableError as error:
            self._write_json({"error": str(error), "resolved_count": 0, "failed": []}, status=503)
            return
        except ValueError as error:
            if str(error) == "bulk_approve_gate_required":
                self._write_json(
                    {"error": str(error), "resolved_count": 0, "failed": []},
                    status=403,
                )
                return
            self._write_json(
                {"error": str(error), "resolved_count": 0, "failed": []},
                status=400,
            )
            return
        except ApprovalGateError as error:
            error_payload = error.to_payload()
            error_payload.setdefault("resolved_count", 0)
            error_payload.setdefault("failed", [])
            self._write_json(error_payload, status=error.status)
            return
        # A resident outage stops the batch; rows approved before it stay in resolved_count.
        self._write_json(result, status=503 if "error" in result else 200)

    def _approval_persist_policy(self, payload: dict[str, object]) -> bool | None:
        if "persist_policy" in payload:
            return True if self._optional_bool(payload.get("persist_policy"), default=False) else None
        if "remember" in payload:
            return True if self._optional_bool(payload.get("remember"), default=False) else None
        return None

    def _write_stale_approval_scope_error(self, error: StaleApprovalScopeContractError) -> None:
        self._write_json(
            {"resolved": False, "error": str(error), **error.contract.to_dict()},
            status=409,
        )

    def _write_ineligible_approval_scope_error(self, error: IneligibleApprovalScopeError) -> None:
        self._write_json(
            {
                "resolved": False,
                "error": str(error),
                "action": error.action,
                "requested_scope": error.requested_scope,
                **error.contract.to_dict(),
            },
            status=422,
        )

    def _handle_request_resume_read(self, request_id: str) -> None:
        if self.server.store.get_approval_request(request_id) is None:  # type: ignore[attr-defined]
            self._write_json({"error": "not_found"}, status=404)
            return
        try:
            payload = get_request_resume_status(self.server.store, request_id=request_id, now=_now())  # type: ignore[attr-defined]
        except ResumeUnavailableError:
            self._write_json({"error": "resume_unavailable"}, status=503)
            return
        if payload is None:
            self._write_json({"error": "not_found"}, status=404)
            return
        self._write_json(payload)

    def _handle_request_resume_retry(self, request_id: str) -> None:
        try:
            payload = retry_request_resume(self.server.store, request_id=request_id, now=_now(), force=False)  # type: ignore[attr-defined]
        except ValueError as error:
            error_code = str(error)
            if error_code == "not_found":
                self._write_json({"error": "not_found"}, status=404)
                return
            if error_code == "not_resolved":
                self._write_json({"error": "not_resolved"}, status=409)
                return
            if error_code == "resume_unavailable":
                self._write_json({"error": "resume_unavailable"}, status=503)
                return
            self._write_json({"error": "resume_not_supported"}, status=400)
            return
        self.server.store.add_event(  # type: ignore[attr-defined]
            "codex/thread_resume",
            {"request_id": request_id, "action": payload.get("resolution_action"), **payload},
            _now(),
        )
        self._write_json(payload)

    def _write_legacy_cloud_handoff_disabled(self) -> None:
        self._write_json(
            {
                "error": "legacy_cloud_handoff_disabled",
                "message": "Use hol-guard connect for browser OAuth.",
            },
            status=410,
        )

    def _handle_policy_upsert(self, payload: dict[str, object]) -> None:
        guard_home = self.server.store.guard_home  # type: ignore[attr-defined]
        verdict = self._native_handler_decision(
            lambda: native_body_handler("policy_upsert", payload, guard_home=guard_home)
        )
        if verdict is None:
            return
        store = self.server.store  # type: ignore[attr-defined]
        decision = PolicyDecision(**verdict.fields)
        try:
            approval_gate_grant = require_high_risk(
                store.guard_home,
                purpose="policy_write",
                approval_gate_input=approval_gate_input_from_mapping(payload),
            )
            store.upsert_policy(
                decision,
                _now(),
                approval_gate_grant=approval_gate_grant,
            )
        except ApprovalGateError as error:
            payload = error.to_payload()
            payload["saved"] = False
            self._write_json(payload, status=error.status)
            return
        except ValueError as error:
            self._write_json({"saved": False, "error": str(error)}, status=400)
            return
        self._write_json(verdict.body)

    def _handle_policy_resolve(self, payload: dict[str, object]) -> None:
        from .policy_authority_api import PolicyAuthorityApiError, resolve_policy_decision

        try:
            result = resolve_policy_decision(self.server.store, payload, now=_now())  # type: ignore[attr-defined]
        except PolicyAuthorityApiError as error:
            self._write_json({"error": str(error)}, status=400)
            return
        self._write_json(result, extra_headers={"Cache-Control": "no-store"})

    def _handle_policy_claim(self, payload: dict[str, object]) -> None:
        from .policy_authority_api import PolicyAuthorityApiError, claim_policy_decision

        try:
            result = claim_policy_decision(self.server.store, payload, now=_now())  # type: ignore[attr-defined]
        except PolicyAuthorityApiError as error:
            self._write_json({"error": str(error)}, status=400)
            return
        self._write_json(result, status=200 if result["claimed"] else 409)
