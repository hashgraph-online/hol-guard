"""Control-plane POST route dispatch split out of the daemon server module."""

# pyright: reportAttributeAccessIssue=false, reportUnknownMemberType=false

from __future__ import annotations

from typing import Any, cast

from ..approval_gate import ApprovalGateError
from ..approval_gate import input_from_mapping as approval_gate_input_from_mapping
from ..approval_scope_support import (
    IneligibleApprovalScopeError,
    StaleApprovalScopeContractError,
    request_scope_contract_payload,
    resolve_request_scope_selection,
)
from ..approvals import ApprovalRequestAlreadyResolvedError, ApprovalRequestNotFoundError, apply_approval_resolution
from ..native_approval_scope import ApprovalScopeUnavailableError
from ..native_daemon_route import NativeDaemonRouteError, native_resolve_request
from ..native_resident_revival import native_route_unavailable_body
from .command_activity_api import handle_command_activity_feedback
from .extension_control_api import ExtensionControlApiError
from .harness_version_api import WRITE_PATHS as HARNESS_VERSION_WRITE_PATHS
from .harness_version_api import handle_harness_version_write
from .local_approval_continuation import apply_local_approval_continuation
from .local_cli_http import handle_local_cli_post
from .manager import repair_approval_center_locator
from .server_common import _now

_AUDIT_REMEDIATION_ACTIONS = {"package_shim_path"}


_SUPPLY_CHAIN_PACKAGE_ACTIONS = {
    "activate",
    "install",
    "repair",
    "test",
    "audit",
    "sync",
    "remove",
    "uninstall",
    "connect",
    "open-shell",
}


_HARNESS_RETRY_COPY: dict[str, str] = {
    "codex": "Return to Codex and retry",
    "claude-code": "Return to Claude and retry",
    "opencode": "Return to OpenCode and retry",
    "copilot": "Return to Copilot and retry",
    "pi": "Return to Pi and retry",
    "omp": "Return to Oh My Pi and retry",
}


_DEFAULT_RETRY_COPY = "Return to your AI assistant and retry"


def _build_resolution_copy(action: str, harness: str) -> dict[str, str]:
    title = "Approved. Retry in chat." if action == "allow" else "Blocked. Decision saved."
    return {"title": title, "body": _HARNESS_RETRY_COPY.get(harness, _DEFAULT_RETRY_COPY)}


class _ControlPostRoutes:
    """Control-plane route dispatch for the daemon handler."""

    def _dispatch_control_post(self, parsed: Any, path_parts: list[str], payload: dict[str, Any], route: Any) -> None:
        if route.route_class == "extension_control":
            try:
                if parsed.path.endswith("/test"):
                    response = self._daemon_server().extension_control_api.test_command(payload)
                elif parsed.path.endswith("/inspect"):
                    response = self._daemon_server().extension_control_api.inspect_command(payload)
                elif parsed.path.endswith("/preview"):
                    response = self._daemon_server().extension_control_api.preview(payload)
                elif parsed.path.endswith("/apply"):
                    response = self._daemon_server().extension_control_api.apply(payload)
                elif parsed.path.endswith("/acknowledge-degraded"):
                    response = self._daemon_server().extension_control_api.acknowledge_degraded(payload)
                elif parsed.path.endswith("/recover-authority"):
                    response = self._daemon_server().extension_control_api.recover_authority(
                        payload,
                        require_fresh_totp=self._request_uses_protection_repair_session(),
                    )
                else:
                    response = self._daemon_server().extension_control_api.refresh()
            except ExtensionControlApiError as error:
                self._write_json(error.to_payload(), status=error.status)
                return
            self._write_json(response, extra_headers={"Cache-Control": "no-store"})
            return
        if route.route_class == "local_cli":
            handle_local_cli_post(self, parsed.path, payload)
            return
        if parsed.path == "/v1/initialize":
            self._handle_initialize(payload)
            return
        if parsed.path == "/v1/command-activity/feedback":
            handle_command_activity_feedback(self, payload)
            return
        if parsed.path == "/v1/clients/attach":
            self._handle_client_attach(payload)
            return
        if parsed.path == "/v1/clients/heartbeat":
            self._handle_client_heartbeat(payload)
            return
        if parsed.path == "/v1/sessions/start":
            self._handle_session_start(payload)
            return
        if parsed.path == "/v1/operations/start":
            self._handle_operation_start(payload)
            return
        if parsed.path == "/v1/operations/block":
            self._handle_operation_block(payload)
            return
        if len(path_parts) == 4 and path_parts[:2] == ["v1", "operations"] and path_parts[3] == "items":
            self._handle_operation_item(path_parts[2], payload)
            return
        if len(path_parts) == 4 and path_parts[:2] == ["v1", "operations"] and path_parts[3] == "status":
            self._handle_operation_status(path_parts[2], payload)
            return
        if parsed.path == "/v1/policy/decisions":
            self._handle_policy_upsert(payload)
            return
        if parsed.path == "/v1/policy/resolve":
            self._handle_policy_resolve(payload)
            return
        if parsed.path == "/v1/policy/claim":
            self._handle_policy_claim(payload)
            return
        if parsed.path == "/v1/policy/clear":
            self._handle_policy_clear(payload)
            return
        if parsed.path == "/v1/requests/clear":
            self._handle_requests_clear(payload)
            return
        if parsed.path == "/v1/requests/bulk-allow-once":
            self._handle_bulk_allow_read_once(payload)
            return
        if parsed.path == "/v1/policy/sync":
            self._handle_headless_policy_sync(payload)
            return
        if parsed.path == "/v1/policy/cloud-exception-requests":
            self._handle_cloud_exception_request_create(payload)
            return
        if parsed.path == "/v1/command-queue/worker/refresh":
            self._handle_command_queue_worker_refresh()
            return
        if parsed.path == "/v1/cloud-review":
            self._handle_cloud_review_settings(payload)
            return
        if parsed.path == "/v1/read-state":
            self._handle_read_state_update(payload)
            return
        if parsed.path == "/v1/protection/repair/approval-gate/setup":
            self._handle_protection_repair_approval_gate_setup(payload)
            return
        if parsed.path == "/v1/settings":
            self._handle_settings_update(payload)
            return
        if parsed.path == "/v1/settings/import":
            self._handle_settings_import(payload)
            return
        if parsed.path == "/v1/settings/reset":
            self._handle_settings_reset(payload)
            return
        if parsed.path == "/v1/approval-gate/cooldown/revoke":
            self._handle_approval_gate_cooldown_revoke(payload)
            return
        if parsed.path == "/v1/approval-gate/totp/enroll":
            self._handle_approval_gate_totp_enroll(payload)
            return
        if parsed.path == "/v1/approval-gate/totp/verify":
            self._handle_approval_gate_totp_verify(payload)
            return
        if parsed.path == "/v1/approval-gate/totp/disable":
            self._handle_approval_gate_totp_disable(payload)
            return
        if parsed.path == "/v1/daemon/repair":
            result = repair_approval_center_locator(self.server.store.guard_home)  # type: ignore[attr-defined]
            self._write_json(result)
            return
        if parsed.path == "/v1/protection/repair":
            self._handle_protection_repair(payload)
            return
        if parsed.path in {"/v1/repair", "/v1/protection/remove-hooks"}:
            self._handle_repair_api(parsed.path, payload)
            return
        if parsed.path == "/v1/supply-chain/repair":
            self._run_package_firewall_mutation("repair_all", lambda: self._handle_supply_chain_repair(payload))
            return
        if parsed.path == "/v1/insights/share":
            self._handle_insights_share_publish(payload)
            return
        if parsed.path == "/v1/cloud/connect":
            self._handle_guard_cloud_connect_start()
            return
        if parsed.path == "/v1/update/reconnect/prepare":
            self._handle_dashboard_reconnect_prepare()
            return
        if parsed.path == "/v1/update/channel":
            self._handle_update_channel(payload)
            return
        if parsed.path == "/v1/update":
            self._handle_dashboard_update(payload)
            return
        if parsed.path == "/v1/notifications/setup":
            self._handle_notification_setup(payload)
            return
        if (
            len(path_parts) == 4
            and path_parts[:3] == ["v1", "audit", "remediations"]
            and path_parts[3] in _AUDIT_REMEDIATION_ACTIONS
        ):
            self._handle_audit_remediation(path_parts[3], payload)
            return
        if (
            len(path_parts) == 4
            and path_parts[:3] == ["v1", "supply-chain", "package-shims"]
            and path_parts[3] in _SUPPLY_CHAIN_PACKAGE_ACTIONS
        ):
            action = path_parts[3]

            def handle_package_action() -> None:
                self._handle_supply_chain_package_firewall_action(action, payload)

            if action in {"install", "repair", "uninstall", "remove", "activate", "open-shell", "sync"}:
                self._run_package_firewall_mutation(action, handle_package_action)
            else:
                handle_package_action()
            return
        if parsed.path == "/v1/supply-chain/choose-folder":
            self._handle_supply_chain_choose_folder()
            return
        if len(path_parts) == 3 and path_parts[:2] == ["v1", "supply-chain"] and path_parts[2] in {"audit", "sync"}:
            action = path_parts[2]
            if action == "sync":
                self._run_package_firewall_mutation(
                    action,
                    lambda: self._handle_supply_chain_package_firewall_action(action, payload),
                )
            else:
                self._handle_supply_chain_package_firewall_action(action, payload)
            return
        if parsed.path in HARNESS_VERSION_WRITE_PATHS:
            # Fail closed if the native route table predates these paths.
            if not self._header_token_is_valid():
                self._write_unauthorized(extra_headers=self._cors_headers_for_request())
                return
            handle_harness_version_write(self, parsed.path, payload, self._harness_context({}))
            return
        if len(path_parts) == 4 and path_parts[:2] == ["v1", "harnesses"]:
            self._handle_harness_action(path_parts[2], path_parts[3], payload)
            return
        if len(path_parts) == 5 and path_parts[:2] == ["v1", "apps"] and path_parts[3] == "cloud":
            self._write_legacy_cloud_handoff_disabled()
            return
        if len(path_parts) == 3 and path_parts[:2] == ["v1", "apps"]:
            self._handle_headless_app_action(path_parts[2], payload)
            return
        if len(path_parts) == 4 and path_parts[:2] == ["v1", "requests"] and path_parts[3] == "resume":
            self._handle_request_resume_retry(path_parts[2])
            return
        if len(path_parts) == 4 and path_parts[:2] == ["v1", "requests"] and path_parts[3] == "live-decision":
            self._handle_codex_live_decision(path_parts[2], payload)
            return
        if len(path_parts) == 5 and path_parts[:3] == ["v1", "mcp-policy", "requests"] and path_parts[4] == "decision":
            self._handle_mcp_policy_decision(path_parts[3], payload)
            return
        try:
            resolution = native_resolve_request(parsed.path, payload, guard_home=self._route_home())
        except NativeDaemonRouteError:
            self._write_json({"resolved": False, **native_route_unavailable_body()}, status=503)
            return
        if resolution.outcome == "not_matched":
            self.send_response(404)
            self.end_headers()
            return
        if resolution.outcome != "resolved":
            self._write_json({"resolved": False, "error": resolution.outcome}, status=400)
            return
        request_id = cast(str, resolution.request_id)
        action = cast(str, resolution.action)
        scope = cast(str, resolution.scope)
        scope_contract_version = resolution.scope_contract_version
        scope_contract_digest = resolution.scope_contract_digest
        try:
            existing_request = self.server.store.get_approval_request(request_id)  # type: ignore[attr-defined]
            if isinstance(existing_request, dict):
                scope_selection = resolve_request_scope_selection(
                    existing_request,
                    action=action,
                    requested_scope=scope,
                    contract_version=scope_contract_version,
                    contract_digest=scope_contract_digest,
                )
                if existing_request.get("status") != "pending":
                    if (
                        existing_request.get("resolution_action") == action
                        and existing_request.get("resolution_scope") == scope_selection.applied_scope
                    ):
                        self._write_json(
                            {
                                "resolved": True,
                                "idempotent": True,
                                "resolved_request": existing_request,
                                "requested_scope": scope_selection.requested_scope,
                                "applied_scope": scope_selection.applied_scope,
                                **request_scope_contract_payload(existing_request),
                            }
                        )
                        return
                    raise ApprovalRequestAlreadyResolvedError(f"Approval request already resolved: {request_id}")
            persist_policy = self._approval_persist_policy(payload)
            updated = apply_approval_resolution(
                store=self.server.store,  # type: ignore[attr-defined]
                request_id=request_id,
                action=action,
                scope=scope,
                workspace=self._optional_string(payload.get("workspace")),
                reason=self._optional_string(payload.get("reason")),
                return_queue_result=True,
                resolve_scope_matches=True,
                approval_gate_input=approval_gate_input_from_mapping(payload),
                persist_policy=persist_policy,
                scope_contract_version=scope_contract_version,
                scope_contract_digest=scope_contract_digest,
                mcp_grant_target=payload.get("mcp_grant_target"),
                mcp_grant_duration=payload.get("mcp_grant_duration"),
                local_tool_grant_target=payload.get("local_tool_grant_target"),
                local_tool_grant_duration=payload.get("local_tool_grant_duration"),
            )
        except ApprovalRequestNotFoundError:
            self._write_json(
                {
                    "resolved": False,
                    "error": "not_found",
                    "recovery": {
                        "code": "request_unknown",
                        "title": "This request is no longer waiting.",
                        "body": "The request was either already resolved or expired. You can close this tab.",
                        "queue_url": self._local_queue_url(),
                    },
                },
                status=404,
            )
            return
        except ApprovalRequestAlreadyResolvedError:
            resolved_request = self.server.store.get_approval_request(request_id)  # type: ignore[attr-defined]
            if isinstance(resolved_request, dict):
                try:
                    replay_selection = resolve_request_scope_selection(
                        resolved_request,
                        action=action,
                        requested_scope=scope,
                        contract_version=scope_contract_version,
                        contract_digest=scope_contract_digest,
                    )
                except StaleApprovalScopeContractError as error:
                    self._write_stale_approval_scope_error(error)
                    return
                except IneligibleApprovalScopeError as error:
                    self._write_ineligible_approval_scope_error(error)
                    return
                except ValueError as error:
                    self._write_json({"resolved": False, "error": str(error)}, status=400)
                    return
                if (
                    resolved_request.get("resolution_action") == action
                    and resolved_request.get("resolution_scope") == replay_selection.applied_scope
                ):
                    self._write_json(
                        {
                            "resolved": True,
                            "idempotent": True,
                            "resolved_request": resolved_request,
                            "requested_scope": replay_selection.requested_scope,
                            "applied_scope": replay_selection.applied_scope,
                            **request_scope_contract_payload(resolved_request),
                        }
                    )
                    return
            self._write_json(
                {
                    "resolved": False,
                    "error": "already_resolved",
                    "recovery": {
                        "code": "request_resolved",
                        "title": "This request has already been resolved.",
                        "body": (
                            "If the action is blocked and you believe it should be allowed, "
                            "you can re-submit from your AI assistant."
                        ),
                        "queue_url": self._local_queue_url(),
                    },
                },
                status=409,
            )
            return
        except ApprovalGateError as error:
            self._write_approval_gate_error(error, resolved=False)
            return
        except StaleApprovalScopeContractError as error:
            self._write_stale_approval_scope_error(error)
            return
        except IneligibleApprovalScopeError as error:
            self._write_ineligible_approval_scope_error(error)
            return
        except ApprovalScopeUnavailableError:
            self._write_json(
                {"resolved": False, "error": "native_approval_scope_unavailable"},
                status=503,
                extra_headers={"Cache-Control": "no-store"},
            )
            return
        except ValueError as error:
            self._write_json({"resolved": False, "error": str(error)}, status=400)
            return
        normalized_scope = scope
        item = updated.get("item")
        harness_str = str(item.get("harness", "")) if isinstance(item, dict) else ""
        self.server.store.add_event(  # type: ignore[attr-defined]
            "approval_resolved",
            {"request_id": request_id, "action": action, "scope": normalized_scope, "harness": harness_str},
            _now(),
        )
        harness = str(updated.get("harness", ""))
        resolved_harness = harness_str or harness
        copy = _build_resolution_copy(action, resolved_harness)
        updated, copy = apply_local_approval_continuation(
            store=self.server.store,  # type: ignore[attr-defined]
            updated=updated,
            request_id=request_id,
            action=action,
            harness=resolved_harness,
            copy=copy,
            now=_now,
        )
        updated["copy"] = copy
        updated["retry_hint"] = copy["body"]
        self._write_json(updated)
