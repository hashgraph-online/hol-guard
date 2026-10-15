"""Headless app and receipt route handlers for the daemon."""

# pyright: reportAttributeAccessIssue=false, reportUnknownMemberType=false

from __future__ import annotations

import json
from typing import TypedDict

from ..adapters import get_adapter
from ..adapters.base import HarnessContext
from ..approval_gate import (
    ApprovalGateError,
    require_high_risk,
)
from ..approval_gate import input_from_mapping as approval_gate_input_from_mapping
from ..cli.install_commands import (
    apply_managed_install,
    build_harness_verification,
    uninstall_confirmation_token,
)
from ..harness_disconnect_gate import require_harness_disconnect_gate
from ..native_daemon_handler import (
    NativeDaemonHandlerError,
    native_headless_action_error,
    native_headless_action_state,
    native_headless_cursor_surface_error,
)
from ..package_firewall_entitlement import (
    package_firewall_available_actions,
    package_firewall_block_details,
)
from ..package_firewall_receipts import package_firewall_receipt_metadata
from ..receipts.manager import build_receipt
from ..shims import (
    activate_package_shims,
    package_shim_status,
)
from ..stable_digest import stable_digest_hex
from .server_common import (
    _NATIVE_HANDLER_UNAVAILABLE,
    _is_string_object_dict,
    _now,
)
from .server_control_cloud_sync import (
    _headless_failure,
    _managed_controls_publish_for,
    _queue_headless_cloud_sync_with_optional_publish,
    _receipt_summary,
)


class _CursorReceiptContext(TypedDict):
    action_scope: str
    artifact_name: str
    capabilities_summary: str
    changed_capability: str
    scanner_evidence: dict[str, object]
    source_scope: str
    summary: dict[str, object]


_HEADLESS_APP_ACTIONS = {
    "connect": ("install", "install"),
    "repair": ("repair", "repair"),
    "disconnect": ("remove", "uninstall"),
    "status": ("status", "verify"),
    "test": ("scan", "verify"),
}


class _HeadlessRoutes:
    """Handler methods for control-plane routes."""

    def _latest_cloud_sync_snapshot(self) -> dict[str, object]:
        latest_payload = self.server.store.get_sync_payload("headless_app_sync_summary")  # type: ignore[attr-defined]
        if not isinstance(latest_payload, dict):
            latest_payload = self.server.store.get_sync_payload("sync_summary")  # type: ignore[attr-defined]
        if isinstance(latest_payload, dict):
            return dict(latest_payload)
        return {}

    def _headless_app_action_payload(
        self,
        *,
        action_path: str,
        payload: dict[str, object],
    ) -> tuple[int, dict[str, object]]:
        guard_home = self.server.store.guard_home  # type: ignore[attr-defined]

        def failure(operation: str, error_code: str) -> tuple[int, dict[str, object]]:
            return _headless_failure(lambda: native_headless_action_error(operation, error_code, guard_home=guard_home))

        try:
            mapping = _HEADLESS_APP_ACTIONS[action_path]
        except KeyError:
            return failure(action_path, "unsupported_operation")
        operation, harness_action = mapping
        harness = self._optional_string(payload.get("harness"))
        if harness is None:
            return failure(operation, "missing_harness")
        try:
            adapter = get_adapter(harness)
        except ValueError:
            return failure(operation, "unknown_harness")
        try:
            surface = self._cursor_headless_surface(payload) if adapter.harness == "cursor" else None
        except ValueError:
            status, error_payload = _headless_failure(
                lambda: native_headless_cursor_surface_error(guard_home=guard_home)
            )
            error = error_payload.get("error")
            if status == 400 and isinstance(error, dict):
                error["surface"] = self._optional_string(payload.get("surface")) or ""
            return status, error_payload
        context = self._harness_context(payload)
        try:
            if harness_action == "verify":
                verification_action = "status" if action_path == "status" else "test"
                result = build_harness_verification(
                    adapter.harness,
                    context,
                    self.server.store,  # type: ignore[attr-defined]
                    surface=surface,
                    action=verification_action,
                )
            else:
                result = self._run_headless_managed_action(adapter.harness, harness_action, payload, context)
        except ApprovalGateError as error:
            return error.status, error.to_payload()
        except ValueError as error:
            return failure(operation, str(error))
        location_id = self._optional_string(payload.get("location_id")) or self._optional_string(
            payload.get("locationId")
        )
        receipt = self._record_headless_receipt(
            harness=adapter.harness,
            operation=operation,
            payload=payload,
            result=result,
            location_id=location_id,
            workspace_id=self._optional_string(payload.get("workspace_id")),
            cloud_sync={"status": "pending"},
        )
        cloud_sync = _queue_headless_cloud_sync_with_optional_publish(
            store=self.server.store,
            managed_controls_publish=_managed_controls_publish_for(self.server),
        )
        receipt["cloud_sync"] = cloud_sync
        try:
            state = native_headless_action_state(adapter.harness, operation, result, guard_home=guard_home)
        except NativeDaemonHandlerError:
            # The action already ran and its receipt is recorded; say so, so a client does not blindly retry.
            return 503, {
                **_NATIVE_HANDLER_UNAVAILABLE[1],
                "action_applied": True,
                "cloud_sync": cloud_sync,
                "harness": adapter.harness,
                "operation": operation,
                "receipt": receipt,
            }
        return 200, {
            "cloud_sync": cloud_sync,
            "harness": adapter.harness,
            "operation": operation,
            "result": result,
            "receipt": receipt,
            "state": {**state, "receipt_summary": _receipt_summary(receipt)},
            "reconnect": self._headless_reconnect_payload(
                cloud_sync=cloud_sync,
                location_id=location_id,
            ),
            "status": "completed",
        }

    def _handle_cloud_app_handoff(self, harness: str, query_string: str) -> None:
        _ = (harness, query_string)
        self._write_legacy_cloud_handoff_disabled()

    def _handle_headless_app_action(self, action_path: str, payload: dict[str, object]) -> None:
        status, payload = self._headless_app_action_payload(action_path=action_path, payload=payload)
        self._write_json(payload, status=status)

    def _run_headless_managed_action(
        self,
        harness: str,
        action: str,
        payload: dict[str, object],
        context: HarnessContext,
    ) -> dict[str, object]:
        surface = self._cursor_headless_surface(payload) if harness == "cursor" else None
        if action == "uninstall":
            expected_confirmation = uninstall_confirmation_token(harness)
            confirmation = self._optional_string(payload.get("confirmation_phrase")) or self._optional_string(
                payload.get("confirmation_token")
            )
            if confirmation != expected_confirmation:
                raise ValueError("confirmation_required")
            require_harness_disconnect_gate(
                self.server.store.guard_home,  # type: ignore[attr-defined]
                payload,
                harness=harness,
            )
        install_command = "uninstall" if action == "uninstall" else "install"
        return apply_managed_install(
            install_command,
            harness,
            False,
            context,
            self.server.store,  # type: ignore[attr-defined]
            self._optional_string(payload.get("workspace_id")),
            _now(),
            surface=surface,
        )

    def _handle_audit_remediation(self, action: str, payload: dict[str, object]) -> None:
        if action != "package_shim_path":
            self._write_json({"error": "unsupported_remediation", "operation": action}, status=404)
            return
        manager = self._optional_string(payload.get("manager"))
        if manager is None:
            self._write_json({"error": "missing_manager", "operation": action}, status=400)
            return
        managers, manager_error = self._supply_chain_managers({"managers": [manager]})
        if manager_error is not None:
            self._write_json({"error": manager_error, "operation": action}, status=400)
            return
        entitlement = self._supply_chain_entitlement()
        if not bool(entitlement["allowed"]):
            status, error_code, message = package_firewall_block_details(entitlement)
            current_status = package_shim_status(self._supply_chain_context(payload))
            self._write_json(
                {
                    "available_actions": package_firewall_available_actions(
                        entitlement,
                        has_installed_managers=bool(current_status.get("installed_managers")),
                    ),
                    "entitlement": entitlement,
                    "error": error_code,
                    "message": message,
                    "operation": action,
                },
                status=status,
            )
            return
        context = self._supply_chain_context(payload)
        try:
            require_high_risk(
                self.server.store.guard_home,  # type: ignore[attr-defined]
                purpose="supply_chain_firewall",
                approval_gate_input=approval_gate_input_from_mapping(payload),
            )
            activation_result = activate_package_shims(context, managers=managers)
        except ApprovalGateError as error:
            self._write_approval_gate_error(error)
            return
        except ValueError as error:
            self._write_json({"error": str(error), "operation": action}, status=400)
            return
        result = {
            "manager": manager,
            **activation_result,
        }
        receipt_overrides = package_firewall_receipt_metadata(
            operation=action,
            result=result,
            managers=(manager,),
            workspace_dir=context.workspace_dir,
        )
        scanner_evidence = receipt_overrides.get("scanner_evidence")
        receipt = self._record_headless_receipt(
            harness="package-firewall",
            operation=action,
            payload=payload,
            result=result,
            workspace_id=self._optional_string(payload.get("workspace_id"))
            or self.server.store.get_cloud_workspace_id(),  # type: ignore[attr-defined]
            policy_decision=self._optional_string(receipt_overrides.get("policy_decision")),
            capabilities_summary=self._optional_string(receipt_overrides.get("capabilities_summary")),
            artifact_name=self._optional_string(receipt_overrides.get("artifact_name")),
            scanner_evidence_extra=scanner_evidence if _is_string_object_dict(scanner_evidence) else None,
        )
        self._write_json(
            {
                "entitlement": entitlement,
                "operation": action,
                "receipt": receipt,
                "result": result,
                "status": "completed",
            }
        )

    def _record_headless_receipt(
        self,
        *,
        harness: str,
        location_id: str | None = None,
        operation: str,
        payload: dict[str, object],
        result: dict[str, object],
        workspace_id: str | None,
        cloud_sync: dict[str, object] | None = None,
        policy_decision: str | None = None,
        capabilities_summary: str | None = None,
        artifact_name: str | None = None,
        scanner_evidence_extra: dict[str, object] | None = None,
    ) -> dict[str, object]:
        cursor_receipt_context = self._cursor_receipt_context(
            harness=harness,
            operation=operation,
            payload=payload,
            result=result,
            cloud_sync=cloud_sync,
        )
        material = json.dumps(
            {
                "harness": harness,
                "location_id": location_id,
                "operation": operation,
                "result_keys": sorted(result.keys()),
                "cursor": cursor_receipt_context,
                "workspace_id": workspace_id,
            },
            sort_keys=True,
        )
        artifact_hash = stable_digest_hex(material.encode("utf-8"))
        changed_capabilities = [] if operation in {"status", "scan"} else [operation]
        artifact_id = f"headless:{harness}:{operation}"
        resolved_artifact_name = artifact_name or f"Headless {operation}"
        resolved_capabilities_summary = capabilities_summary or f"Guard local daemon completed headless {operation}."
        source_scope = "local-daemon"
        resolved_policy_decision = policy_decision or "allow"
        scanner_evidence: dict[str, object] = {
            "operation": operation,
            "location_id": location_id,
            "workspace_id": workspace_id,
            "status": "completed",
        }
        if scanner_evidence_extra is not None:
            scanner_evidence.update(scanner_evidence_extra)
        if cursor_receipt_context is not None:
            artifact_id = str(cursor_receipt_context["action_scope"])
            resolved_artifact_name = str(cursor_receipt_context["artifact_name"])
            resolved_capabilities_summary = str(cursor_receipt_context["capabilities_summary"])
            source_scope = str(cursor_receipt_context["source_scope"])
            changed_capabilities = [str(cursor_receipt_context["changed_capability"])]
            scanner_evidence.update(cursor_receipt_context["scanner_evidence"])
        receipt = build_receipt(
            harness=harness,
            artifact_id=artifact_id,
            artifact_hash=artifact_hash,
            policy_decision=resolved_policy_decision,
            capabilities_summary=resolved_capabilities_summary,
            changed_capabilities=changed_capabilities,
            provenance_summary="Guard Cloud local daemon API",
            artifact_name=resolved_artifact_name,
            source_scope=source_scope,
            scanner_evidence=(scanner_evidence,),
            approval_source="guard-cloud-headless",
        )
        self.server.store.add_receipt(receipt)  # type: ignore[attr-defined]
        summary: dict[str, object] = {
            "id": receipt.receipt_id,
            "operation": operation,
            "status": "completed",
            "timestamp": receipt.timestamp,
        }
        if cursor_receipt_context is not None:
            summary.update(cursor_receipt_context["summary"])
        return summary

    def _cursor_headless_surface(self, payload: dict[str, object]) -> str | None:
        surface = self._optional_string(payload.get("surface")) or self._optional_string(payload.get("editor_or_cli"))
        if surface is None:
            return None
        if surface not in {"editor", "cli"}:
            raise ValueError("invalid_cursor_surface")
        return surface

    def _cursor_receipt_context(
        self,
        *,
        harness: str,
        operation: str,
        payload: dict[str, object],
        result: dict[str, object],
        cloud_sync: dict[str, object] | None,
    ) -> _CursorReceiptContext | None:
        if harness != "cursor":
            return None
        action_payload = result.get("cursor_action")
        action_dict = action_payload if isinstance(action_payload, dict) else {}
        surface = (
            self._optional_string(action_dict.get("surface"))
            or self._optional_string(payload.get("surface"))
            or self._optional_string(payload.get("editor_or_cli"))
            or "editor"
        )
        action = self._optional_string(action_dict.get("action")) or operation
        evidence = action_dict.get("evidence")
        evidence_dict = evidence if isinstance(evidence, dict) else {}
        action_scope = self._optional_string(evidence_dict.get("actionScope")) or f"cursor:{surface}:{action}"
        cloud_sync_status = "pending"
        if isinstance(cloud_sync, dict):
            cloud_sync_status = self._optional_string(cloud_sync.get("status")) or cloud_sync_status
        surface_label = "CLI" if surface == "cli" else "editor"
        scanner_evidence: dict[str, object] = {
            "action_scope": action_scope,
            "cloud_sync_status": cloud_sync_status,
            "cursor_status": self._optional_string(action_dict.get("status")) or "unknown",
            "editor_or_cli": surface,
            "error_reason": self._optional_string(payload.get("error_reason")),
        }
        summary: dict[str, object] = {
            "action_scope": action_scope,
            "cloud_sync": dict(cloud_sync) if isinstance(cloud_sync, dict) else {"status": cloud_sync_status},
            "editor_or_cli": surface,
        }
        return {
            "action_scope": action_scope,
            "artifact_name": f"Cursor {surface_label} {action}",
            "capabilities_summary": f"Guard local daemon completed Cursor {surface_label} {action}.",
            "changed_capability": f"{surface}:{action}",
            "scanner_evidence": scanner_evidence,
            "source_scope": f"cursor:{surface}",
            "summary": summary,
        }

    def _approval_with_extension_recommendation(self, approval: dict[str, object]) -> dict[str, object]:
        from .approval_extension_recommendation import with_approval_extension_recommendation

        include = not self._is_hosted_dashboard_origin()
        api = getattr(self._daemon_server(), "extension_control_api", None)
        if not include or api is None:
            return with_approval_extension_recommendation(approval, registry=None, snapshot=None, include=False)
        registry, snapshot = api.recommendation_inputs()
        hint = self._daemon_server().store.get_approval_extension_allow_hint(str(approval.get("request_id", "")))
        return with_approval_extension_recommendation(
            {**approval, "extension_allow_hint": hint}, registry=registry, snapshot=snapshot, include=True
        )
